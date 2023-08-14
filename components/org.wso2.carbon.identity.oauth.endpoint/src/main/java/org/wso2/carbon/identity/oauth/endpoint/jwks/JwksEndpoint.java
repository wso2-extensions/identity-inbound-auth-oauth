/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.jws.WebService;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * Rest implementation for JWKS endpoint.
 */
@WebService
public class JwksEndpoint {

    private static final Log log = LogFactory.getLog(JwksEndpoint.class);
    private static final String KEY_USE = "sig";
    private static final String SECURITY_KEY_STORE_LOCATION = "Security.KeyStore.Location";
    private static final String SECURITY_KEY_STORE_PW = "Security.KeyStore.Password";
    private static final String KEYS = "keys";
    private static final String ADD_PREVIOUS_VERSION_KID = "JWTValidatorConfigs.JWKSEndpoint.AddPreviousVersionKID";

    @GET
    @Path(value = "/jwks")
    @Produces(MediaType.APPLICATION_JSON)
    public String jwks() {

        String tenantDomain = getTenantDomain();
        String keystorePath = CarbonUtils.getServerConfiguration().getFirstProperty(SECURITY_KEY_STORE_LOCATION);

        try (FileInputStream file = new FileInputStream(keystorePath)) {
            final KeyStore keystore;
            List<CertificateInfo> certificateInfoList = new ArrayList<>();
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {
                keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                String password = CarbonUtils.getServerConfiguration().getFirstProperty(SECURITY_KEY_STORE_PW);
                keystore.load(file, password.toCharArray());
            } else {
                try {
                    int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                    IdentityTenantUtil.initializeRegistry(tenantId);
                    FrameworkUtils.startTenantFlow(tenantDomain);
                    KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                    keystore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                } finally {
                    FrameworkUtils.endTenantFlow();
                }
            }
            Enumeration enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = (String) enumeration.nextElement();
                if (keystore.isKeyEntry(alias)) {
                    CertificateInfo certificateInfo = new CertificateInfo(keystore.getCertificate(alias), alias);
                    certificateInfo.setCertificateChain(keystore.getCertificateChain(alias));
                    certificateInfoList.add(certificateInfo);
                }
            }
            return buildResponse(certificateInfoList);
        } catch (Exception e) {
            String errorMessage = "Error while generating the keyset for tenant domain: " + tenantDomain;
            return logAndReturnError(errorMessage, e);
        }
    }

    private String buildResponse(List<CertificateInfo> certInfoList)
            throws IdentityOAuth2Exception, ParseException, CertificateEncodingException, JOSEException {

        JSONArray jwksArray = new JSONArray();
        JSONObject jwksJson = new JSONObject();
        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        JWSAlgorithm accessTokenSignAlgorithm =
                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getSignatureAlgorithm());
        // If we read different algorithms from identity.xml then put them in a list.
        List<JWSAlgorithm> diffAlgorithms = findDifferentAlgorithms(accessTokenSignAlgorithm, config);
        // Create JWKS for different algorithms using new KeyID creation method.
        populateJWKSArray(certInfoList, diffAlgorithms, jwksArray,
                OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM);

        // Add SHA-1 KeyID to the KeySet if the config is enabled.
        if (Boolean.parseBoolean(IdentityUtil.getProperty(ADD_PREVIOUS_VERSION_KID))) {
            populateJWKSArray(certInfoList, diffAlgorithms, jwksArray,
                    OAuthConstants.SignatureAlgorithms.PREVIOUS_KID_HASHING_ALGORITHM);

            // This method add KeySets which have thumbprint of certificate as KeyIDs without appending the algo.
            // This KeyID format is deprecated. However, we are enabling old KeyID based on config to support migration.
            createKeySetUsingOldKeyID(jwksArray, certInfoList, accessTokenSignAlgorithm);
        }
        jwksJson.put(KEYS, jwksArray);
        return jwksJson.toString();
    }

    private void populateJWKSArray(List<CertificateInfo> certInfoList, List<JWSAlgorithm> diffAlgorithms,
                                   JSONArray jwksArray, String hashingAlgorithm)
            throws IdentityOAuth2Exception, ParseException, CertificateEncodingException, JOSEException {

        for (CertificateInfo certInfo : certInfoList) {
            for (JWSAlgorithm algorithm : diffAlgorithms) {
                String alias = certInfo.getCertificateAlias();
                X509Certificate cert = (X509Certificate) certInfo.getCertificate();
                Certificate[] certChain = certInfo.getCertificateChain();
                List<Base64> encodedCertList = generateEncodedCertList(certChain, alias);
                RSAKey.Builder jwk = getJWK(algorithm, encodedCertList, cert,
                        hashingAlgorithm, alias);
                jwksArray.add(jwk.build().toJSONObject());
            }
        }
    }

    private RSAKey.Builder getJWK(JWSAlgorithm algorithm, List<Base64> encodedCertList, X509Certificate certificate,
                                  String kidAlgorithm, String alias)
            throws ParseException, IdentityOAuth2Exception, JOSEException {

        RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) certificate.getPublicKey());
        if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
            jwk.keyID(OAuth2Util.getKID(certificate, algorithm, getTenantDomain()));
        } else {
            jwk.keyID(OAuth2Util.getPreviousKID(certificate, algorithm, getTenantDomain()));
        }
        jwk.algorithm(algorithm);
        jwk.keyUse(KeyUse.parse(KEY_USE));
        jwk.x509CertChain(encodedCertList);
        jwk.x509CertSHA256Thumbprint(new Base64URL(OAuth2Util.getThumbPrint(certificate, alias)));
        return jwk;
    }

    /**
     * This method generates the kid value without the algo appended to the end of kid.
     * This method is marked as @Deprecated because we issue kids with algo appended at present,
     * and we are keeping this to only support migration efforts.
     *
     * @param jwksArray
     * @param certInfoList
     * @param algorithm
     * @throws IdentityOAuth2Exception
     * @throws ParseException
     */
    @Deprecated
    private void createKeySetUsingOldKeyID(JSONArray jwksArray, List<CertificateInfo> certInfoList,
                                           JWSAlgorithm algorithm) throws IdentityOAuth2Exception, ParseException {

        for (CertificateInfo certInfo : certInfoList) {
            X509Certificate cert = (X509Certificate) certInfo.getCertificate();
            RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
            RSAKey.Builder jwk = new RSAKey.Builder(publicKey);
            jwk.keyID(OAuth2Util.getThumbPrintWithPrevAlgorithm(cert));
            jwk.algorithm(algorithm);
            jwk.keyUse(KeyUse.parse(KEY_USE));
            jwksArray.add(jwk.build().toJSONObject());
        }
    }

    /**
     * This method read identity.xml and find different signing algorithms.
     *
     * @param accessTokenSignAlgorithm
     * @param config
     * @return
     * @throws IdentityOAuth2Exception
     */
    private List<JWSAlgorithm> findDifferentAlgorithms(
            JWSAlgorithm accessTokenSignAlgorithm, OAuthServerConfiguration config) throws IdentityOAuth2Exception {

        List<JWSAlgorithm> diffAlgorithms = new ArrayList<>();
        diffAlgorithms.add(accessTokenSignAlgorithm);
        JWSAlgorithm idTokenSignAlgorithm =
                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getIdTokenSignatureAlgorithm());
        if (!accessTokenSignAlgorithm.equals(idTokenSignAlgorithm)) {
            diffAlgorithms.add(idTokenSignAlgorithm);
        }
        JWSAlgorithm userInfoSignAlgorithm =
                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getUserInfoJWTSignatureAlgorithm());
        if (!accessTokenSignAlgorithm.equals(userInfoSignAlgorithm)
                && !idTokenSignAlgorithm.equals(userInfoSignAlgorithm)) {
            diffAlgorithms.add(userInfoSignAlgorithm);
        }
        return diffAlgorithms;
    }

    private String getTenantDomain() {

        Object tenantObj = IdentityUtil.threadLocalProperties.get().get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        if (tenantObj != null && StringUtils.isNotBlank((String) tenantObj)) {
            return (String) tenantObj;
        }
        return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    }

    private String logAndReturnError(String errorMesage, Exception e) {

        if (e != null) {
            log.error(errorMesage, e);
        } else {
            log.error(errorMesage);
        }
        return errorMesage;
    }

    /**
     * This method generates the key store file name from the Domain Name.
     *
     * @return key store file name
     */
    private String generateKSNameFromDomainName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(".", "-");
        return (ksName + ".jks");
    }

    /**
     * This method generates the base64 encoded certificate list from a Certificate array.
     *
     * @return base64 encoded certificate list.
     */
    private List<Base64> generateEncodedCertList(Certificate[] certificates, String alias)
            throws CertificateEncodingException {

        List<Base64> certList = new ArrayList<>();
        for (Certificate certificate : certificates) {
            try {
                certList.add(Base64.encode(certificate.getEncoded()));
            } catch (CertificateEncodingException exception) {
                String errorMessage = "Unable to encode the public certificate with alias: " + alias +
                        " in the tenant domain: " + getTenantDomain();
                throw new CertificateEncodingException(errorMessage, exception);
            }
        }
        return certList;
    }
}
