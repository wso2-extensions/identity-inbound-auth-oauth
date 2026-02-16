/*
 * Copyright (c) 2015-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.jws.WebService;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.JWT_X5T_ENABLED;

/**
 * Rest implementation for JWKS endpoint.
 */
@WebService
public class JwksEndpoint {

    private static final Log log = LogFactory.getLog(JwksEndpoint.class);
    private static final String KEY_USE = "sig";
    private static final String KEYS = "keys";
    private static final String ADD_PREVIOUS_VERSION_KID = "JWTValidatorConfigs.JWKSEndpoint.AddPreviousVersionKID";
    private static final String ENABLE_X5C_IN_RESPONSE = "JWTValidatorConfigs.JWKSEndpoint.EnableX5CInResponse";
    public static final String JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED = "JWTValidatorConfigs.JWKSEndpoint" +
            ".IsThumbprintHexifyRequired";

    @GET
    @Path(value = "/jwks")
    @Produces(MediaType.APPLICATION_JSON)
    public String jwks() {

        String tenantDomain = getTenantDomain();

        try {
            final KeyStore keystore = IdentityKeyStoreResolver.getInstance().getKeyStore(tenantDomain,
                    IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
            List<CertificateInfo> certificateInfoList = new ArrayList<>();
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

        List<Map<String, Object>> jwksArray = new ArrayList<>();
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
                                   List<Map<String, Object>> jwksArray, String hashingAlgorithm)
            throws IdentityOAuth2Exception, ParseException, CertificateEncodingException, JOSEException {

        for (CertificateInfo certInfo : certInfoList) {
            for (JWSAlgorithm algorithm : diffAlgorithms) {
                String alias = certInfo.getCertificateAlias();
                X509Certificate cert = (X509Certificate) certInfo.getCertificate();
                Certificate[] certChain = certInfo.getCertificateChain();
                List<Base64> encodedCertList = generateEncodedCertList(certChain, alias);
                JWK jwk = getJWK(algorithm, encodedCertList, cert, hashingAlgorithm, alias);
                
                // Skip if key type is not supported
                if (jwk != null) {
                    jwksArray.add(jwk.toJSONObject());
                }
            }
        }
    }

    private JWK getJWK(JWSAlgorithm algorithm, List<Base64> encodedCertList, X509Certificate certificate,
                      String kidAlgorithm, String alias)
            throws ParseException, IdentityOAuth2Exception, JOSEException {

        PublicKey publicKey = certificate.getPublicKey();
        
        // Only handle RSA keys - EdDSA and EC keys are served via separate endpoint
        if (!(publicKey instanceof RSAPublicKey)) {
            if (log.isDebugEnabled()) {
                log.debug("Skipping non-RSA key for alias: " + alias + 
                         ", algorithm: " + publicKey.getAlgorithm() + 
                         " (EdDSA/EC keys are served via separate endpoint)");
            }
            return null;
        }
        
        // Determine key ID
        String keyId;
        if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
            keyId = OAuth2Util.getKID(certificate, algorithm, getTenantDomain());
        } else {
            keyId = OAuth2Util.getPreviousKID(certificate, algorithm, getTenantDomain());
        }

        // Build RSA JWK
        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) publicKey)
                .keyID(keyId)
                .algorithm(algorithm)
                .keyUse(KeyUse.parse(KEY_USE));
        
        if (Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))) {
            builder.x509CertChain(encodedCertList);
        }
        
        addThumbprints(builder, certificate, alias);
        return builder.build();
    }
    
    /**
     * Add X.509 certificate thumbprints to RSA JWK builder.
     */
    private void addThumbprints(RSAKey.Builder builder, X509Certificate certificate, String alias)
            throws ParseException, JOSEException, IdentityOAuth2Exception {
        
        if (!Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))) {
            // x5t#S256
            JWK parsedJWK = JWK.parse(certificate);
            builder.x509CertSHA256Thumbprint(parsedJWK.getX509CertSHA256Thumbprint());

            // x5t
            if (Boolean.parseBoolean(IdentityUtil.getProperty(JWT_X5T_ENABLED))) {
                log.debug("Adding SHA-1 thumbprint (x5t) to JWK.");  
                String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
                builder.x509CertThumbprint(new Base64URL(certThumbPrint));
            }
        } else {
            // x5t#S256
            builder.x509CertSHA256Thumbprint(new Base64URL(OAuth2Util.getThumbPrint(certificate, alias)));

            // x5t
            if (Boolean.parseBoolean(IdentityUtil.getProperty(JWT_X5T_ENABLED))) {
                String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, true);
                builder.x509CertThumbprint(new Base64URL(certThumbPrint));
            }
        }
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
    private void createKeySetUsingOldKeyID(List<Map<String, Object>> jwksArray, List<CertificateInfo> certInfoList,
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
