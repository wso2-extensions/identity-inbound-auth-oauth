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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
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
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.jws.WebService;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@WebService
public class JwksEndpoint {
    private static final Log log = LogFactory.getLog(JwksEndpoint.class);
    private static final String KEY_USE = "sig";
    private static final String SECURITY_KEY_STORE_LOCATION = "Security.KeyStore.Location";
    private static final String SECURITY_KEY_STORE_PW = "Security.KeyStore.Password";
    private static final String KEYS = "keys";

    @GET
    @Path(value = "/jwks")
    @Produces(MediaType.APPLICATION_JSON)
    public String jwks() {

        String tenantDomain = getTenantDomain();
        String keystorePath = CarbonUtils.getServerConfiguration().getFirstProperty(SECURITY_KEY_STORE_LOCATION);

        try (FileInputStream file = new FileInputStream(keystorePath)) {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            final KeyStore keystore;
            Map<String, Certificate> certificatesWithAliases = new HashMap<>();
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {
                keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                String password = CarbonUtils.getServerConfiguration().getFirstProperty(SECURITY_KEY_STORE_PW);
                keystore.load(file, password.toCharArray());
            } else {
                if (isInvalidTenantId(tenantId)) {
                    String errorMessage = "Invalid Tenant: " + tenantDomain;
                    return logAndReturnError(errorMessage, null);
                }
                FrameworkUtils.startTenantFlow(tenantDomain);
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                keystore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
            }
            Enumeration enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = (String) enumeration.nextElement();
                if (keystore.isKeyEntry(alias)) {
                    Certificate cert = keystore.getCertificate(alias);
                    certificatesWithAliases.put(alias, cert);
                }
            }
            return buildResponse(certificatesWithAliases);
        } catch (Exception e) {
            String errorMessage = "Error while generating the keyset for tenant domain: " + tenantDomain;
            return logAndReturnError(errorMessage, e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
    }

    private String buildResponse(Map<String, Certificate> certificates)
            throws IdentityOAuth2Exception, ParseException {

        JSONArray jwksArray = new JSONArray();
        JSONObject jwksJson = new JSONObject();
        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        JWSAlgorithm accessTokenSignAlgorithm =
                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getSignatureAlgorithm());
        // This method add keysets which have thumbprint of certificate as KeyIDs.
        jwksArray = createKeysetUsingOldKeyID(jwksArray, certificates, accessTokenSignAlgorithm);
        // If we read different algorithms from identity.xml then put them in a list.
        List<JWSAlgorithm> diffAlgorithms = findDifferentAlgorithms(accessTokenSignAlgorithm, config);
        // Create JWKS for different algorithms using new KeyID creation method.
        for (Map.Entry certificateWithAlias : certificates.entrySet()) {
            for (JWSAlgorithm algorithm : diffAlgorithms) {
                Certificate cert = (Certificate) certificateWithAlias.getValue();
                String alias = (String) certificateWithAlias.getKey();
                RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
                RSAKey.Builder jwk = new RSAKey.Builder(publicKey);
                jwk.keyID(OAuth2Util.getKID(OAuth2Util.getThumbPrint(cert, alias), algorithm));
                jwk.algorithm(algorithm);
                jwk.keyUse(KeyUse.parse(KEY_USE));
                jwksArray.put(jwk.build().toJSONObject());
            }
        }
        jwksJson.put(KEYS, jwksArray);
        return jwksJson.toString();
    }

    /**
     *
     * @deprecated Earlier for all the type of JWT Tokens(eg: accessToken, ID token) only one algorithm is shown as
     * "algo" in keysets on the JWKS endpoint. But it is possible to configure different algorithms for different
     * JWT Types via identity.xml. Thus it is recommended to create keysets for different algorithms. In earlier
     * cases thumbprint of certificate is used as KeyID but to differentiate algorithms which uses same certificates a
     * new KeyID generating mechanism is created in the OAuth2Util. However for backward compatibility, a keyset
     * which uses thumbPrint as KeyID is added. In future it okay to remove this keyset completely.
     *
     * This method is marked as @deprecated because this method should not be used in any other places. In future
     * this method should be removed.
     *
     */
    @Deprecated
    private JSONArray createKeysetUsingOldKeyID(JSONArray jwksArray, Map<String, Certificate> certificates,
                                                JWSAlgorithm algorithm) throws IdentityOAuth2Exception, ParseException {

        JSONArray OldJwksArray = jwksArray;
        for (Map.Entry certificateWithAlias : certificates.entrySet()) {
            Certificate cert = (Certificate) certificateWithAlias.getValue();
            String alias = (String) certificateWithAlias.getKey();
            RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
            RSAKey.Builder jwk = new RSAKey.Builder(publicKey);
            jwk.keyID(OAuth2Util.getThumbPrint(cert, alias));
            jwk.algorithm(algorithm);
            jwk.keyUse(KeyUse.parse(KEY_USE));
            jwksArray.put(jwk.build().toJSONObject());
        }
        return OldJwksArray;
    }

    /**
     * This method read identity.xml and find different signing algorithms
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

    private boolean isInvalidTenantId(int tenantId) {
        return tenantId < 1 && tenantId != MultitenantConstants.SUPER_TENANT_ID;
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
     * This method generates the key store file name from the Domain Name
     *
     * @return key store file name
     */
    private String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(".", "-");
        return (ksName + ".jks");
    }
}
