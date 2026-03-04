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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
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
    private static final String KEYS = "keys";
    private static final String ADD_PREVIOUS_VERSION_KID = "JWTValidatorConfigs.JWKSEndpoint.AddPreviousVersionKID";
    private static final String ENABLE_X5C_IN_RESPONSE = "JWTValidatorConfigs.JWKSEndpoint.EnableX5CInResponse";
    public static final String JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED = "JWTValidatorConfigs.JWKSEndpoint" +
            ".IsThumbprintHexifyRequired";
    public static final String JWKS_IS_X5T_REQUIRED = "JWTValidatorConfigs.JWKSEndpoint" +
            ".IsX5tRequired";

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

        JSONArray jwksArray = new JSONArray();
        JSONObject jwksJson = new JSONObject();
        populateJWKSArray(certInfoList, jwksArray, OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM);

        // Add SHA-1 KeyID to the KeySet if the config is enabled.
        if (Boolean.parseBoolean(IdentityUtil.getProperty(ADD_PREVIOUS_VERSION_KID))) {
            populateJWKSArray(certInfoList, jwksArray,
                    OAuthConstants.SignatureAlgorithms.PREVIOUS_KID_HASHING_ALGORITHM);
            // For previous RSA approach with old KID
            OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
            JWSAlgorithm accessTokenSignAlgorithm =
                    OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getSignatureAlgorithm());
            // This method add KeySets which have thumbprint of certificate as KeyIDs without appending the algo.
            // This KeyID format is deprecated. However, we are enabling old KeyID based on config to support migration.
            createKeySetUsingOldKeyID(jwksArray, certInfoList, accessTokenSignAlgorithm);
        }
        jwksJson.put(KEYS, jwksArray);
        return jwksJson.toString();
    }

    private void populateJWKSArray(List<CertificateInfo> certInfoList, JSONArray jwksArray, String hashingAlgorithm)
            throws IdentityOAuth2Exception, ParseException, CertificateEncodingException, JOSEException {

        for (CertificateInfo certInfo : certInfoList) {
            String alias = certInfo.getCertificateAlias();
            X509Certificate cert = (X509Certificate) certInfo.getCertificate();
            Certificate[] certChain = certInfo.getCertificateChain();
            
            // Handle null or empty certificate chain
            List<Base64> encodedCertList = new ArrayList<>();
            if (certChain != null && certChain.length > 0) {
                encodedCertList = generateEncodedCertList(certChain, alias);
            }
            
            PublicKey publicKey = cert.getPublicKey();
            List<JWSAlgorithm> algorithms = resolveSupportedSigningAlgorithms(publicKey);

            for (JWSAlgorithm algorithm : algorithms) {
                JWK jwk = getJWK(algorithm, encodedCertList, cert, hashingAlgorithm, alias);
                jwksArray.add(jwk.toJSONObject());
            }
        }
    }

    private List<JWSAlgorithm> resolveSupportedSigningAlgorithms(PublicKey publicKey) throws IdentityOAuth2Exception {

        List<JWSAlgorithm> algs = new ArrayList<>();
        
        // Check if there is a publicKey instance
        if (publicKey == null) {
            throw new IdentityOAuth2Exception("Public key is null. Unable to resolve supported signing algorithms.");
        }
        
        // Preserving previous behaviour for backward compatibility
        if (publicKey instanceof RSAPublicKey) {
            OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
            JWSAlgorithm accessTokenSignAlgorithm =
                    OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getSignatureAlgorithm());
            // If we read different algorithms from identity.xml then put them in a list.
            List<JWSAlgorithm> configuredAlgs = findDifferentAlgorithms(accessTokenSignAlgorithm, config);
            // Filter to only include RSA-compatible algorithms for RSA keys
            for (JWSAlgorithm configuredAlg : configuredAlgs) {
                if (JWSAlgorithm.Family.RSA.contains(configuredAlg)) {
                    algs.add(configuredAlg);
                }
            }
            if (algs.isEmpty()) {
                throw new IdentityOAuth2Exception("No RSA-compatible signing algorithm configured for RSA key.");
            }
            return algs;
        } else if (publicKey instanceof ECPublicKey) {
            Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            if (Curve.P_256.equals(curve)) {
                algs.add(JWSAlgorithm.ES256);
                return algs;
            }
            throw new IdentityOAuth2Exception("Only P256 EC keys are supported for ES256. Found " + curve);
        } else if ("Ed25519".equals(publicKey.getAlgorithm()) || "EdDSA".equals(publicKey.getAlgorithm())) {
            // Validate that EdDSA is specifically Ed25519, not Ed448
            byte[] encodedKey = publicKey.getEncoded();
            if (!isEd25519Spki(encodedKey)) {
                throw new IdentityOAuth2Exception("Only Ed25519 keys are supported for EdDSA." + 
                "Found different EdDSA variant.");
            }
            algs.add(JWSAlgorithm.EdDSA);
            return algs;
        }
        throw new IdentityOAuth2Exception("Unsupported public key type in JWKS: " + publicKey.getAlgorithm() +
                " (" + publicKey.getClass().getName() + ")");
    }

    private JWK getJWK(JWSAlgorithm algorithm, List<Base64> encodedCertList, X509Certificate certificate,
                       String kidAlgorithm, String alias)
            throws CertificateEncodingException, ParseException, IdentityOAuth2Exception, JOSEException {

        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey instanceof RSAPublicKey) {
            RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) publicKey);
            if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
                jwk.keyID(OAuth2Util.getKID(certificate, algorithm, getTenantDomain()));
            } else {
                jwk.keyID(OAuth2Util.getPreviousKID(certificate, algorithm, getTenantDomain()));
            }
            jwk.algorithm(algorithm);
            jwk.keyUse(KeyUse.parse(KEY_USE));
            if (Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))) {
                jwk.x509CertChain(encodedCertList);
            }
            if (!Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))) {
                if (Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))) {
                    String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
                    jwk.x509CertThumbprint(new Base64URL(certThumbPrint));
                }
                JWK parsedJWK = JWK.parse(certificate);
                jwk.x509CertSHA256Thumbprint(parsedJWK.getX509CertSHA256Thumbprint());
            } else {
                if (Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))) {
                    String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, true);
                    jwk.x509CertThumbprint(new Base64URL(certThumbPrint));
                }
                jwk.x509CertSHA256Thumbprint(new Base64URL(OAuth2Util.getThumbPrint(certificate, alias)));
            }
            return jwk.build();
        } else if (publicKey instanceof ECPublicKey) {
            Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            ECKey.Builder jwk = new ECKey.Builder(curve, (ECPublicKey) publicKey);
            if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
                jwk.keyID(OAuth2Util.getKID(certificate, algorithm, getTenantDomain()));
            } else {
                jwk.keyID(OAuth2Util.getPreviousKID(certificate, algorithm, getTenantDomain()));
            }
            jwk.algorithm(algorithm);
            jwk.keyUse(KeyUse.parse(KEY_USE));
            if (Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))) {
                jwk.x509CertChain(encodedCertList);
            }
            if (!Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))) {
                if (Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))) {
                    String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
                    jwk.x509CertThumbprint(new Base64URL(certThumbPrint));
                }
                JWK parsedJWK = JWK.parse(certificate);
                jwk.x509CertSHA256Thumbprint(parsedJWK.getX509CertSHA256Thumbprint());
            } else {
                if (Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))) {
                    String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, true);
                    jwk.x509CertThumbprint(new Base64URL(certThumbPrint));
                }
                jwk.x509CertSHA256Thumbprint(new Base64URL(OAuth2Util.getThumbPrint(certificate, alias)));
            }
            return jwk.build();
        } else if ("Ed25519".equals(publicKey.getAlgorithm()) || "EdDSA".equals(publicKey.getAlgorithm())) {
            // Extract the raw 32-byte public key identifier from the ASN.1 encoded public key
            byte[] encodedKey = publicKey.getEncoded();
            if (!isEd25519Spki(encodedKey)) {
                throw new IdentityOAuth2Exception("Only Ed25519 keys are supported for EdDSA.");
            }
            byte[] xCoordinate = Arrays.copyOfRange(encodedKey, encodedKey.length - 32, encodedKey.length);

            OctetKeyPair.Builder jwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(xCoordinate));
            if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
                jwk.keyID(OAuth2Util.getKID(certificate, algorithm, getTenantDomain()));
            } else {
                jwk.keyID(OAuth2Util.getPreviousKID(certificate, algorithm, getTenantDomain()));
            }
            jwk.algorithm(algorithm);
            jwk.keyUse(KeyUse.parse(KEY_USE));
            if (Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))) {
                jwk.x509CertChain(encodedCertList);
            }
            if (!Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))) {
                if (Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))) {
                    String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
                    jwk.x509CertThumbprint(new Base64URL(certThumbPrint));
                }
                // JWK.parse(certificate) does not support Ed25519 keys, so compute the SHA-256
                // thumbprint directly instead of going through JWK.parse().
                jwk.x509CertSHA256Thumbprint(new Base64URL(OAuth2Util.getThumbPrint(certificate, alias)));
            } else {
                if (Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))) {
                    String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, true);
                    jwk.x509CertThumbprint(new Base64URL(certThumbPrint));
                }
                jwk.x509CertSHA256Thumbprint(new Base64URL(OAuth2Util.getThumbPrint(certificate, alias)));
            }
            return jwk.build();
        }
        throw new IdentityOAuth2Exception("Unsupported public key type in JWKS. Key algorithm "
                + publicKey.getAlgorithm());
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
            PublicKey publicKey = cert.getPublicKey();
            //  Preserve Backward compatibility
            if (publicKey instanceof RSAPublicKey) {
                RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) publicKey);
                jwk.keyID(OAuth2Util.getThumbPrintWithPrevAlgorithm(cert));
                jwk.algorithm(algorithm);
                jwk.keyUse(KeyUse.parse(KEY_USE));
                jwksArray.add(jwk.build().toJSONObject());
            }
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

    /**
     * Validates that the EdDSA public key is specifically Ed25519 (not Ed448).
     * Per RFC 8410, the EdDSA variant is identified by the AlgorithmIdentifier OID
     * in the X.509 SubjectPublicKeyInfo structure.
     * Ed25519 OID: 1.3.101.112
     * Ed448 OID: 1.3.101.113
     *
     * @param encodedKey the ASN.1 encoded public key from publicKey.getEncoded()
     * @return true if the key is Ed25519, false otherwise
     */
    private boolean isEd25519Spki(byte[] encodedKey) {

        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encodedKey));
            // Get the algorithm OID from the SubjectPublicKeyInfo
            String oid = spki.getAlgorithm().getAlgorithm().getId();
            // Ed25519 OID: 1.3.101.112
            return "1.3.101.112".equals(oid);
        } catch (Exception e) {
            log.error("Error while validating Ed25519 SPKI structure for tenant domain: " + getTenantDomain(), e);
            return false;
        }
    }
}
