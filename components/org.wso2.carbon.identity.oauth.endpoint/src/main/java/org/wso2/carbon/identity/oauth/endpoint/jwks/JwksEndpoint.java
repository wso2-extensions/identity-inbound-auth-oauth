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
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.services.OAuth2OIDCConfigOrgUsageScopeMgtService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

        String tenantDomain = StringUtils.EMPTY;
        String appResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();

        try {
            if (StringUtils.isNotEmpty(appResidentOrgId)) {
                OAuth2OIDCConfigOrgUsageScopeMgtService oAuth2OIDCConfigOrgUsageScopeMgtService =
                        OAuth2ServiceComponentHolder.getInstance().getOAuth2OIDCConfigOrgUsageScopeMgtService();
                List<IssuerDetails> issuerDetailsList =
                        oAuth2OIDCConfigOrgUsageScopeMgtService.getAllowedIssuerDetails();
                if (issuerDetailsList != null && !issuerDetailsList.isEmpty()) {
                    Map<String, List<CertificateInfo>> issuerCertificateInfoMap = new HashMap<>();
                    if (log.isDebugEnabled()) {
                        log.debug("Retrieved issuer details for organization id: " + appResidentOrgId);
                    }
                    for (IssuerDetails issuerDetails : issuerDetailsList) {
                        tenantDomain = issuerDetails.getIssuerTenantDomain();
                        if (log.isDebugEnabled()) {
                            log.debug("Retrieving certificate information for tenant domain: " + tenantDomain);
                        }
                        List<CertificateInfo> certificateInfos = getCertificateInfoList(tenantDomain);
                        issuerCertificateInfoMap.put(tenantDomain, certificateInfos);
                    }
                    return buildResponseForMultipleCertificates(issuerCertificateInfoMap);
                }
                String errorMessage = "No allowed issuer details found for organization id: " + appResidentOrgId;
                return logAndReturnError(errorMessage, null);
            } else {
                tenantDomain = getTenantDomain();
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
            }
        } catch (Exception e) {
            String errorMessage = "Error while generating the keyset for tenant domain: " + tenantDomain;
            return logAndReturnError(errorMessage, e);
        }
    }

    /**
     * Returns the certificate information list for the given tenant domain. This method reads the keystore
     * for the tenant and extracts the certificate information for all key entries.
     *
     * @param tenantDomain The tenant domain for which to retrieve the certificate information.
     * @return List of CertificateInfo objects containing the certificate and its alias for the tenant domain.
     * @throws IdentityKeyStoreResolverException If there is an error resolving the keystore for the tenant domain.
     * @throws KeyStoreException If there is an error accessing the keystore or retrieving the certificate information.
     */
    private static List<CertificateInfo> getCertificateInfoList(String tenantDomain) throws
            IdentityKeyStoreResolverException, KeyStoreException {

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
        return certificateInfoList;
    }

    /**
     * Builds the JWKS response for multiple certificates across different tenants.
     *
     * @param issuerCertificateInfoMap A map where the key is the tenant domain and the value is a list of
     *                                 CertificateInfo objects for that tenant.
     * @return A JSON string representing the JWKS response containing keys from multiple tenants.
     * @throws IdentityOAuth2Exception If there is an error while processing the certificates.
     * @throws ParseException If there is an error while parsing the certificates into JWKs.
     * @throws CertificateEncodingException If there is an error while encoding the certificates.
     * @throws JOSEException If there is an error while creating JWKs from the certificates.
     */
    private String buildResponseForMultipleCertificates(Map<String, List<CertificateInfo>> issuerCertificateInfoMap)
            throws IdentityOAuth2Exception, ParseException, CertificateEncodingException, JOSEException {

        JSONObject jwksJson = new JSONObject();
        JSONArray jwksArray = new JSONArray();
        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        JWSAlgorithm accessTokenSignAlgorithm =
                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getSignatureAlgorithm());
        // If there are different algorithms from identity.xml then put them in a list.
        List<JWSAlgorithm> diffAlgorithms = findDifferentAlgorithms(accessTokenSignAlgorithm, config);

        for (Map.Entry<String, List<CertificateInfo>> entry : issuerCertificateInfoMap.entrySet()) {
            List<CertificateInfo> certInfoList = entry.getValue();
            // Create JWKS for different algorithms using new KeyID creation method.
            populateJWKSArray(certInfoList, diffAlgorithms, jwksArray,
                    OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM, entry.getKey());

            // Add SHA-1 KeyID to the KeySet if the config is enabled.
            if (Boolean.parseBoolean(IdentityUtil.getProperty(ADD_PREVIOUS_VERSION_KID))) {
                populateJWKSArray(certInfoList, diffAlgorithms, jwksArray,
                        OAuthConstants.SignatureAlgorithms.PREVIOUS_KID_HASHING_ALGORITHM, entry.getKey());

                // Skip deprecated thumbprint-only KIDs in combined JWKS to avoid cross-tenant kid collisions.
                if (log.isDebugEnabled()) {
                    log.debug("Skipping deprecated old-format KID entries for combined multi-tenant JWKS response.");
                }
            }
        }
        jwksJson.put(KEYS, jwksArray);
        return jwksJson.toString();
    }

    /**
     * Construct the JWKS array for a list of certificates, supporting multiple algorithms and tenant-aware
     * KID resolution.
     *
     * @param certInfoList List of CertificateInfo objects containing certificate details for a tenant.
     * @param diffAlgorithms List of JWSAlgorithms to generate keys for, based on server configuration.
     * @param jwksArray JSONArray to which the generated JWKs will be added.
     * @param hashingAlgorithm The hashing algorithm to use for KID generation.
     * @param tenantDomain The tenant domain for which the JWKS is being generated.
     * @throws IdentityOAuth2Exception If there is an error while processing the certificates or generating JWKs.
     * @throws ParseException If there is an error while parsing the certificates into JWKs.
     * @throws CertificateEncodingException If there is an error while encoding the certificates.
     * @throws JOSEException If there is an error while creating JWKs from the certificates.
     */
    private void populateJWKSArray(List<CertificateInfo> certInfoList, List<JWSAlgorithm> diffAlgorithms,
                                   JSONArray jwksArray, String hashingAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception, ParseException, CertificateEncodingException, JOSEException {

        for (CertificateInfo certInfo : certInfoList) {
            String alias = certInfo.getCertificateAlias();
            X509Certificate cert = (X509Certificate) certInfo.getCertificate();
            Certificate[] certChain = certInfo.getCertificateChain();

            // Handle null or empty certificate chain
            List<Base64> encodedCertList = new ArrayList<>();
            if (certChain != null && certChain.length > 0) {
                encodedCertList = generateEncodedCertList(certChain, alias, tenantDomain);
            }

            PublicKey publicKey = cert.getPublicKey();

            // Filter algorithms based on key type to ensure compatibility
            List<JWSAlgorithm> compatibleAlgorithms = filterCompatibleAlgorithms(publicKey, diffAlgorithms);

            for (JWSAlgorithm algorithm : compatibleAlgorithms) {
                JWK jwk = getJWKWithTenantAwareKID(algorithm, encodedCertList, cert, hashingAlgorithm, alias,
                        tenantDomain);
                if (jwk != null) {
                    jwksArray.add(jwk.toJSONObject());
                }
            }
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
                encodedCertList = generateEncodedCertList(certChain, alias, null);
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
                log.warn("No RSA-compatible signing algorithm configured for RSA key.");
            }
            return algs;
        } else if (publicKey instanceof ECPublicKey) {
            Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            if (Curve.P_256.equals(curve)) {
                algs.add(JWSAlgorithm.ES256);
                return algs;
            }
            log.warn("Only P256 EC keys are supported for ES256. Found " + curve);
            return algs;
        } else if (publicKey instanceof EdECPublicKey) {
            algs.add(JWSAlgorithm.EdDSA);
            return algs;
        }
        log.warn("Unsupported public key type in JWKS: " + publicKey.getAlgorithm());
        return algs;
    }

    /**
     * Filters the provided algorithms to only include those compatible with the given public key type.
     *
     * @param publicKey The public key to check compatibility for
     * @param algorithms List of algorithms to filter
     * @return List of compatible algorithms
     */
    private List<JWSAlgorithm> filterCompatibleAlgorithms(PublicKey publicKey, List<JWSAlgorithm> algorithms) {

        List<JWSAlgorithm> compatibleAlgorithms = new ArrayList<>();

        if (publicKey instanceof RSAPublicKey) {
            // For RSA keys, filter to only include RSA algorithms
            for (JWSAlgorithm algorithm : algorithms) {
                if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
                    compatibleAlgorithms.add(algorithm);
                }
            }
            if (compatibleAlgorithms.isEmpty()) {
                log.warn("No RSA-compatible algorithms found in the provided list for RSA key.");
            }
        } else if (publicKey instanceof ECPublicKey) {
            // For EC keys, filter to only include EC algorithms
            Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            for (JWSAlgorithm algorithm : algorithms) {
                if (JWSAlgorithm.Family.EC.contains(algorithm)) {
                    // Additional check: ensure the algorithm matches the curve
                    if (Curve.P_256.equals(curve) && JWSAlgorithm.ES256.equals(algorithm)) {
                        compatibleAlgorithms.add(algorithm);
                    } else if (Curve.P_384.equals(curve) && JWSAlgorithm.ES384.equals(algorithm)) {
                        compatibleAlgorithms.add(algorithm);
                    } else if (Curve.P_521.equals(curve) && JWSAlgorithm.ES512.equals(algorithm)) {
                        compatibleAlgorithms.add(algorithm);
                    }
                }
            }
            if (compatibleAlgorithms.isEmpty()) {
                log.warn("No EC-compatible algorithms found in the provided list for EC key with curve: " + curve);
            }
        } else if (publicKey instanceof EdECPublicKey) {
            // For EdDSA keys, filter to only include EdDSA algorithm
            for (JWSAlgorithm algorithm : algorithms) {
                if (JWSAlgorithm.EdDSA.equals(algorithm)) {
                    compatibleAlgorithms.add(algorithm);
                }
            }
            if (compatibleAlgorithms.isEmpty()) {
                log.warn("EdDSA algorithm not found in the provided list for EdDSA key.");
            }
        } else {
            log.warn("Unsupported public key type for algorithm filtering: " + publicKey.getAlgorithm());
        }
        return compatibleAlgorithms;
    }

    /**
     * Generates a JWK for the given certificate with tenant-aware KID resolution.
     * This method handles RSA, EC, and EdDSA key types.
     *
     * @param algorithm The JWS algorithm
     * @param encodedCertList List of base64-encoded certificates
     * @param certificate The X509 certificate
     * @param kidAlgorithm The hashing algorithm for KID generation
     * @param alias The certificate alias
     * @param tenantDomain The tenant domain for tenant-aware KID resolution
     * @return JWK object or null if key type is unsupported
     * @throws CertificateEncodingException If certificate encoding fails
     * @throws ParseException If JWK parsing fails
     * @throws IdentityOAuth2Exception If OAuth2 processing fails
     * @throws JOSEException If JOSE processing fails
     */
    private JWK getJWKWithTenantAwareKID(JWSAlgorithm algorithm, List<Base64> encodedCertList,
                                         X509Certificate certificate, String kidAlgorithm, String alias,
                                         String tenantDomain)
            throws CertificateEncodingException, ParseException, IdentityOAuth2Exception, JOSEException {

        PublicKey publicKey = certificate.getPublicKey();

        // Resolve KID with tenant awareness
        String keyID;
        if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
            keyID = OAuth2Util.getKID(certificate, algorithm, tenantDomain);
        } else {
            keyID = OAuth2Util.getPreviousKID(certificate, algorithm, tenantDomain);
        }

        boolean thumbprintHexify = Boolean.parseBoolean(
                IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED));
        boolean x5tRequired = Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED));
        boolean addX5c = Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))
                && !encodedCertList.isEmpty();

        // EdECPublicKey: JWK.parse() does not support Ed25519; always use alias-based SHA-256 thumbprint.
        Base64URL sha256Thumbprint;
        if (!thumbprintHexify && !(publicKey instanceof EdECPublicKey)) {
            sha256Thumbprint = JWK.parse(certificate).getX509CertSHA256Thumbprint();
        } else {
            sha256Thumbprint = new Base64URL(OAuth2Util.getThumbPrint(certificate, alias));
        }
        Base64URL x5tThumbprint = x5tRequired
                ? new Base64URL(OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, thumbprintHexify))
                : null;

        if (publicKey instanceof RSAPublicKey) {
            RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) publicKey);
            jwk.keyID(keyID).algorithm(algorithm).keyUse(KeyUse.parse(KEY_USE));
            if (addX5c) {
                jwk.x509CertChain(encodedCertList);
            }
            if (x5tThumbprint != null) {
                jwk.x509CertThumbprint(x5tThumbprint);
            }
            return jwk.x509CertSHA256Thumbprint(sha256Thumbprint).build();
        } else if (publicKey instanceof ECPublicKey) {
            Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            ECKey.Builder jwk = new ECKey.Builder(curve, (ECPublicKey) publicKey);
            jwk.keyID(keyID).algorithm(algorithm).keyUse(KeyUse.parse(KEY_USE));
            if (addX5c) {
                jwk.x509CertChain(encodedCertList);
            }
            if (x5tThumbprint != null) {
                jwk.x509CertThumbprint(x5tThumbprint);
            }
            return jwk.x509CertSHA256Thumbprint(sha256Thumbprint).build();
        } else if (publicKey instanceof EdECPublicKey) {
            byte[] encodedKey = publicKey.getEncoded();
            byte[] xCoordinate = Arrays.copyOfRange(encodedKey, encodedKey.length - 32, encodedKey.length);
            OctetKeyPair.Builder jwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(xCoordinate));
            jwk.keyID(keyID).algorithm(algorithm).keyUse(KeyUse.parse(KEY_USE));
            if (addX5c) {
                jwk.x509CertChain(encodedCertList);
            }
            if (x5tThumbprint != null) {
                jwk.x509CertThumbprint(x5tThumbprint);
            }
            return jwk.x509CertSHA256Thumbprint(sha256Thumbprint).build();
        }

        log.warn("Unsupported public key type in JWKS for tenant " + tenantDomain + ". Key algorithm: "
                + publicKey.getAlgorithm());
        return null;
    }

    private JWK getJWK(JWSAlgorithm algorithm, List<Base64> encodedCertList, X509Certificate certificate,
                       String kidAlgorithm, String alias)
            throws CertificateEncodingException, ParseException, IdentityOAuth2Exception, JOSEException {

        PublicKey publicKey = certificate.getPublicKey();
        String keyID = resolveKeyID(kidAlgorithm, certificate, algorithm);
        boolean thumbprintHexify = Boolean.parseBoolean(
                IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED));
        boolean x5tRequired = Boolean.parseBoolean(IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED));
        boolean addX5c = Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))
                && !encodedCertList.isEmpty();

        // EdECPublicKey: JWK.parse() does not support Ed25519; always use alias-based SHA-256 thumbprint.
        Base64URL sha256Thumbprint;
        if (!thumbprintHexify && !(publicKey instanceof EdECPublicKey)) {
            sha256Thumbprint = JWK.parse(certificate).getX509CertSHA256Thumbprint();
        } else {
            sha256Thumbprint = new Base64URL(OAuth2Util.getThumbPrint(certificate, alias));
        }
        Base64URL x5tThumbprint = x5tRequired
                ? new Base64URL(OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, thumbprintHexify))
                : null;

        if (publicKey instanceof RSAPublicKey) {
            RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) publicKey);
            jwk.keyID(keyID).algorithm(algorithm).keyUse(KeyUse.parse(KEY_USE));
            if (addX5c) {
                jwk.x509CertChain(encodedCertList);
            }
            if (x5tThumbprint != null) {
                jwk.x509CertThumbprint(x5tThumbprint);
            }
            return jwk.x509CertSHA256Thumbprint(sha256Thumbprint).build();
        } else if (publicKey instanceof ECPublicKey) {
            Curve curve = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams());
            ECKey.Builder jwk = new ECKey.Builder(curve, (ECPublicKey) publicKey);
            jwk.keyID(keyID).algorithm(algorithm).keyUse(KeyUse.parse(KEY_USE));
            if (addX5c) {
                jwk.x509CertChain(encodedCertList);
            }
            if (x5tThumbprint != null) {
                jwk.x509CertThumbprint(x5tThumbprint);
            }
            return jwk.x509CertSHA256Thumbprint(sha256Thumbprint).build();
        } else if (publicKey instanceof EdECPublicKey) {
            byte[] encodedKey = publicKey.getEncoded();
            byte[] xCoordinate = Arrays.copyOfRange(encodedKey, encodedKey.length - 32, encodedKey.length);
            OctetKeyPair.Builder jwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(xCoordinate));
            jwk.keyID(keyID).algorithm(algorithm).keyUse(KeyUse.parse(KEY_USE));
            if (addX5c) {
                jwk.x509CertChain(encodedCertList);
            }
            if (x5tThumbprint != null) {
                jwk.x509CertThumbprint(x5tThumbprint);
            }
            return jwk.x509CertSHA256Thumbprint(sha256Thumbprint).build();
        }
        throw new IdentityOAuth2Exception("Unsupported public key type in JWKS. Key algorithm "
                + publicKey.getAlgorithm());
    }

    private String resolveKeyID(String kidAlgorithm, X509Certificate certificate, JWSAlgorithm algorithm)
            throws IdentityOAuth2Exception {

        if (kidAlgorithm.equals(OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM)) {
            return OAuth2Util.getKID(certificate, algorithm, getTenantDomain());
        }
        return OAuth2Util.getPreviousKID(certificate, algorithm, getTenantDomain());
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
    private List<Base64> generateEncodedCertList(Certificate[] certificates, String alias, String tenantDomain)
            throws CertificateEncodingException {

        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = getTenantDomain();
        }
        List<Base64> certList = new ArrayList<>();
        for (Certificate certificate : certificates) {
            try {
                certList.add(Base64.encode(certificate.getEncoded()));
            } catch (CertificateEncodingException exception) {
                String errorMessage = "Unable to encode the public certificate with alias: " + alias +
                        " in the tenant domain: " + tenantDomain;
                throw new CertificateEncodingException(errorMessage, exception);
            }
        }
        return certList;
    }


}
