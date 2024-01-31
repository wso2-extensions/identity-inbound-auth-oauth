/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Utility class for JWT related operations.
 */
public class JWTUtils {

    private static final Log log = LogFactory.getLog(JWTUtils.class);
    private static final String DOT_SEPARATOR = ".";
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ALGO_PREFIX = "RS";
    private static final String ALGO_PREFIX_PS = "PS";

    /**
     * Parse JWT Token.
     *
     * @param accessToken Access Token
     * @return SignedJWT    Signed JWT
     * @throws ParseException If an error occurs while parsing the JWT token.
     */
    public static SignedJWT parseJWT(String accessToken) throws ParseException {

        return SignedJWT.parse(accessToken);
    }

    /**
     * Return true if the token identifier is JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    public static boolean isJWT(String tokenIdentifier) {
        // JWT token contains 3 base64 encoded components separated by periods.
        return StringUtils.countMatches(tokenIdentifier, DOT_SEPARATOR) == 2;
    }

    /**
     * Get JWT Claim sets for the given access token.
     *
     * @param signedJWT Signed JWT
     * @return JWT Claim sets
     * @throws IdentityOAuth2Exception If an error occurs while getting the JWT claim sets.
     */
    public static Optional<JWTClaimsSet> getJWTClaimSet(SignedJWT signedJWT)
            throws IdentityOAuth2Exception {

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            return Optional.ofNullable(claimsSet);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while retrieving claim set from Token.", e);
        }
    }

    /**
     * Validate Requested Fields in JWT claim set. Eg: issuer, sub, exp, aud, jti
     *
     * @param claimsSet JWT Claim set
     * @return true required fields present, false otherwise.
     */
    public static boolean validateRequiredFields(JWTClaimsSet claimsSet) {

        String subject = resolveSubject(claimsSet);
        List<String> audience = claimsSet.getAudience();
        String jti = claimsSet.getJWTID();
        if (StringUtils.isEmpty(claimsSet.getIssuer()) || StringUtils.isEmpty(subject) ||
                claimsSet.getExpirationTime() == null || audience == null || jti == null) {
            if (log.isDebugEnabled()) {
                log.debug("Mandatory fields(Issuer, Subject, Expiration time," +
                        " jtl or Audience) are empty in the given Token.");
            }
            return false;
        }
        return true;
    }

    /**
     * Resolve subject from JWTClaims.
     *
     * @param claimsSet JWT Claim set
     * @return Subject claim value
     */
    public static String resolveSubject(JWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    /**
     * Retrieves the signing tenant domain from the given JWT claims set and AccessTokenDO, considering various sources
     * such as the 'realm' claim, the 'signing_tenant' claim, and the OAuth application associated with the AccessToken.
     *
     * @param claimsSet     The JWTClaimsSet containing the claims of the JWT, including the 'realm' claim.
     * @param accessTokenDO The AccessTokenDO associated with the OAuth token.
     * @return The signing tenant domain based on the provided claims and AccessTokenDO.
     * @throws ParseException          If an error occurs while parsing the JWT claims.
     * @throws IdentityOAuth2Exception If an error occurs in OAuth2-related functionality.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static String getSigningTenantDomain(JWTClaimsSet claimsSet, AccessTokenDO accessTokenDO)
            throws ParseException, IdentityOAuth2Exception {

        Map<String, String> realm = (HashMap) claimsSet.getClaim(OAuthConstants.OIDCClaims.REALM);
        if (MapUtils.isNotEmpty(realm)) {
            if (realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT) != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Getting signing tenant domain from JWT's 'signing_tenant' claim.");
                }
                return realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT);
            } else if (realm.get(OAuthConstants.OIDCClaims.TENANT) != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Getting signing tenant domain from JWT's 'tenant' claim.");
                }
                return realm.get(OAuthConstants.OIDCClaims.TENANT);
            }
        }
        if (accessTokenDO == null) {
            return getTenantDomain();
        }
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        if (isJWTSignedWithSPKey) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Getting signing tenant domain from OAuth app.");
                }
                return OAuth2Util.getTenantDomainOfOauthApp(accessTokenDO.getConsumerKey());
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while getting tenant domain from OAuth app with consumer key: "
                        + accessTokenDO.getConsumerKey());
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Getting signing tenant domain from authenticated user.");
            }
            return accessTokenDO.getAuthzUser().getTenantDomain();
        }
    }

    /**
     * Retrieves the tenant domain associated with the current execution context using CarbonContext.
     * If the tenant domain is empty or not available, the super tenant domain name is returned as the default.
     *
     * @return The tenant domain associated with the current execution context, or the super tenant domain name
     * if not available.
     */
    private static String getTenantDomain() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * Retrieves the resident Identity Provider (IDP) associated with the issuer of the provided JSON Web Token (JWT)
     * claims set within the context of a given tenant.
     *
     * @param claimsSet    The JWTClaimsSet containing the claims of the JWT, including the issuer
     * @param tenantDomain The domain of the tenant for which the resident IDP needs to be retrieved.
     * @return The resident Identity Provider associated with the JWT issuer
     * @throws IdentityOAuth2Exception If an error occurs while processing OAuth2-related functionality.
     */
    public static IdentityProvider getResidentIDPForIssuer(JWTClaimsSet claimsSet, String tenantDomain)
            throws IdentityOAuth2Exception {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg =
                    String.format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDC_IDP_ENTITY_ID).getValue();
        }
        if (!claimsSet.getIssuer().equals(issuer)) {
            throw new IdentityOAuth2Exception("No Registered IDP found for the token with issuer name : "
                    + claimsSet.getIssuer());
        }
        return residentIdentityProvider;
    }

    /**
     * Checks if the provided expiration time of a token is valid, considering the configured timestamp skew.
     *
     * @param expirationTime The expiration time of the token to be checked.
     * @return True if the token is not expired, false otherwise.
     */
    public static boolean checkExpirationTime(Date expirationTime) {

        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug("Token is expired." +
                        ", Expiration Time(ms) : " + expirationTimeInMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
            }
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Expiration Time(exp) of Token was validated successfully.");
        }
        return true;
    }

    /**
     * Validates that the provided token's "Not Before" time has passed, considering the configured timestamp skew.
     * If the token is used before the "Not Before" time, an IdentityOAuth2Exception is thrown.
     *
     * @param notBeforeTime The "Not Before" time of the token to be validated.
     * @throws IdentityOAuth2Exception If the token is used before the "Not Before" time.
     */
    public static void checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Token is used before Not_Before_Time." +
                            ", Not Before Time(ms) : " + notBeforeTimeMillis +
                            ", TimeStamp Skew : " + timeStampSkewMillis +
                            ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    Map<String, Object> params = new HashMap<>();
                    params.put("notBeforeTime", notBeforeTimeMillis);
                    params.put("timestampSkew", timeStampSkewMillis);
                    params.put("currentTime", currentTimeInMillis);
                    LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                            OAuthConstants.LogConstants.FAILED, "Token is used before Not_Before_Time.",
                            "validate-jwt-access-token", null);
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }
    }

    /**
     * Verifies and retrieves the signature algorithm from the header of the given SignedJWT.
     *
     * @param signedJWT The SignedJWT from which to verify and retrieve the signature algorithm.
     * @return The signature algorithm.
     * @throws IdentityOAuth2Exception If the algorithm is null or empty in the token header.
     */
    public static String verifyAlgorithm(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new IdentityOAuth2Exception("Algorithm must not be null.");
        }
        if (log.isDebugEnabled()) {
            log.debug("Signature Algorithm found in the Token Header: " + alg);
        }
        return alg;
    }

    /**
     * Verifies the signature of the given SignedJWT using the provided X.509 certificate and signature algorithm.
     *
     * @param signedJWT       The SignedJWT to verify.
     * @param x509Certificate The X.509 certificate used for signature verification.
     * @param alg             The signature algorithm.
     * @return True if the signature is valid, false otherwise.
     * @throws IdentityOAuth2Exception If an error occurs during signature verification.
     * @throws JOSEException           If an error occurs in the JOSE library.
     */
    public static boolean verifySignature(SignedJWT signedJWT, X509Certificate x509Certificate, String alg)
            throws IdentityOAuth2Exception, JOSEException {

        JWSVerifier verifier = null;
        if (alg.indexOf(ALGO_PREFIX) == 0 || alg.indexOf(ALGO_PREFIX_PS) == 0) {
            // At this point 'x509Certificate' will never be null.
            PublicKey publicKey = x509Certificate.getPublicKey();
            if (publicKey instanceof RSAPublicKey) {
                verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            } else {
                throw new IdentityOAuth2Exception("Public key is not an RSA public key.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm not supported yet: " + alg);
            }
        }
        if (verifier == null) {
            throw new IdentityOAuth2Exception("Could not create a signature verifier for algorithm type: " + alg);
        }
        boolean isValid;
        isValid = signedJWT.verify(verifier);
        if (log.isDebugEnabled()) {
            log.debug("Signature verified: " + isValid);
        }
        return isValid;
    }

    /**
     * Retrieves an X.509 certificate from the JWT claims, specifically from the 'realm' claim,
     * considering the signing tenant information. If available, the certificate is obtained from the tenant's keystore.
     *
     * @param jwtClaimsSet The JWTClaimsSet containing the claims, including the 'realm' claim with signing tenant
     *                     information.
     * @return An Optional containing the X.509 certificate if found, or an empty Optional if not available.
     * @throws IdentityOAuth2Exception If an error occurs during the retrieval of the X.509 certificate.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static Optional<X509Certificate> getCertificateFromClaims(JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2Exception {

        X509Certificate x509Certificate = null;
        Map<String, String> realm = (HashMap) jwtClaimsSet.getClaim(OAuthConstants.OIDCClaims.REALM);
        // Get certificate from tenant if available in claims.
        if (MapUtils.isNotEmpty(realm)) {
            String tenantDomain = null;
            // Get signed key tenant from JWT token or ID token based on claim key.
            if (realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT) != null) {
                tenantDomain = realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT);
            } else if (realm.get(OAuthConstants.OIDCClaims.TENANT) != null) {
                tenantDomain = realm.get(OAuthConstants.OIDCClaims.TENANT);
            }
            if (tenantDomain != null) {
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                // Retrieve the X.509 certificate from the tenant's keystore.
                x509Certificate = (X509Certificate) OAuth2Util.getCertificate(tenantDomain, tenantId);
            }
        }
        return Optional.ofNullable(x509Certificate);
    }


    /**
     * This resolves one certificate to Identity Provider and ignores the JWT header.
     *
     * @param idp The identity provider, if you need it.
     * @return the resolved X509 Certificate, to be used to validate the JWT signature.
     * @throws IdentityOAuth2Exception something goes wrong.
     */
    public static X509Certificate resolveSignerCertificate(IdentityProvider idp) throws IdentityOAuth2Exception {

        X509Certificate x509Certificate;
        String tenantDomain = getTenantDomain();
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }
        return x509Certificate;
    }
}
