/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.TokenMgtUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Token Validation processor is supposed to be used during token introspection and user info endpoints where you need
 * to validate the token before proceeding. This class provides methods for validating access tokens and refresh tokens
 * in the context of in-memory token persistence. It implements the TokenProvider interface to offer the following
 * functionalities:
 * - Validating access tokens, including JWT tokens, checking their expiration, signature, and revocation status.
 * - Validating refresh tokens, including JWT tokens, and checking their expiration and revocation status.
 * The class also handles the caching of validated tokens for improved performance.
 */
public class HybridPersistenceTokenProvider implements TokenProvider {

    private static final Log LOG = LogFactory.getLog(HybridPersistenceTokenProvider.class);
    private final DefaultTokenProvider defaultTokenProvider = new DefaultTokenProvider();
    private static final String ISS = "iss";
    private static final String AUD = "aud";
    private static final String DEFAULT_JWT_RT_HEADER_VALUE = "rt+jwt";

    /**
     * Retrieves and verifies JWT access token based on the JWT claims with an option to include expired tokens
     * as valid in the verification process.
     *
     * @param token          The access token JWT to retrieve and verify.
     * @param includeExpired A boolean flag indicating whether to include expired tokens in the verification.
     *                       Set to true to include expired tokens, false to exclude them.
     * @return The AccessTokenDO if the token is valid (ACTIVE or, optionally, EXPIRED), or null if the token
     * is not found either in ACTIVE or EXPIRED states when includeExpired is true. The method should throw
     * IllegalArgumentException if the access token is in an inactive or invalid state (e.g., 'REVOKED')
     * when includeExpired is false.
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    @Override
    public AccessTokenDO getVerifiedAccessToken(String token, boolean includeExpired) throws IdentityOAuth2Exception {

        return getVerifiedAccessToken(token, includeExpired, true);

    }

    /**
     * Retrieves and verifies an access token based on the provided access token data object,
     * with an option to include expired tokens in the verification process.
     *
     * @param token                     The access token data object to retrieve and verify.
     * @param includeExpired            A boolean flag indicating whether to include expired tokens in the verification.
     *                                  Set to true to include expired tokens, false to exclude them.
     * @param checkIndirectRevocation   A boolean flag indicating whether to check for indirect revocation.
     * @return The AccessTokenDO if the token is valid (ACTIVE or, optionally, EXPIRED), or null if the token
     * is not found either in ACTIVE or EXPIRED states when includeExpired is true. The method should throw
     * IllegalArgumentException if the access token is in an inactive or invalid state (e.g., 'REVOKED' or 'INVALID')
     * when includeExpired is false.
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    @Override
    public AccessTokenDO getVerifiedAccessToken(String token, boolean includeExpired,
                                                boolean checkIndirectRevocation) throws IdentityOAuth2Exception {

        // check if token is JWT.
        if (!JWTUtils.isJWT(token)) {
            // assume this is a migrated access token, validate and get the token from the database in the old way.
            return getPersistedAccessToken(token, includeExpired);
        }
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        // get JTI of the token.
        String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        /*
         * No need to validate the consumer key in the token with the consumer key in the verification request, as
         * it is done by the calling functions. eg: OAuth2Service.revokeTokenByOAuthClient().
         */
        String consumerKey = (String) claimsSet.getClaim(NonPersistenceConstants.AUTHORIZATION_PARTY);
        if (claimsSet.getClaim(NonPersistenceConstants.ENTITY_ID) == null) {
            return getPersistedAccessToken(accessTokenIdentifier, includeExpired);
        }
        AccessTokenDO validationDataDO;
        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                LOG.debug(String.format("Validating JWT access token: %s with expiry: %s", includeExpired,
                        DigestUtils.sha256Hex(accessTokenIdentifier)));
            } else {
                LOG.debug(String.format("Validating JWT access token with expiry: %s", includeExpired));
            }
        }
        AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
        // validate JWT token signature.
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet, authenticatedUser);
        // expiry time verification.
        boolean isTokenActive = true;
        if (!JWTUtils.checkExpirationTime(claimsSet.getExpirationTime())) {
            if (!includeExpired) {
                // this means the token is not active, so we can't proceed further.
                handleInvalidAccessTokenError(accessTokenIdentifier);
            }
            isTokenActive = false;
        }
        // not before time verification.
        JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());

        if (checkIndirectRevocation) {
            /*
             * check whether the token is already revoked through direct revocations and through following indirect
             * revocation events.
             * 1. check if consumer app was changed.
             * 2. check if user was changed.
             */
            if (TokenMgtUtil.isTokenRevokedDirectly(accessTokenIdentifier, consumerKey)
                    || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, authenticatedUser)) {
                if (!includeExpired) {
                    handleInvalidAccessTokenError(accessTokenIdentifier);
                }
                return null; // even if the token is invalid/revoked, we return null if includeExpired is true.
            }
        }
        Optional<AccessTokenDO> accessTokenDO = TokenMgtUtil.getTokenDOFromCache(accessTokenIdentifier);
        if (accessTokenDO.isPresent()) {
            validationDataDO = accessTokenDO.get();
            if (LOG.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    LOG.debug(String.format("Retrieved access token(hashed): %s from OAuthCache to verify.",
                            DigestUtils.sha256Hex(validationDataDO.getAccessToken())));
                } else {
                    LOG.debug("Retrieved access token from cache to verify.");
                }
            }
        } else {
            // create new AccessTokenDO with validated token information.
            validationDataDO = new AccessTokenDO();
            validationDataDO.setAccessToken(accessTokenIdentifier);
            validationDataDO.setConsumerKey(consumerKey);
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            Object scopes = claimsSet.getClaim(NonPersistenceConstants.SCOPE);
            validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
            validationDataDO.setAuthzUser(authenticatedUser);
            validationDataDO.setNotPersisted(true);
            Object autObj = claimsSet.getClaim(OAuthConstants.AUTHORIZED_USER_TYPE);
            if (autObj != null) {
                String aut = autObj.toString();
                validationDataDO.setTokenType(aut);
            } else {
                // Handle missing claim case
                LOG.debug("Aut type claim is missing in the non persistent access token.");
            }
            Object grantTypeObj = claimsSet.getClaim(NonPersistenceConstants.GRANT_TYPE);
            if (grantTypeObj != null) {
                String grantType = grantTypeObj.toString();
                validationDataDO.setGrantType(grantType);
                // Use grantType here
            } else {
                // Handle missing claim case
                LOG.debug("Grant type claim is missing in the non persistent access token.");
            }
            Object consentedTokenObj = claimsSet.getClaim(OAuth2Constants.IS_CONSENTED);
            if (consentedTokenObj != null) {
                boolean consentedToken = Boolean.parseBoolean(consentedTokenObj.toString());
                validationDataDO.setIsConsentedToken(consentedToken);
            } else {
                // Handle missing claim case
                validationDataDO.setIsConsentedToken(false);
                LOG.debug("Consented token claim is missing in the non persistent access token.");
            }
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            try {
                int tenantId = realmService.getTenantManager().getTenantId(authenticatedUser.getTenantDomain());
                validationDataDO.setTenantID(tenantId);
            } catch (UserStoreException e) {
                throw new IdentityOAuth2Exception("Error while getting tenant ID from tenant domain:"
                        + authenticatedUser.getTenantDomain(), e);
            }
            if (isTokenActive) {
                validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            validationDataDO.setTokenId(TokenMgtUtil.getTokenId(claimsSet));
        }
        return validationDataDO;
    }

    /**
     * Retrieves and verifies a refresh token.
     *
     * @param refreshToken The refresh token data object to retrieve and verify.
     * @param consumerKey  Consumer key
     * @return The RefreshTokenValidationDataDO if the token is available, or null otherwise.
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    @Override
    public RefreshTokenValidationDataDO getVerifiedRefreshToken(String refreshToken, String consumerKey)
            throws IdentityOAuth2Exception {

        if (!TokenMgtUtil.isHybridPersistedToken(refreshToken)) {
            if (JWTUtils.isJWT(refreshToken)) {
                LOG.debug("Refresh token is JWT, should be with non persistent access token. " +
                        "Hence, validating using hybrid persistent token provider.");
                return validateJWTRefreshToken(refreshToken, consumerKey);
            }
            LOG.debug("Refresh token is not with non-persistence access token. " +
                    "Hence, finding from persisted access token table from database.");

            return defaultTokenProvider.getVerifiedRefreshToken(refreshToken, consumerKey);
        }

        RefreshTokenDAOImpl refreshTokenDAO = new RefreshTokenDAOImpl();
        return refreshTokenDAO.validateRefreshToken(consumerKey, refreshToken);
    }

    private RefreshTokenValidationDataDO validateJWTRefreshToken(String token, String consumerKey)
            throws IdentityOAuth2Exception {

        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        if (!StringUtils.equals(DEFAULT_JWT_RT_HEADER_VALUE, signedJWT.getHeader().getType().getType())) {
            throw new IdentityOAuth2Exception("Invalid jwt refresh token provided for validation.");
        }
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        // get JTI of the token.
        String tokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        if (claimsSet.getClaim(NonPersistenceConstants.ENTITY_ID) == null) {
            throw new IdentityOAuth2Exception("Invalid jwt refresh token provided for validation.");
        }
        RefreshTokenValidationDataDO validationDataDO;
        AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
        // validate JWT token signature.
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet, authenticatedUser);
        // expiry time verification.
        boolean isTokenActive = JWTUtils.checkExpirationTime(claimsSet.getExpirationTime());
        // not before time verification.
        JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());
        validateAudienceClaim(claimsSet);

        /*
         * check whether the token is already revoked through direct revocations and through following indirect
         * revocation events.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        boolean isTokenRevoked = TokenMgtUtil.isTokenRevokedDirectly(tokenIdentifier, consumerKey)
                || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, authenticatedUser);

        // create new AccessTokenDO with validated token information.
        validationDataDO = new RefreshTokenValidationDataDO();
        validationDataDO.setRefreshToken(tokenIdentifier);
        validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
        validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                - claimsSet.getIssueTime().getTime());
        Object scopes = claimsSet.getClaim(OAuth2Constants.REFRESH_TOKEN_SCOPE_CLAIM_KEY);
        validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
        validationDataDO.setAuthorizedUser(authenticatedUser);
        validationDataDO.setWithNotPersistedAT(true);
        Object grantTypeObj = claimsSet.getClaim(NonPersistenceConstants.GRANT_TYPE);
        if (grantTypeObj != null) {
            String grantType = grantTypeObj.toString();
            validationDataDO.setGrantType(grantType);
            // Use grantType here
        } else {
            // Handle missing claim case
            LOG.debug("Grant type claim is missing in the non persistent access token.");
        }
        Object consentedTokenObj = claimsSet.getClaim(OAuth2Constants.IS_CONSENTED);
        if (consentedTokenObj != null) {
            boolean consentedToken = Boolean.parseBoolean(consentedTokenObj.toString());
            validationDataDO.setConsented(consentedToken);
        } else {
            // Handle missing claim case
            validationDataDO.setConsented(false);
            LOG.debug("Consented token claim is missing in the non persistent access token.");
        }

        String state;
        if (isTokenRevoked) {
            state = OAuthConstants.TokenStates.TOKEN_STATE_REVOKED;
        } else if (isTokenActive) {
            state = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        } else {
            state = OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED;
        }

        validationDataDO.setRefreshTokenState(state);
        validationDataDO.setTokenId(TokenMgtUtil.getTokenId(claimsSet));
        validationDataDO.setTokenBindingReference(OAuthConstants.TokenBindings.NONE);

        return validationDataDO;

    }

    private void validateAudienceClaim(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String issuer = (String) claimsSet.getClaim(ISS);
        Object audClaim = claimsSet.getClaim(AUD);

        if (StringUtils.isBlank(issuer) || audClaim == null) {
            throw new IdentityOAuth2Exception("Invalid jwt refresh token provided for validation.");
        }

        boolean issuerInAud = false;

        if (audClaim instanceof String) {
            issuerInAud = StringUtils.equals(issuer, (String) audClaim);
        } else if (audClaim instanceof List<?>) {
            List<?> audList = (List<?>) audClaim;
            issuerInAud = audList.stream()
                    .filter(Objects::nonNull)
                    .anyMatch(a -> issuer.equals(a.toString()));
        }

        if (!issuerInAud) {
            throw new IdentityOAuth2Exception("Invalid jwt refresh token provided for validation.");
        }

    }

    /**
     * Validates the refresh token to check whether it is active and returns the validation data in an AccessTokenDO.
     *
     * @param refreshToken The refresh token to validate
     * @return The AccessTokenDO if the token is valid (ACTIVE), or null if the token is not found in active state
     * @throws IdentityOAuth2Exception If there is an error during the refresh token validation process.
     */
    @Override
    public AccessTokenDO getVerifiedRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        if (!TokenMgtUtil.isHybridPersistedToken(refreshToken)) {
            if (JWTUtils.isJWT(refreshToken)) {
                LOG.debug("Refresh token is JWT, should be with non persistent access token. " +
                        "Hence, validating using hybrid persistent token provider.");
                return validateJWTRefreshToken(refreshToken);
            }
            LOG.debug("Refresh token is not with non-persistence access token. " +
                    "Hence, finding from persisted access token table from database.");
            return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO().getRefreshToken(refreshToken);
        }

        RefreshTokenDAOImpl refreshTokenDAO = new RefreshTokenDAOImpl();
        return refreshTokenDAO.getRefreshToken(refreshToken);
    }

    private AccessTokenDO validateJWTRefreshToken(String token)  throws IdentityOAuth2Exception {

        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        if (!StringUtils.equals(DEFAULT_JWT_RT_HEADER_VALUE, signedJWT.getHeader().getType().getType())) {
            throw new IdentityOAuth2Exception("Invalid jwt refresh token provided for validation.");
        }
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        // get JTI of the token.
        String tokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        String consumerKey = (String) claimsSet.getClaim(NonPersistenceConstants.AUTHORIZATION_PARTY);
        if (claimsSet.getClaim(NonPersistenceConstants.ENTITY_ID) == null) {
            throw new IdentityOAuth2Exception("Invalid jwt refresh token provided for validation.");
        }
        AccessTokenDO validationDataDO;
        AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
        // validate JWT token signature.
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet, authenticatedUser);
        // expiry time verification.
        boolean isTokenActive = JWTUtils.checkExpirationTime(claimsSet.getExpirationTime());
        // not before time verification.
        JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());
        validateAudienceClaim(claimsSet);

        /*
         * check whether the token is already revoked through direct revocations and through following indirect
         * revocation events.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (TokenMgtUtil.isTokenRevokedDirectly(tokenIdentifier, consumerKey)
                || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, authenticatedUser)) {
            return null;
        }

        // create new AccessTokenDO with validated token information.
        validationDataDO = new AccessTokenDO();
        validationDataDO.setRefreshToken(tokenIdentifier);
        validationDataDO.setConsumerKey(consumerKey);
        validationDataDO.setRefreshTokenIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
        validationDataDO.setRefreshTokenValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                - claimsSet.getIssueTime().getTime());
        Object scopes = claimsSet.getClaim(OAuth2Constants.REFRESH_TOKEN_SCOPE_CLAIM_KEY);
        validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
        validationDataDO.setAuthzUser(authenticatedUser);
        validationDataDO.setNotPersisted(true);
        Object autObj = claimsSet.getClaim(OAuthConstants.AUTHORIZED_USER_TYPE);
        if (autObj != null) {
            String aut = autObj.toString();
            validationDataDO.setTokenType(aut);
        } else {
            // Handle missing claim case
            LOG.debug("Aut type claim is missing in the non persistent access token.");
        }
        Object grantTypeObj = claimsSet.getClaim(NonPersistenceConstants.GRANT_TYPE);
        if (grantTypeObj != null) {
            String grantType = grantTypeObj.toString();
            validationDataDO.setGrantType(grantType);
            // Use grantType here
        } else {
            // Handle missing claim case
            LOG.debug("Grant type claim is missing in the non persistent access token.");
        }
        Object consentedTokenObj = claimsSet.getClaim(OAuth2Constants.IS_CONSENTED);
        if (consentedTokenObj != null) {
            boolean consentedToken = Boolean.parseBoolean(consentedTokenObj.toString());
            validationDataDO.setIsConsentedToken(consentedToken);
        } else {
            // Handle missing claim case
            validationDataDO.setIsConsentedToken(false);
            LOG.debug("Consented token claim is missing in the non persistent access token.");
        }
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        try {
            int tenantId = realmService.getTenantManager().getTenantId(authenticatedUser.getTenantDomain());
            validationDataDO.setTenantID(tenantId);
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error while getting tenant ID from tenant domain:"
                    + authenticatedUser.getTenantDomain(), e);
        }
        if (isTokenActive) {
            validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        } else {
            validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        }
        validationDataDO.setTokenId(TokenMgtUtil.getTokenId(claimsSet));
        return validationDataDO;
    }

    /**
     * Handles throwing of error when active or valid access token not found.
     *
     * @param tokenIdentifier Token Identifier (JTI) of the JWT
     */
    private void handleInvalidAccessTokenError(String tokenIdentifier) {

        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                LOG.debug(String.format("Failed to validate the JWT Access Token %s in memory.",
                        DigestUtils.sha256Hex(tokenIdentifier)));
            } else {
                LOG.debug("Failed to validate the JWT Access Token in memory.");
            }
        }
        throw new IllegalArgumentException(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);
    }

    /**
     * Retrieves and verifies a migrated access token based on the provided access token data object. A migrated access
     * token can be either an Opaque or a JWT with entity_id : null.
     *
     * @param accessTokenIdentifier Access token identifier (JTI in JWT case, token in Opaque case)
     * @param includeExpired        A boolean flag indicating whether to include expired tokens in the verification.
     * @return AccessTokenDO if the token is valid (ACTIVE or, optionally, EXPIRED), or null if the token is not found
     * or revoked
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    private AccessTokenDO getPersistedAccessToken(String accessTokenIdentifier, boolean includeExpired)
            throws IdentityOAuth2Exception {

        return defaultTokenProvider.getVerifiedAccessToken(accessTokenIdentifier, includeExpired);
    }
}
