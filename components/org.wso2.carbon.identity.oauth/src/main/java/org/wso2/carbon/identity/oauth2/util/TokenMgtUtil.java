/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.REFRESH_TOKEN_PREFIX;

/**
 * Util class for token management related activities.
 */
public class TokenMgtUtil {

    private static final Log LOG = LogFactory.getLog(TokenMgtUtil.class);

    /**
     * Check if the given refresh token is a non-persisted token.
     *
     * @param refreshToken Refresh Token
     * @return True if the refresh token is a non-persisted token.
     */
    public static boolean isHybridPersistedToken(String refreshToken) {

        return StringUtils.isNotBlank(refreshToken) && refreshToken.startsWith(REFRESH_TOKEN_PREFIX);
    }

    /**
     * Get token identifier (JTI) for JWT.
     *
     * @param claimsSet Claim Set
     * @return JTI
     * @throws IdentityOAuth2Exception if JTI claim is not present in the JWTClaimSet of the access token.
     */
    public static String getTokenIdentifier(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String jwtId = claimsSet.getJWTID();
        if (jwtId == null) {
            throw new IdentityOAuth2Exception("JTI could not be retrieved from the JWT token.");
        } else {
            return jwtId;
        }
    }

    /**
     * Parse JWT Token.
     *
     * @param accessToken Access Token
     * @return SignedJWT
     * @throws IdentityOAuth2Exception If an error occurs while parsing the JWT token
     */
    public static SignedJWT parseJWT(String accessToken) throws IdentityOAuth2Exception {

        try {
            return SignedJWT.parse(accessToken);
        } catch (ParseException e) {
            if (LOG.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    LOG.debug(String.format("Failed to parse the received token: %s", accessToken));
                } else {
                    LOG.debug("Failed to parse the received token.");
                }
            }
            throw new IdentityOAuth2Exception("Error while parsing token.", e);
        }
    }

    /**
     * Get JWT Claim sets for the given access token.
     *
     * @param signedJWT Signed JWT
     * @return JWT Claim sets
     * @throws IdentityOAuth2Exception If an error occurs while getting the JWT claim sets
     */
    public static JWTClaimsSet getTokenJWTClaims(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given token.");
            }
            return claimsSet;
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while retrieving claim set from token.", e);
        }
    }

    /**
     * Validate the JWT signature.
     *
     * @param signedJWT         Signed JWT
     * @param claimsSet         JWT claims set
     * @param authenticatedUser Authenticated user
     * @throws IdentityOAuth2Exception If signature verification fails or if an error occurs while
     *                                 validating the JWT signature.
     */
    public static void validateJWTSignature(SignedJWT signedJWT, JWTClaimsSet claimsSet,
                                            AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        try {
            String tenantDomain = getSigningTenantDomain(claimsSet, authenticatedUser);
            IdentityProvider idp = JWTUtils.getResidentIDPForIssuer(claimsSet, tenantDomain);
            // Get certificate from tenant if available in claims.
            X509Certificate x509Certificate = OAuth2Util.resolverSignerCertificate(idp);
            if (x509Certificate == null) {
                throw new IdentityOAuth2Exception("Unable to locate certificate for Identity Provider: "
                        + idp.getDisplayName());
            }
            String algorithm = JWTUtils.verifyAlgorithm(signedJWT);
            if (!JWTUtils.verifySignature(signedJWT, x509Certificate, algorithm)) {
                throw new IdentityOAuth2Exception(("Invalid signature."));
            }
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the organization hierarchy.", e);
        }
    }

    /**
     * Get Scope array from the scopes string object.
     *
     * @param scopes String object of scopes with delimiter space.
     * @return Array of scopes
     */
    public static String[] getScopes(Object scopes) {

        if (scopes instanceof String) {
            return ((String) scopes).split(" ");
        }
        return new String[0];
    }

    /**
     * Get authenticated user.
     *
     * @param claimsSet JWT claims set
     * @return AuthenticatedUser
     */
    public static AuthenticatedUser getAuthenticatedUser(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        String userTenantDomain = TokenMgtUtil.getTenantDomain();
        boolean isFederated = claimsSet.getClaim(OAuth2Constants.IS_FEDERATED) != null
                && (boolean) claimsSet.getClaim(OAuth2Constants.IS_FEDERATED);
        authenticatedUser = resolveAuthenticatedUserFromEntityId((String) claimsSet.getClaim(
                NonPersistenceConstants.ENTITY_ID), userTenantDomain, isFederated, claimsSet.getSubject(), claimsSet);
        if (isFederated) {
            if (authenticatedUser == null) {
                authenticatedUser =
                        createFederatedAuthenticatedUser((String)
                                claimsSet.getClaim(NonPersistenceConstants.ENTITY_ID));
            } else {
                authenticatedUser.setFederatedUser(true);
            }
        }
        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception("Error while getting authenticated user. Authenticated user not found.");
        }
        authenticatedUser.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
        return authenticatedUser;
    }

    /**
     * Create an authenticated user object for the given user ID from usersession store.
     *
     * @param userId User ID
     * @return AuthenticatedUser
     */
    public static AuthenticatedUser createFederatedAuthenticatedUser(String userId) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        try {
            authenticatedUser = UserSessionStore.getInstance().getUser(userId);
            if (authenticatedUser == null) {
                throw new IdentityOAuth2Exception("Error occurred while resolving the user from the userId for the "
                        + "federated user. No user found for the userId");
            }
            authenticatedUser.setUserName(authenticatedUser.getUserName());
            authenticatedUser.setTenantDomain(authenticatedUser.getTenantDomain());
            authenticatedUser.setUserStoreDomain(authenticatedUser.getUserStoreDomain());
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(authenticatedUser.getFederatedIdPName());
            authenticatedUser.setUserId(userId);
        } catch (UserSessionException e) {
            // In here we better not log the user id.
            throw new IdentityOAuth2Exception("Error occurred while resolving the user from the userId for the "
                    + "federated user", e);
        }
        return authenticatedUser;
    }

    /**
     * Get authenticated user from the entity ID.
     *
     * @param entityId                Entity ID JWT Claim value which uniquely identifies the
     *                                subject principle of the JWT. Eg: user
     * @param userTenantDomain        Tenant domain of the user from the token
     * @param isFederated             Federated user token
     * @param sub                     Subject claim
     * @param claimsSet               JWTClaimsSet of the parsed token.
     * @return Username
     * @throws IdentityOAuth2Exception If an error occurs while getting the authenticated user
     */
    private static AuthenticatedUser resolveAuthenticatedUserFromEntityId(String entityId,
                                                                          String userTenantDomain,
                                                                          boolean isFederated,
                                                                          String sub,
                                                                          JWTClaimsSet claimsSet)
            throws IdentityOAuth2Exception {

        if (StringUtils.isBlank(entityId)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entity ID is null or empty. Cannot resolve authenticated user.");
            }
            throw new IdentityOAuth2Exception("Entity ID is required to resolve the authenticated user.");
        }

        String entityIdType = (String) claimsSet.getClaim(NonPersistenceConstants.ENTITY_TYPE);
        AuthenticatedUser authenticatedUser = null;

        switch (entityIdType) {
            case NonPersistenceConstants.ENTITY_ID_TYPE_CLIENT_ID:
                try {
                    OAuthAppDO consumerApp = OAuth2Util.getAppInformationByClientId(entityId);
                    authenticatedUser = consumerApp.getAppOwner();
                    return authenticatedUser;
                } catch (InvalidOAuthClientException e) {
                    throw new IdentityOAuth2Exception("Failed to retrieve OAuth application for client ID: "
                            + entityId, e);
                }

            case NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME:
                authenticatedUser = OAuth2Util.getUserFromUserName(entityId);
                return authenticatedUser;

            case NonPersistenceConstants.ENTITY_ID_TYPE_USER_ID:
                try {
                    String userName = getUserNameFromUserID(entityId, userTenantDomain);
                    if (StringUtils.isNotBlank(userName)) {
                        authenticatedUser = OAuth2Util.getUserFromUserName(userName);
                        authenticatedUser.setTenantDomain(userTenantDomain);
                    } else if (!isFederated && StringUtils.isNotBlank(sub)) {
                        // If not federated, fallback to subject (assumed to be full qualified username).
                        authenticatedUser = OAuth2Util.getUserFromUserName(sub);
                    }

                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Failed to resolve username from user ID: " + entityId, e);
                }
                break;

            default:
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unsupported entity ID type received in claims: " + entityIdType);
                }
                break;
        }

        return authenticatedUser;
    }


    private static String getUserNameFromUserID(String userId, String tenantDomain) throws UserStoreException {

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) realmService
                .getTenantUserRealm(tenantId).getUserStoreManager();
        return userStoreManager.getUserNameFromUserID(userId);
    }

    /**
     * Get tenant domain from thread local carbon context.
     *
     * @return Tenant domain
     */
    public static String getTenantDomain() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * Check if token is in-directly revoked through a user related or client application related change action.
     *
     * @param claimsSet         JWTClaimsSet of the parsed token.
     * @param authenticatedUser Authenticated User
     * @return True if token is in-directly revoked.
     * @throws IdentityOAuth2Exception If failed to check is token is in-directly revoked.
     */
    public static boolean isTokenRevokedIndirectly(JWTClaimsSet claimsSet, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        Date tokenIssuedTime = claimsSet.getIssueTime();
        String entityId = (String) claimsSet.getClaim(NonPersistenceConstants.ENTITY_ID);
        String consumerKey = (String) claimsSet.getClaim(NonPersistenceConstants.AUTHORIZATION_PARTY);
        boolean isRevoked =  OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                    .isTokenRevokedForSubjectEntity(consumerKey, tokenIssuedTime);
        if (!StringUtils.equals(consumerKey, entityId) && !isRevoked) {
            isRevoked = OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                    .isTokenRevokedForSubjectEntity(entityId, tokenIssuedTime);
        }

        if (isRevoked) {
            if (authenticatedUser != null) {
                String[] scopes = getScopes(claimsSet.getClaim(NonPersistenceConstants.SCOPE));
                // if revoked, remove the token information from oauth cache.
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser,
                        OAuth2Util.buildScopeString(scopes), OAuthConstants.TokenBindings.NONE);
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser,
                        OAuth2Util.buildScopeString(scopes));
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser);
            }
            String accessTokenIdentifier = getTokenIdentifier(claimsSet);
            OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
            OAuthCache.getInstance().clearCacheEntry(cacheKey);
        }
        return isRevoked;
    }

    /**
     * Check if token is directly revoked by calling revoked token endpoint. This seamlessly validates current
     * tokens and not migrated tokens.
     *
     * @param tokenIdentifier Token Identifier
     * @param consumerKey     Consumer Key
     * @return True if token is directly revoked
     * @throws IdentityOAuth2Exception If failed to check is token is directly revoked
     */
    public static boolean isTokenRevokedDirectly(String tokenIdentifier, String consumerKey)
            throws IdentityOAuth2Exception {

        /*
         * Clearing of cache is already handled when direct revocation happens through oauth2 revocation service.
         * Hence, no need of clearing cache.
         */
        return OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                .isRevokedToken(tokenIdentifier, consumerKey);
    }

    /**
     * Get AccessTokenDO from cache.
     *
     * @param accessTokenIdentifier Identifier
     * @return Optional AccessTokenDO
     */
    public static Optional<AccessTokenDO> getTokenDOFromCache(String accessTokenIdentifier) {

        AccessTokenDO accessTokenDO = null;
        if (OAuthCache.getInstance().isEnabled()) {
            CacheEntry result = OAuthCache.getInstance().getValueFromCache(getOAuthCacheKey(accessTokenIdentifier));
            // cache hit, do the type check.
            if (result instanceof AccessTokenDO) {
                accessTokenDO = (AccessTokenDO) result;
                if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(
                        IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    LOG.debug(String.format("Hit OAuthCache for accessTokenIdentifier: %s", accessTokenIdentifier));
                } else {
                    LOG.debug("Hit OAuthCache with accessTokenIdentifier");
                }
            }
        }
        return Optional.ofNullable(accessTokenDO);
    }

    /**
     * Adds an access token and its associated information to the OAuth cache for efficient retrieval.
     *
     * @param accessTokenIdentifier The identifier of the access token to be cached.
     * @param accessTokenDO         The AccessTokenDO (Access Token Data Object) containing information about the
     *                              access token.
     */
    public static void addTokenToCache(String accessTokenIdentifier, AccessTokenDO accessTokenDO) {

        if (OAuthCache.getInstance().isEnabled()) {
            OAuthCache.getInstance().addToCache(getOAuthCacheKey(accessTokenIdentifier), accessTokenDO);
            if (LOG.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    LOG.debug(String.format("Access token(hashed): %s added to OAuthCache.",
                            DigestUtils.sha256Hex(accessTokenIdentifier)));
                } else {
                    LOG.debug("Access token added to OAuthCache.");
                }
            }
        }
    }

    /**
     * Get OAuth cache key for access token identifier.
     *
     * @param accessTokenIdentifier Access token ID
     * @return OAuth Cache Key
     */
    public static OAuthCacheKey getOAuthCacheKey(String accessTokenIdentifier) {

        return new OAuthCacheKey(accessTokenIdentifier);
    }

    /**
     * Get token id from the JWT token. This tokenId is the unique identifier of the logged-in session.
     *
     * @param claimsSet JWTClaimsSet of the parsed token.
     * @return Token Id
     * @throws IdentityOAuth2Exception If failed to get the token id.
     */
    public static String getTokenId(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String tokenId = claimsSet.getClaim(OAuth2Constants.TOKEN_ID) != null ?
                claimsSet.getClaim(OAuth2Constants.TOKEN_ID).toString() : null;
        if (tokenId == null) {
            throw new IdentityOAuth2Exception("TokenId could not be retrieved from the JWT token.");
        } else {
            return tokenId;
        }
    }

    /**
     * Retrieves the signing tenant domain from the given JWT claims set and AccessTokenDO, considering
     * various sources
     * such as the 'realm' claim, the 'signing_tenant' claim, and the OAuth application associated with the
     * AccessToken.
     *
     * @param claimsSet         The JWTClaimsSet containing the claims of the JWT, including the 'realm' claim.
     * @param authenticatedUser Authenticated user.
     * @return The signing tenant domain based on the provided claims and AccessTokenDO.
     * @throws IdentityOAuth2Exception If an error occurs in OAuth2-related functionality.
     */
    public static String getSigningTenantDomain(JWTClaimsSet claimsSet, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        String consumerKey = (String) claimsSet.getClaim(NonPersistenceConstants.AUTHORIZATION_PARTY);
        if (consumerKey == null) {
            return getTenantDomain();
        }
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        if (isJWTSignedWithSPKey) {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Getting signing tenant domain from OAuth app.");
                }
                return OAuth2Util.getTenantDomainOfOauthApp(consumerKey);
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while getting tenant domain from OAuth app with consumer key: "
                        + consumerKey);
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Getting signing tenant domain from authenticated user.");
            }
            return authenticatedUser.getTenantDomain();
        }
    }

    /**
     * Check if the given token is a non-persistence access token.
     *
     * @param token Access Token
     * @return True if the token is a non-persistence access token.
     */
    public static boolean isNonPersistenceAccessToken(String token) {

        if (JWTUtils.isJWT(token)) {
            try {
                SignedJWT signedJWT = parseJWT(token);
                JWTClaimsSet claimsSet = getTokenJWTClaims(signedJWT);
                return claimsSet.getClaim(NonPersistenceConstants.ENTITY_ID) != null;
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while parsing the JWT token.", e);
            }
        }
        return false;
    }

    /**
     * Get the token ID from a non-persistence access token.
     *
     * @param accessToken Non-persistence access token
     * @return Token ID or null if not found
     * @throws IdentityOAuth2Exception If an error occurs while parsing the JWT token
     */
    public static String getTokenIDFromNonPersistenceAccessToken(String accessToken) throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJWT = parseJWT(accessToken);
            JWTClaimsSet claimsSet = getTokenJWTClaims(signedJWT);
            return (String) claimsSet.getClaim(OAuth2Constants.TOKEN_ID);
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while parsing the JWT token.", e);
            return null;
        }
    }
}
