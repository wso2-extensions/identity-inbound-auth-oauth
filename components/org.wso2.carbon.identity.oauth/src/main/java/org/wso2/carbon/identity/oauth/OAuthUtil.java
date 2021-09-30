/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth;

import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.CURRENT_SESSION_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.Config.PRESERVE_LOGGED_IN_SESSION_AT_PASSWORD_UPDATE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * OAuth utility functionality.
 */
public final class OAuthUtil {

    public static final Log LOG = LogFactory.getLog(OAuthUtil.class);
    private static final String ALGORITHM = "HmacSHA1";

    private OAuthUtil() {

    }

    /**
     * Generates a random number using two UUIDs and HMAC-SHA1
     *
     * @return generated secure random number
     * @throws IdentityOAuthAdminException Invalid Algorithm or Invalid Key
     */
    public static String getRandomNumber() throws IdentityOAuthAdminException {
        try {
            String secretKey = UUIDGenerator.generateUUID();
            String baseString = UUIDGenerator.generateUUID();

            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(Charsets.UTF_8), ALGORITHM);
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(baseString.getBytes(Charsets.UTF_8));
            String random = Base64.encode(rawHmac);
            // Registry doesn't have support for these character.
            random = random.replace("/", "_");
            random = random.replace("=", "a");
            random = random.replace("+", "f");
            return random;
        } catch (Exception e) {
            throw new IdentityOAuthAdminException("Error when generating a random number.", e);
        }
    }

    /**
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser)} instead.
     * @param consumerKey
     * @param authorizedUser
     */
    @Deprecated
    public static void clearOAuthCache(String consumerKey, User authorizedUser) {

        if (authorizedUser instanceof AuthenticatedUser) {
            clearOAuthCache(consumerKey, (AuthenticatedUser) authorizedUser);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User object is not an instance of AuthenticatedUser therefore cannot resolve " +
                        "authenticatedIDP name.");
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
            String userId;
            try {
                userId = authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                LOG.error("User id cannot be found for user: " + authenticatedUser.getLoggableUserId());
                return;
            }
            clearOAuthCache(consumerKey, userId);
            clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, null);
        }
    }

    /**
     * Clear OAuth cache based on the application and authorized user.
     *
     * @param consumerKey       Client id of the application the token issued to.
     * @param authorizedUser    authorized user.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser) {

        String authenticatedIDP = authorizedUser.getFederatedIdPName();
        String userId;
        try {
            userId = authorizedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableUserId());
            return;
        }
        clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, authenticatedIDP);
    }

    /**
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser, String)} instead.
     * @param consumerKey
     * @param authorizedUser
     * @param scope
     */
    @Deprecated
    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope) {

        String authenticatedIDP;
        if (authorizedUser instanceof AuthenticatedUser) {
            clearOAuthCache(consumerKey, (AuthenticatedUser) authorizedUser, scope);
        } else {
            authenticatedIDP = null;
            if (LOG.isDebugEnabled()) {
                LOG.debug("User object is not an instance of AuthenticatedUser therefore cannot resolve " +
                        "authenticatedIDP name.");
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
            String userId;
            try {
                userId = authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                LOG.error("User id cannot be found for user: " + authenticatedUser.getLoggableUserId());
                return;
            }
            clearOAuthCache(consumerKey, userId, scope);
            clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, scope, authenticatedIDP);
        }
    }

    /**
     * Clear OAuth cache based on the application, authorized user and scope list.
     *
     * @param consumerKey       Client id of the application the token issued to.
     * @param authorizedUser    authorized user.
     * @param scope             scope string.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser, String scope) {

        String authenticatedIDP = authorizedUser.getFederatedIdPName();

        String userId;
        try {
            userId = authorizedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableUserId());
            return;
        }
        clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, scope, authenticatedIDP);
    }

    /**
     * Clear OAuth cache.
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser, String, String)} instead.
     *
     * @param consumerKey consumer key.
     * @param authorizedUser authorized user.
     * @param scope scope.
     * @param tokenBindingReference token binding reference.
     */
    @Deprecated
    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope,
            String tokenBindingReference) {

        if (authorizedUser instanceof AuthenticatedUser) {
            clearOAuthCache(consumerKey, (AuthenticatedUser) authorizedUser, scope, tokenBindingReference);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User is not an instance of AuthenticatedUser therefore cannot resolve authenticatedIDP "
                        + "name");
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
            String userId;
            try {
                userId = authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                LOG.error("User id cannot be found for user: " + authenticatedUser.getLoggableUserId());
                return;
            }
            clearOAuthCache(consumerKey, userId, scope);
            clearOAuthCache(buildCacheKeyStringForToken(consumerKey, scope, userId, null,
                    tokenBindingReference));
        }
    }

    /**
     * Clear OAuth cache based on the application, authorized user, scope list and token binding reference.
     *
     * @param consumerKey           Client id of the application the token issued to.
     * @param authorizedUser        Authorized user.
     * @param scope                 Scope list.
     * @param tokenBindingReference Token binding reference.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser, String scope,
                                       String tokenBindingReference) {

        String authenticatedIDP = authorizedUser.getFederatedIdPName();

        String userId;
        try {
            userId = authorizedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableUserId());
            return;
        }
        clearOAuthCache(buildCacheKeyStringForToken(consumerKey, scope, userId,
                authenticatedIDP, tokenBindingReference));
    }

    private static void clearOAuthCache(String consumerKey, String authorizedUserId) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey      Consumer key.
     * @param authorizedUserId   Authorized user.
     * @param authenticatedIDP Authenticated IdP.
     */
    private static void clearOAuthCacheWithAuthenticatedIDP(String consumerKey, String authorizedUserId,
                                                            String authenticatedIDP) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId + ":" + authenticatedIDP);
    }

    private static void clearOAuthCache(String consumerKey, String authorizedUserId, String scope) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId + ":" + scope);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey      Consumer key.
     * @param authorizedUserId   Authorized user.
     * @param scope            Scopes.
     * @param authenticatedIDP Authenticated IdP.
     */
    private static void clearOAuthCacheWithAuthenticatedIDP(String consumerKey, String authorizedUserId, String scope,
                                                           String authenticatedIDP) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId + ":" + scope + ":" + authenticatedIDP);
    }

    /**
     * Build the cache key string when storing token info in cache.
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser, String, String)} instead.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUserId   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @param tokenBindingReference Token binding reference.
     * @return Cache key string combining the input parameters.
     */
    @Deprecated
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUserId,
            String authenticatedIDP, String tokenBindingReference) {

        return clientId + ":" + authorizedUserId + ":" + scope + ":" + authenticatedIDP + ":" + tokenBindingReference;
    }

    public static void clearOAuthCache(String oauthCacheKey) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Clearing cache for cache key: " + oauthCacheKey);
        }

        OAuthCacheKey cacheKey = new OAuthCacheKey(oauthCacheKey);
        OAuthCache.getInstance().clearCacheEntry(cacheKey);
    }

    public static void clearOAuthCache(AccessTokenDO accessTokenDO) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Clearing cache for access token as cache key of user: " +
                    accessTokenDO.getAuthzUser().getLoggableUserId());
        }
        OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenDO.getAccessToken());
        String tenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();
        OAuthCache.getInstance().clearCacheEntry(cacheKey,  tenantDomain);
    }

    public static AuthenticatedUser getAuthenticatedUser(String fullyQualifiedUserName) {

        if (StringUtils.isBlank(fullyQualifiedUserName)) {
            throw new RuntimeException("Invalid username.");
        }

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(IdentityUtil.extractDomainFromName(fullyQualifiedUserName));
        authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(fullyQualifiedUserName));

        String username = fullyQualifiedUserName;
        if (fullyQualifiedUserName.startsWith(authenticatedUser.getUserStoreDomain())) {
            username = UserCoreUtil.removeDomainFromName(fullyQualifiedUserName);
        }
        authenticatedUser.setUserName(MultitenantUtils.getTenantAwareUsername(username));

        return authenticatedUser;
    }

    /**
     * This is used to handle the OAuthAdminService exceptions. This will log the error message and return an
     * IdentityOAuthAdminException exception
     * @param message error message
     * @param exception Exception.
     * @return
     */
    public static IdentityOAuthAdminException handleError(String message, Exception exception) {

        if (exception == null) {
            return new IdentityOAuthAdminException(message);
        } else {
            String errorCode = Error.UNEXPECTED_SERVER_ERROR.getErrorCode();
            return new IdentityOAuthAdminException(errorCode, message, exception);
        }
    }

    /**
     * This is used to handle the OAuthAdminService exceptions depends on the exception type, there can be client
     * exception and server exception.This will log the error message and
     * return an IdentityOAuthClientException/IdentityOAuthServerException/IdentityOAuthAdminException exception
     * depends on the IdentityOAuth2Exception exception type.
     *
     * @param message   Error message.
     * @param exception Exception.
     * @return
     */
    public static IdentityOAuthAdminException handleErrorWithExceptionType(String message,
                                                                           IdentityOAuth2Exception exception) {

        if (exception == null) {
            return new IdentityOAuthAdminException(message);
        }
        if (StringUtils.isBlank(exception.getErrorCode())) {
            handleError(message, exception);
        }
        if (exception instanceof IdentityOAuth2ClientException) {
            return new IdentityOAuthClientException(exception.getErrorCode(), message, exception);
        } else if (exception instanceof IdentityOAuth2ServerException) {
            return new IdentityOAuthServerException(exception.getErrorCode(), message, exception);
        } else {
            return new IdentityOAuthAdminException(exception.getErrorCode(), message, exception);
        }
    }

    /**
     * Get created oauth application details.
     *
     * @param appDO <code>OAuthAppDO</code> with created application information.
     * @return OAuthConsumerAppDTO Created OAuth application details.
     */
    public static OAuthConsumerAppDTO buildConsumerAppDTO(OAuthAppDO appDO) {

        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        dto.setApplicationName(appDO.getApplicationName());
        dto.setCallbackUrl(appDO.getCallbackUrl());
        dto.setOauthConsumerKey(appDO.getOauthConsumerKey());
        dto.setOauthConsumerSecret(appDO.getOauthConsumerSecret());
        dto.setOAuthVersion(appDO.getOauthVersion());
        dto.setGrantTypes(appDO.getGrantTypes());
        dto.setScopeValidators(appDO.getScopeValidators());
        dto.setUsername(appDO.getUser().toFullQualifiedUsername());
        dto.setState(appDO.getState());
        dto.setPkceMandatory(appDO.isPkceMandatory());
        dto.setPkceSupportPlain(appDO.isPkceSupportPlain());
        dto.setUserAccessTokenExpiryTime(appDO.getUserAccessTokenExpiryTime());
        dto.setApplicationAccessTokenExpiryTime(appDO.getApplicationAccessTokenExpiryTime());
        dto.setRefreshTokenExpiryTime(appDO.getRefreshTokenExpiryTime());
        dto.setIdTokenExpiryTime(appDO.getIdTokenExpiryTime());
        dto.setAudiences(appDO.getAudiences());
        dto.setRequestObjectSignatureValidationEnabled(appDO.isRequestObjectSignatureValidationEnabled());
        dto.setIdTokenEncryptionEnabled(appDO.isIdTokenEncryptionEnabled());
        dto.setIdTokenEncryptionAlgorithm(appDO.getIdTokenEncryptionAlgorithm());
        dto.setIdTokenEncryptionMethod(appDO.getIdTokenEncryptionMethod());
        dto.setBackChannelLogoutUrl(appDO.getBackChannelLogoutUrl());
        dto.setFrontchannelLogoutUrl(appDO.getFrontchannelLogoutUrl());
        dto.setTokenType(appDO.getTokenType());
        dto.setBypassClientCredentials(appDO.isBypassClientCredentials());
        dto.setRenewRefreshTokenEnabled(appDO.getRenewRefreshTokenEnabled());
        dto.setTokenBindingType(appDO.getTokenBindingType());
        dto.setTokenRevocationWithIDPSessionTerminationEnabled(appDO
                .isTokenRevocationWithIDPSessionTerminationEnabled());
        dto.setTokenBindingValidationEnabled(appDO.isTokenBindingValidationEnabled());
        return dto;
    }

    /**
     * This will be called after when Tokens Revoked through Listeners directly.
     *
     * @param accessTokenDO {@link AccessTokenDO}
     */
    public static void invokePostRevocationBySystemListeners(AccessTokenDO accessTokenDO, Map<String, Object> params) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPostTokenRevocationBySystem(accessTokenDO, params);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while triggering listener for post token revocation by system.", e);
            }
        }
    }

    /**
     * This will be called before when Tokens Revoked through Listeners directly.
     *
     * @param accessTokenDO {@link AccessTokenDO}
     */
    public static void invokePreRevocationBySystemListeners(AccessTokenDO accessTokenDO, Map<String, Object> params) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPreTokenRevocationBySystem(accessTokenDO, params);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while triggering listener for pre token revocation by system.", e);
            }
        }
    }

    /**
     * Remove user claims from ClaimCache
     *
     * @param userName
     */
    public static boolean removeUserClaimsFromCache(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        ClaimCache claimCache = ClaimCache.getInstance();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(userName);
        authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
        authenticatedUser.setUserStoreDomain(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()));
        ClaimCacheKey cacheKey = new ClaimCacheKey(authenticatedUser);
        if (cacheKey != null) {
            claimCache.clearCacheEntry(cacheKey, userStoreManager.getTenantId());
        }
        return true;
    }

    /**
     * This method will revoke the accesstokens of user.
     * @param username username.
     * @param userStoreManager userStoreManager.
     * @return true if revocation is successfull. Else return false
     * @throws UserStoreException
     */
    public static boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);

        /* This userStoreDomain variable is used for access token table partitioning. So it is set to null when access
        token table partitioning is not enabled.*/
        userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error occurred while getting user store domain for User ID : " + authenticatedUser, e);
                throw new UserStoreException(e);
            }
        }

        Set<String> clientIds;
        try {
            // get all the distinct client Ids authorized by this user
            clientIds = OAuthTokenPersistenceFactory.getInstance()
                    .getTokenManagementDAO().getAllTimeAuthorizedClientIds(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error occurred while retrieving apps authorized by User ID : " + authenticatedUser, e);
            throw new UserStoreException(e);
        }
        for (String clientId : clientIds) {
            Set<AccessTokenDO> accessTokenDOs;
            try {
                // retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                accessTokenDOs = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getAccessTokens(clientId, authenticatedUser, userStoreDomain, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while retrieving access tokens issued for " +
                        "Client ID : " + clientId + ", User ID : " + authenticatedUser;
                LOG.error(errorMsg, e);
                throw new UserStoreException(e);
            }

            boolean isTokenPreservingAtPasswordUpdateEnabled =
                    Boolean.parseBoolean(IdentityUtil.getProperty(PRESERVE_LOGGED_IN_SESSION_AT_PASSWORD_UPDATE));
            String currentTokenBindingReference = "";
            if (isTokenPreservingAtPasswordUpdateEnabled) {
                if (IdentityUtil.threadLocalProperties.get().get(CURRENT_SESSION_IDENTIFIER) != null) {
                    currentTokenBindingReference =
                            (String) IdentityUtil.threadLocalProperties.get().get(CURRENT_SESSION_IDENTIFIER);
                }
            }

            Set<String> scopes = new HashSet<>();
            List<AccessTokenDO> accessTokens = new ArrayList<>();
            boolean tokenBindingEnabled = false;
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                // Clear cache
                String tokenBindingReference = NONE;
                if (accessTokenDO.getTokenBinding() != null && StringUtils
                        .isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
                    tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
                    tokenBindingEnabled = true;
                    // Skip current token from being revoked.
                    if (StringUtils.equals(accessTokenDO.getTokenBinding().getBindingValue(),
                            currentTokenBindingReference)) {
                        continue;
                    }
                }
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                OAuthUtil.clearOAuthCache(accessTokenDO);
                // Get unique scopes list
                scopes.add(OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                accessTokens.add(accessTokenDO);
            }

            if (!tokenBindingEnabled && OAuth2Util.isHashDisabled()) {
                return revokeLatestTokensWithScopes(scopes, clientId, authenticatedUser);
            } else {
                // If the hashed token is enabled, there can be multiple active tokens with a user with same scope.
                // Also, if token binding is enabled, there can be multiple active tokens for the same user, scope
                // and client combination.
                // So need to revoke all the tokens.
                try {
                    return revokeTokens(accessTokens);
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking Access Token";
                    LOG.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
        return true;
    }

    private static boolean revokeTokens(List<AccessTokenDO> accessTokens) throws IdentityOAuth2Exception {

        if (!accessTokens.isEmpty()) {
            // Revoking token from database.
            for (AccessTokenDO accessToken : accessTokens) {
                OAuthUtil.invokePreRevocationBySystemListeners(accessToken, Collections.emptyMap());
                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .revokeAccessTokens(new String[]{accessToken.getAccessToken()}, OAuth2Util.isHashEnabled());
                OAuthUtil.invokePostRevocationBySystemListeners(accessToken, Collections.emptyMap());
            }
        }
        return true;
    }

    private static boolean revokeLatestTokensWithScopes(Set<String> scopes, String clientId,
                                                        AuthenticatedUser authenticatedUser) throws
            UserStoreException {

        for (String scope : scopes) {
            AccessTokenDO scopedToken = null;
            try {
                // Retrieve latest access token for particular client, user and scope combination
                // if its ACTIVE or EXPIRED.
                scopedToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getLatestAccessToken(clientId, authenticatedUser, authenticatedUser.getUserStoreDomain(),
                                scope, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while retrieving latest access token issued for Client ID : " +
                        clientId + ", User ID : " + authenticatedUser + " and Scope : " + scope;
                LOG.error(errorMsg, e);
                throw new UserStoreException(e);
            }
            if (scopedToken != null) {
                try {
                    // Revoking token from database
                    revokeTokens(Collections.singletonList(scopedToken));
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking " + "Access Token : "
                            + scopedToken.getAccessToken() + " for user " + authenticatedUser;
                    LOG.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
        return true;
    }
}
