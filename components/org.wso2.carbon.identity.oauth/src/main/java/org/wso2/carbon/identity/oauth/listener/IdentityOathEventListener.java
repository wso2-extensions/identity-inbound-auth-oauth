/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheEntry;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.
        CURRENT_SESSION_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.Config.
        PRESERVE_LOGGED_IN_SESSION_AT_PASSWORD_UPDATE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * This is an implementation of UserOperationEventListener. This defines
 * additional operations
 * for some of the core user management operations
 */
public class IdentityOathEventListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(IdentityOathEventListener.class);

    /**
     * Bundle execution order id.
     */
    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 100;
    }

    /**
     * Deleting user from the identity database prerequisites.
     */
    @Override
    public boolean doPreDeleteUser(String username,
                                   org.wso2.carbon.user.core.UserStoreManager userStoreManager)
            throws org.wso2.carbon.user.core.UserStoreException {

        if (!isEnable()) {
            return true;
        }

        removeClaimCacheEntry(username, userStoreManager);

        return revokeTokens(username, userStoreManager);

    }

    @Override
    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName,
                                          UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        removeTokensFromCache(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        removeTokensFromCache(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPostSetUserClaimValue(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokensOfLockedUser(userName, userStoreManager) &&
                revokeTokensOfDisabledUser(userName, userStoreManager)
                && removeUserClaimsFromCache(userName, userStoreManager);
    }

    @Override
    public boolean doPostSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                            UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokensOfLockedUser(userName, userStoreManager) &&
                revokeTokensOfDisabledUser(userName, userStoreManager)
                && removeUserClaimsFromCache(userName, userStoreManager);
    }

    @Override
    public boolean doPostAuthenticate(String userName, boolean authenticated, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokensOfLockedUser(userName, userStoreManager) &&
                revokeTokensOfDisabledUser(userName, userStoreManager);
    }

    @Override
    public boolean doPostUpdateCredential(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokens(userName, userStoreManager);
    }

    @Override
    public boolean doPostUpdateCredentialByAdmin(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokens(userName, userStoreManager);
    }

    @Override
    public boolean doPreUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        removeTokensFromCache(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPostUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles,
                                              UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        if (ArrayUtils.isNotEmpty(deletedRoles)) {
            revokeTokens(userName, userStoreManager);
        }
        return removeUserClaimsFromCache(userName, userStoreManager);
    }

    @Override
    public boolean doPreUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        List<String> userList = new ArrayList<>();
        userList.addAll(Arrays.asList(deletedUsers));
        userList.addAll(Arrays.asList(newUsers));
        for (String username : userList) {
            removeTokensFromCache(username, userStoreManager);
        }
        return true;
    }

    @Override
    public boolean doPostUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers,
                                              UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        List<String> userList = new ArrayList<>();
        userList.addAll(Arrays.asList(deletedUsers));
        userList.addAll(Arrays.asList(newUsers));
        for (String username : userList) {
            removeUserClaimsFromCache(username, userStoreManager);
        }
        for (String deletedUser : deletedUsers) {
            revokeTokens(deletedUser, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);
        if (StringUtils.isEmpty(errorCode)) {
            errorCode =
                    (String) IdentityUtil.threadLocalProperties.get()
                            .get(IdentityCoreConstants.USER_ACCOUNT_STATE_WITH_USERNAME + userName);
        }

        if (errorCode != null && (errorCode.equalsIgnoreCase(UserCoreConstants.ErrorCode.USER_IS_LOCKED))) {
            IdentityUtil.threadLocalProperties.get()
                    .remove(IdentityCoreConstants.USER_ACCOUNT_STATE_WITH_USERNAME + userName);
            return revokeTokens(userName, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensOfDisabledUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);
        if (StringUtils.isEmpty(errorCode)) {
            errorCode =
                    (String) IdentityUtil.threadLocalProperties.get()
                            .get(IdentityCoreConstants.USER_ACCOUNT_STATE_WITH_USERNAME + userName);
        }
        if (errorCode != null && errorCode.equalsIgnoreCase(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
            IdentityUtil.threadLocalProperties.get()
                    .remove(IdentityCoreConstants.USER_ACCOUNT_STATE_WITH_USERNAME + userName);
            return revokeTokens(userName, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

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
                log.error("Error occurred while getting user store domain for User ID : " + authenticatedUser, e);
                throw new UserStoreException(e);
            }
        }

        Set<String> clientIds;
        try {
            // get all the distinct client Ids authorized by this user
            clientIds = OAuthTokenPersistenceFactory.getInstance()
                    .getTokenManagementDAO().getAllTimeAuthorizedClientIds(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while retrieving apps authorized by User ID : " + authenticatedUser, e);
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
                log.error(errorMsg, e);
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
                OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());
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
                    log.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
        return true;
    }

    private boolean revokeTokens(List<AccessTokenDO> accessTokens) throws IdentityOAuth2Exception {

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

    private boolean revokeLatestTokensWithScopes(Set<String> scopes, String clientId,
                                                 AuthenticatedUser authenticatedUser) throws UserStoreException {

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
                log.error(errorMsg, e);
                throw new UserStoreException(e);
            }
            if (scopedToken != null) {
                try {
                    // Revoking token from database
                    revokeTokens(Collections.singletonList(scopedToken));
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking " + "Access Token : "
                            + scopedToken.getAccessToken() + " for user " + authenticatedUser;
                    log.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
        return true;
    }

    private void removeTokensFromCache(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        Set<AccessTokenDO> accessTokenDOSet;
        List<AuthzCodeDO> authorizationCodeDOSet;
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(userName);
        try {
            /*
             Only the tokens and auth codes issued for openid scope should be removed from the cache, since no
             claims are usually cached against tokens or auth codes, otherwise.
             */
            accessTokenDOSet = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getAccessTokensByUserForOpenidScope(authenticatedUser);
            authorizationCodeDOSet = OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().getAuthorizationCodesByUserForOpenidScope(authenticatedUser);
            removeAccessTokensFromCache(accessTokenDOSet);
            removeAuthzCodesFromCache(authorizationCodeDOSet);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while retrieving access tokens issued for user : " + userName;
            log.error(errorMsg, e);
        }
    }

    private void removeAuthzCodesFromCache(List<AuthzCodeDO> authorizationCodeDOSet) {

        if (CollectionUtils.isNotEmpty(authorizationCodeDOSet)) {
            for (AuthzCodeDO authorizationCodeDO : authorizationCodeDOSet) {
                String authorizationCode = authorizationCodeDO.getAuthorizationCode();
                String authzCodeId = authorizationCodeDO.getAuthzCodeId();
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
                AuthorizationGrantCache.getInstance().clearCacheEntryByCodeId(cacheKey, authzCodeId);
            }
        }
    }

    private void removeAccessTokensFromCache(Set<AccessTokenDO> accessTokenDOSet) {

        if (CollectionUtils.isNotEmpty(accessTokenDOSet)) {
            for (AccessTokenDO accessTokenDO : accessTokenDOSet) {
                String accessToken = accessTokenDO.getAccessToken();
                String tokenId = accessTokenDO.getTokenId();
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
                AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(cacheKey, tokenId);
            }
        }
    }

    /**
     * Remove user claims from ClaimCache
     *
     * @param userName
     */
    private boolean removeUserClaimsFromCache(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        ClaimCache claimCache = ClaimCache.getInstance();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(userName);
        authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
        authenticatedUser.setUserStoreDomain(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()));
        ClaimCacheKey cacheKey = new ClaimCacheKey(authenticatedUser);
        if (cacheKey != null) {
            claimCache.clearCacheEntry(cacheKey);
        }
        return true;
    }

    /**
     * Remove ClaimCache Entry if available.
     *
     * @param username
     * @param userStoreManager
     */
    private void removeClaimCacheEntry(String username, UserStoreManager userStoreManager) throws UserStoreException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
        authenticatedUser.setUserStoreDomain(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()));

        ClaimMetaDataCacheEntry cacheEntry = ClaimMetaDataCache.getInstance().getValueFromCache(
                new ClaimMetaDataCacheKey(authenticatedUser));
        if (cacheEntry == null) {
            return;
        }
        ClaimCache.getInstance().clearCacheEntry(cacheEntry.getClaimCacheKey());
    }
}
