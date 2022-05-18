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
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheEntry;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;


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

        return OAuthUtil.revokeTokens(username, userStoreManager);

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
        return true;
    }

    @Override
    public boolean doPostSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                            UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return true;
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
        return OAuthUtil.revokeTokens(userName, userStoreManager);
    }

    @Override
    public boolean doPostUpdateCredentialByAdmin(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return OAuthUtil.revokeTokens(userName, userStoreManager);
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
            OAuthUtil.revokeTokens(userName, userStoreManager);
        }
        return OAuthUtil.removeUserClaimsFromCache(userName, userStoreManager);
    }

    @Override
    public boolean doPostUpdateInternalRoleListOfUser(String userName, String[] deletedInternalRoles,
                                                      String[] newInternalRoles, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        if (ArrayUtils.isNotEmpty(deletedInternalRoles)) {
            OAuthUtil.revokeTokens(userName, userStoreManager);
        }
        return OAuthUtil.removeUserClaimsFromCache(userName, userStoreManager);
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

        return postUpdateUserListOfRole(deletedUsers, newUsers, userStoreManager);
    }

    @Override
    public boolean doPreDeleteRole(String roleName, UserStoreManager userStoreManager) throws UserStoreException {

        /*
         This get invoked during a group deletion. If it is a group, there should be a role associated with the group
          in order to revoke the tokens.
         */
        if (!isEnable()) {
            return true;
        }
        if (!(userStoreManager instanceof AbstractUserStoreManager)) {
            return true;
        }
        AbstractUserStoreManager abstractUserStoreManager = (AbstractUserStoreManager) userStoreManager;
        List<User> userList = abstractUserStoreManager.getUserListOfRoleWithID(roleName);
        // Check whether the group has any associated roles.
        String domainName = UserCoreUtil.getDomainName(abstractUserStoreManager.getRealmConfiguration());
        List<String> roles = abstractUserStoreManager.getHybridRoleListOfGroup(roleName,
                domainName);

        // Revoke the tokens if this group has some associated roles.
        if (CollectionUtils.isNotEmpty(roles)) {
            for (User user : userList) {
                OAuthUtil.removeUserClaimsFromCache(user.getUsername(), userStoreManager);
                OAuthUtil.revokeTokens(user.getUsername(), userStoreManager);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No roles associated with the group: " + roleName);
            }
        }
        return true;
    }

    @Override
    public boolean doPostUpdateUserListOfInternalRole(String roleName, String[] deletedUsers, String[] newUsers,
                                                      UserStoreManager userStoreManager) throws UserStoreException {

        return postUpdateUserListOfRole(deletedUsers, newUsers, userStoreManager);
    }

    private boolean postUpdateUserListOfRole(String[] deletedUsers, String[] newUsers,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        List<String> userList = new ArrayList<>();
        userList.addAll(Arrays.asList(deletedUsers));
        userList.addAll(Arrays.asList(newUsers));
        for (String username : userList) {
            OAuthUtil.removeUserClaimsFromCache(username, userStoreManager);
        }
        for (String deletedUser : deletedUsers) {
            OAuthUtil.revokeTokens(deletedUser, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (errorCode != null && (errorCode.equalsIgnoreCase(UserCoreConstants.ErrorCode.USER_IS_LOCKED))) {
            return OAuthUtil.revokeTokens(userName, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensOfDisabledUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (errorCode != null && errorCode.equalsIgnoreCase(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
            return OAuthUtil.revokeTokens(userName, userStoreManager);
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
                new ClaimMetaDataCacheKey(authenticatedUser),
                IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
        if (cacheEntry == null) {
            return;
        }
        ClaimCache.getInstance().clearCacheEntry(cacheEntry.getClaimCacheKey(),
                IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
    }
}
