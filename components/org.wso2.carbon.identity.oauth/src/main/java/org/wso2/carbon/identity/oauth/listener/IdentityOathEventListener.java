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
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheEntry;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheKey;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;


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
        return revokeTokensOfUser(username, userStoreManager) &&
                OAuthUtil.revokeAuthzCodes(username, userStoreManager);

    }

    @Override
    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName,
                                          UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        OAuthUtil.removeAuthzGrantCacheForUser(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        OAuthUtil.removeAuthzGrantCacheForUser(userName, userStoreManager);
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
        boolean isSuccessOnRevokeTokens = revokeTokensOfUser(userName, userStoreManager);

        boolean isSuccessOnRevokeAuthzCodes = OAuthUtil.revokeAuthzCodes(userName, userStoreManager);

        boolean isSuccessOnRevokeAssociateUsersTokens = revokeTokensOfAssociatedUsers(userName, userStoreManager);

        return isSuccessOnRevokeTokens && isSuccessOnRevokeAssociateUsersTokens && isSuccessOnRevokeAuthzCodes;
    }

    @Override
    public boolean doPostUpdateCredentialByAdmin(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        boolean isSuccessOnRevokeTokens = revokeTokensOfUser(userName, userStoreManager);

        boolean isSuccessOnRevokeAuthzCodes = OAuthUtil.revokeAuthzCodes(userName, userStoreManager);

        boolean isSuccessOnRevokeAssociateUsersTokens = revokeTokensOfAssociatedUsers(userName, userStoreManager);

        return isSuccessOnRevokeTokens && isSuccessOnRevokeAssociateUsersTokens && isSuccessOnRevokeAuthzCodes;
    }

    @Override
    public boolean doPreUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        OAuthUtil.removeAuthzGrantCacheForUser(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPostUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles,
                                              UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        if (ArrayUtils.isNotEmpty(deletedRoles)) {
            revokeTokensOfUser(userName, userStoreManager);
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
            revokeTokensOfUser(userName, userStoreManager);
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
            OAuthUtil.removeAuthzGrantCacheForUser(username, userStoreManager);
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
                revokeTokensOfUser(user.getUsername(), userStoreManager);
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
            revokeTokensOfUser(deletedUser, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (errorCode != null && (errorCode.equalsIgnoreCase(UserCoreConstants.ErrorCode.USER_IS_LOCKED))) {
            return revokeTokensOfUser(userName, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensOfDisabledUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (errorCode != null && errorCode.equalsIgnoreCase(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
            return revokeTokensOfUser(userName, userStoreManager);
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
                new ClaimMetaDataCacheKey(authenticatedUser),
                IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
        if (cacheEntry == null) {
            return;
        }
        ClaimCache.getInstance().clearCacheEntry(cacheEntry.getClaimCacheKey(),
                IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
    }

    /**
     * Revoke access tokens of associated users.
     *
     * @param username         Username of the user.
     * @param userStoreManager User store manager of the user.
     * @return true if revocation is successfull. Else return false
     */
    private boolean revokeTokensOfAssociatedUsers(String username, UserStoreManager userStoreManager) {

        if (log.isDebugEnabled()) {
            log.debug("Revoking access tokens of associated users of user: " + username);
        }

        boolean isSuccessOnRevoking = true;
        try {
            String userId = ((AbstractUserStoreManager) userStoreManager).getUser(null, username).getUserID();
            String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
            String orgId = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            List<UserAssociation> userAssociationList = OAuthComponentServiceHolder.getInstance()
                    .getOrganizationUserSharingService().getUserAssociationsOfGivenUser(userId, orgId);

            for (UserAssociation userAssociation : userAssociationList) {
                String orgIdOfUserAssociation = userAssociation.getOrganizationId();
                String tenantDomainOfUserAssociation = OAuthComponentServiceHolder.getInstance()
                        .getOrganizationManager().resolveTenantDomain(orgIdOfUserAssociation);
                RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
                UserStoreManager userStoreManagerOfUserAssociation = (UserStoreManager)
                        realmService.getTenantUserRealm(
                                IdentityTenantUtil.getTenantId(tenantDomainOfUserAssociation)).getUserStoreManager();
                String usernameOfUserAssociation = ((AbstractUserStoreManager) userStoreManagerOfUserAssociation)
                        .getUserNameFromUserID(userAssociation.getUserId());
                boolean isSuccessOnSingleRevoke = revokeTokensOfUser(usernameOfUserAssociation,
                        userStoreManagerOfUserAssociation);
                if (!isSuccessOnSingleRevoke) {
                    isSuccessOnRevoking = false;
                }
            }
        } catch (OrganizationManagementException | org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error occurred while revoking access tokens of associated users.", e);
            return false;
        }

        return isSuccessOnRevoking;
    }

    /**
     * Revoke tokens of the user by invoking the registered revocation processors.
     *
     * @param userName          Username of the user.
     * @param userStoreManager  User store manager.
     * @return true if tokens are revoked successfully, false otherwise.
     * @throws UserStoreException
     */
    private boolean revokeTokensOfUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        boolean isRevoked = true;
        for (OAuth2RevocationProcessor revocationProcessor :
                OAuth2ServiceComponentHolder.getInstance().getRevocationProcessors()) {
            isRevoked &= revocationProcessor.revokeTokens(userName, userStoreManager);
        }
        return isRevoked;
    }
}
