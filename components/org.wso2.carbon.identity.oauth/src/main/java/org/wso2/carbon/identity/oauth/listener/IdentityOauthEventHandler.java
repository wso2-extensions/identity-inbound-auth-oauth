/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AuthorizedAPI;
import org.wso2.carbon.identity.application.common.model.Scope;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.mgt.core.GroupBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.mgt.core.UserBasicInfo;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleDTO;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.DELETE_GROUP_ID_LIST;

/**
 * This is an event handler listening for some of the core user management operations.
 */
public class IdentityOauthEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(IdentityOauthEventHandler.class);

    public String getName() {

        return "identityOauthEventHandler";
    }

    public String getFriendlyName() {

        return "Identity Oauth Event Handler";
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {

        super.init(configuration);
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        int priority = super.getPriority(messageContext);
        if (priority == -1) {
            priority = 51;
        }
        return priority;
    }


    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName()) ||
                IdentityEventConstants.Event.POST_SET_USER_CLAIM.equals(event.getEventName())) {
            String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
            UserStoreManager userStoreManager =
                    (UserStoreManager) event.getEventProperties()
                            .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
            try {
                revokeTokensOfLockedUser(username, userStoreManager);
                revokeCodesOfLockedUser(username, userStoreManager);
                revokeTokensOfDisabledUser(username, userStoreManager);
                OAuthUtil.removeUserClaimsFromCache(username, userStoreManager);
            } catch (UserStoreException e) {
                String errorMsg = "Error occurred while revoking  access token for User : " + username;
                log.error(errorMsg, e);
                throw new IdentityEventException(errorMsg);
            }

        } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_EVENT.equals(event.getEventName()) ||
            IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_V2_EVENT.equals(event.getEventName())) {

            Object userIdList = event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.DELETE_USER_ID_LIST);
            String roleId = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.ROLE_ID);
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            List<String> deletedUserIDList;

            if (userIdList instanceof List<?>) {
                deletedUserIDList = (List<String>) userIdList;
                terminateSession(deletedUserIDList, roleId, tenantDomain);
            }

        } else if (IdentityEventConstants.Event.PRE_UPDATE_GROUP_LIST_OF_ROLE_EVENT.equals(event.getEventName()) ||
            IdentityEventConstants.Event.PRE_UPDATE_GROUP_LIST_OF_ROLE_V2_EVENT.equals(event.getEventName())) {

            // PRE_UPDATE_IDP_GROUP_LIST_OF_ROLE_V2_EVENT will not be handled since we can not resolve the users.
            // To resolve the users affected by the update, we need to fetch all the users assigned with these group.
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            List<String> deletedGroups = (ArrayList) event.getEventProperties().get(DELETE_GROUP_ID_LIST);
            List<User> userListOfDeletedGroups = new ArrayList<>();
            for (String groupId : deletedGroups) {
                userListOfDeletedGroups.addAll(getUserListOfGroup(groupId, tenantDomain));
            }

            Set<String> userIds = new HashSet<>();
            for (User user : userListOfDeletedGroups) {
                userIds.add(user.getUserID());
            }
            terminateSession(new ArrayList<>(userIds), null, tenantDomain);

        } else if (IdentityEventConstants.Event.PRE_DELETE_ROLE_EVENT.equals(event.getEventName()) ||
                IdentityEventConstants.Event.POST_SET_PERMISSIONS_FOR_ROLE_EVENT.equals(event.getEventName())) {

            String roleId = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.ROLE_ID);
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            try {
                RoleManagementService roleManagementService =
                        OAuthComponentServiceHolder.getInstance().getRoleManagementService();
                // Users can be either directly linked to roles or groups.
                // Get the users directly linked to roles.
                List<UserBasicInfo> userListOfRole = roleManagementService.getUserListOfRole(roleId, tenantDomain);
                // Get the users directly linked to group associated with the role.
                List<GroupBasicInfo> groupListOfRole = roleManagementService.getGroupListOfRole(roleId, tenantDomain);
                List<User> userListOfGroup = new ArrayList<>();
                for (GroupBasicInfo group : groupListOfRole) {
                    String userStoreDomainName = UserCoreUtil.extractDomainFromName(group.getName());
                    String groupName = UserCoreUtil.removeDomainFromName(group.getName());
                    updateUserListOfGroup(userListOfGroup, groupName, tenantDomain, userStoreDomainName);
                }

                List<String> userIdList = new ArrayList<>();
                for (UserBasicInfo userBasicInfo : userListOfRole) {
                    userIdList.add(userBasicInfo.getId());
                }
                for (User user : userListOfGroup) {
                    userIdList.add(user.getUserID());
                }
                terminateSession(userIdList, null, tenantDomain);

            } catch (IdentityRoleManagementException e) {
                String errorMsg = "Invalid role id :" + roleId + "in tenant domain " + tenantDomain;
                throw new IdentityEventException(errorMsg);
            }

        } else if (IdentityEventConstants.Event.PRE_DELETE_ROLE_V2_EVENT.equals(event.getEventName()) ||
                IdentityEventConstants.Event.POST_UPDATE_PERMISSIONS_FOR_ROLE_V2_EVENT.equals(event.getEventName())) {

            String roleId = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.ROLE_ID);
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            try {
                // Terminate sessions associated with the primary role.
                terminateSessionsForRole(roleId, tenantDomain);

                List<RoleDTO> roleDTOList = OAuthComponentServiceHolder.getInstance().getRoleV2ManagementService()
                        .getSharedHybridRoles(roleId, IdentityTenantUtil.getTenantId(tenantDomain));
                for (RoleDTO roleDTO : roleDTOList) {
                    tenantDomain = IdentityTenantUtil.getTenantDomain(roleDTO.getTenantId());
                    roleId = roleDTO.getId();
                    // Terminate sessions associated with the given shared role.
                    terminateSessionsForRole(roleId, tenantDomain);
                }
            } catch (org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException e) {
                String errorMsg = "Invalid role id :" + roleId + "in tenant domain " + tenantDomain;
                throw new IdentityEventException(errorMsg);
            }
        } else if (IdentityEventConstants.Event.PRE_UPDATE_AUTHORIZED_API_FOR_APPLICATION_EVENT
                .equals(event.getEventName())) {

            String appId = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.APPLICATION_ID);
            String apiId = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.API_ID);
            List<String> removedScopes = (List<String>) event.getEventProperties().get(IdentityEventConstants.
                    EventProperty.DELETED_SCOPES);
            String tenantDomain = (String) event.getEventProperties().get(IdentityEventConstants.
                    EventProperty.TENANT_DOMAIN);
            if (!removedScopes.isEmpty()) {
                try {
                    OAuth2ServiceComponentHolder.getInstance()
                            .getRevocationProcessor().revokeTokens(appId, apiId, removedScopes, tenantDomain);
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking access token " +
                            "for application resource id: " + appId;
                    log.error(errorMsg, e);
                    throw new IdentityEventException(errorMsg);
                }
            }
        } else if (IdentityEventConstants.Event.PRE_DELETE_AUTHORIZED_API_FOR_APPLICATION_EVENT
                .equals(event.getEventName())) {

            String appId = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.APPLICATION_ID);
            String apiId = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.API_ID);
            String tenantDomain = (String) event.getEventProperties().get(IdentityEventConstants.
                    EventProperty.TENANT_DOMAIN);
            try {
                AuthorizedAPI authorizedAPI = OAuthComponentServiceHolder.getInstance()
                        .getAuthorizedAPIManagementService()
                        .getAuthorizedAPI(appId, apiId, tenantDomain);
                if (authorizedAPI.getScopes() == null) {
                    return;
                }
                List<String> removedScopes = authorizedAPI.getScopes().stream()
                        .map(Scope::getName).collect(Collectors.toList());
                if (!removedScopes.isEmpty()) {
                    OAuth2ServiceComponentHolder.getInstance()
                            .getRevocationProcessor().revokeTokens(appId, apiId, removedScopes, tenantDomain);
                }
            } catch (IdentityOAuth2Exception | IdentityApplicationManagementException e) {
                String errorMsg = "Error occurred while revoking access token " +
                        "for application resource id: " + appId;
                log.error(errorMsg, e);
                throw new IdentityEventException(errorMsg);
            }
        }
    }

    /**
     * Terminate sessions associated for the given role.
     *
     * @param roleId       The ID of the role.
     * @param tenantDomain The tenant domain of the role.
     * @throws org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException if any error while
     *                                                                                             listing users and
     *                                                                                             groups for the role.
     * @throws IdentityEventException                                                              if any error with
     *                                                                                             session termination.
     */
    private void terminateSessionsForRole(String roleId, String tenantDomain) throws
            org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException,
            IdentityEventException {

        org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService roleV2ManagementService =
                OAuthComponentServiceHolder.getInstance().getRoleV2ManagementService();
        // Users can be either directly linked to roles or groups.
        // Get the users directly linked to roles.
        List<org.wso2.carbon.identity.role.v2.mgt.core.model.UserBasicInfo> userListOfRole =
                roleV2ManagementService.getUserListOfRole(roleId, tenantDomain);
        // Get the users directly linked to group associated with the role.
        List<org.wso2.carbon.identity.role.v2.mgt.core.model.GroupBasicInfo> groupListOfRole =
                roleV2ManagementService.getGroupListOfRole(roleId, tenantDomain);
        List<User> userListOfGroup = new ArrayList<>();
        for (org.wso2.carbon.identity.role.v2.mgt.core.model.GroupBasicInfo group : groupListOfRole) {
            String userStoreDomainName = UserCoreUtil.extractDomainFromName(group.getName());
            String groupName = UserCoreUtil.removeDomainFromName(group.getName());
            updateUserListOfGroup(userListOfGroup, groupName, tenantDomain, userStoreDomainName);
        }

        List<String> userIdList = new ArrayList<>();
        for (org.wso2.carbon.identity.role.v2.mgt.core.model.UserBasicInfo userBasicInfo : userListOfRole) {
            userIdList.add(userBasicInfo.getId());
        }
        for (User user : userListOfGroup) {
            userIdList.add(user.getUserID());
        }
        terminateSession(userIdList, roleId, tenantDomain);
    }

    /**
     * Get the users associated to a group and update the list object.
     *
     * @param userListOfGroup     Existing users of the group.
     * @param groupName           Name of the group.
     * @param tenantDomain        Tenant domain of the group.
     * @param userStoreDomain User store domain of the group
     * @throws IdentityEventException if there is any error while getting user list.
     */
    private void updateUserListOfGroup(List<User> userListOfGroup, String groupName, String tenantDomain,
                                       String userStoreDomain) throws IdentityEventException {

        try {
            UserStoreManager userStoreManager = getUserStoreManager(tenantDomain, userStoreDomain);
            if (userStoreManager instanceof AbstractUserStoreManager) {
                AbstractUserStoreManager abstractUserStoreManager = (AbstractUserStoreManager) userStoreManager;
                userListOfGroup.addAll(abstractUserStoreManager.getUserListOfRoleWithID(groupName));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Provided user store manager for the group: " + groupName + " of userstore domain: " +
                            userStoreDomain + ", is not an instance of the AbstractUserStore manager");
                }
            }
        } catch (UserStoreException e) {
            String errorMsg =
                    "Error while getting user list of group:" + groupName + "in tenant domain " + tenantDomain;
            throw new IdentityEventException(errorMsg, e);
        }
    }

    private List<User> getUserListOfGroup(String groupId, String tenantDomain) throws IdentityEventException {

        try {
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            UserStoreManager userStoreManager;
            try {
                userStoreManager = (UserStoreManager) realmService.getTenantUserRealm(
                        IdentityTenantUtil.getTenantId(tenantDomain)).getUserStoreManager();
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                String errorMsg = "Error while getting realm service in tenant domain " + tenantDomain;
                throw new IdentityEventException(errorMsg, e);
            }
            return ((AbstractUserStoreManager) userStoreManager).getUserListOfGroup(groupId, null, null);

        } catch (UserStoreException e) {
            String errorMsg =
                    "Error while getting user list of group: " + groupId + " in tenant domain " + tenantDomain;
            throw new IdentityEventException(errorMsg, e);
        }
    }

    /**
     * Returns UserStoreManager.
     *
     * @param tenantDomain        Tenant domain of the required user store.
     * @param userStoreDomainName User store domain of the required user store.
     * @return User store manager object using the user store name.
     * @throws IdentityEventException if there is an error while getting realm service.
     */
    private UserStoreManager getUserStoreManager(String tenantDomain, String userStoreDomainName)
            throws IdentityEventException {

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        try {
            UserStoreManager userStoreManager = (UserStoreManager) realmService.getTenantUserRealm(
                            IdentityTenantUtil.getTenantId(tenantDomain)).getUserStoreManager();
            return userStoreManager.getSecondaryUserStoreManager(userStoreDomainName);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error while getting realm service in tenant domain " + tenantDomain;
            throw new IdentityEventException(errorMsg, e);
        }
    }

    private void revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws IdentityEventException, UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (UserCoreConstants.ErrorCode.USER_IS_LOCKED.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is locked. Hence revoking user's access tokens.", userName));
            }
            OAuth2ServiceComponentHolder.getInstance()
                    .getRevocationProcessor()
                    .revokeTokens(userName, userStoreManager);
            // Handling the token revocation of invited users from parent organization.
            revokeTokensOfAssociatedUsers(userName, userStoreManager);
        }
    }

    private void revokeCodesOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (UserCoreConstants.ErrorCode.USER_IS_LOCKED.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is locked. Hence revoking user's authorization codes.", userName));
            }
            OAuthUtil.revokeAuthzCodes(userName, userStoreManager);
        }
    }

    private void revokeTokensOfDisabledUser(String userName, UserStoreManager userStoreManager)
            throws IdentityEventException, UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);
        if (IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is disabled. Hence revoking user's access tokens.", userName));
            }
            OAuth2ServiceComponentHolder.getInstance()
                    .getRevocationProcessor()
                    .revokeTokens(userName, userStoreManager);
            // Handling the token revocation of invited users from parent organization.
            revokeTokensOfAssociatedUsers(userName, userStoreManager);
        }
    }

    /**
     * Revoke access tokens of associated users.
     *
     * @param username         Username of the user.
     * @param userStoreManager User store manager of the user.
     * @throws IdentityEventException If an error occurs while revoking access tokens of associated users.
     */
    private void revokeTokensOfAssociatedUsers(String username, UserStoreManager userStoreManager)
            throws IdentityEventException {

        if (log.isDebugEnabled()) {
            log.debug("Revoking access tokens of associated users of user: " + username);
        }
        try {
            String userId = ((AbstractUserStoreManager) userStoreManager).getUser(null, username).getUserID();
            String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
            String orgId = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            List<UserAssociation> userAssociationList = OAuthComponentServiceHolder.getInstance()
                    .getOrganizationUserSharingService().getUserAssociationsOfGivenUser(userId, orgId);
            if (CollectionUtils.isEmpty(userAssociationList)) {
                return;
            }
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
                OAuth2ServiceComponentHolder.getInstance()
                        .getRevocationProcessor()
                        .revokeTokens(usernameOfUserAssociation, userStoreManagerOfUserAssociation);
            }
        } catch (OrganizationManagementException | org.wso2.carbon.user.api.UserStoreException e) {
            throw new IdentityEventException("Error occurred while revoking access tokens of associated users.", e);
        }
    }

    private UserStoreManager getUserStoreManager(int tenantId) throws org.wso2.carbon.user.api.UserStoreException {

        UserStoreManager userStoreManager;
        userStoreManager = (UserStoreManager) CarbonContext.getThreadLocalCarbonContext()
                .getUserRealm().getUserStoreManager();
        /* In scenarios like tenant creation, the usersStoreManager gets resolved to the super tenant since the
        tenant is not fully created yet. Hence, we need to get the userStoreManager from the tenant user realm.*/
        if (userStoreManager != null && userStoreManager.getTenantId() != tenantId) {
            userStoreManager = (UserStoreManager) OAuthComponentServiceHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
        }
        return userStoreManager;
    }

    /**
     * To revoke access tokens and terminate sessions of given list of user IDs.
     *
     * @param userIDList            List of user IDs
     * @throws IdentityEventException
     */
    private void terminateSession(List<String> userIDList, String roleId, String tenantDomain)
            throws IdentityEventException {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = getUserStoreManager(tenantId);

            String userName;
            if (CollectionUtils.isNotEmpty(userIDList)) {
                for (String userId : userIDList) {
                    try {
                        userName = FrameworkUtils.resolveUserNameFromUserId(userStoreManager, userId);
                        if (userName == null) {
                            log.warn("User name is null for user id: " + userId + ". Hence skipping " +
                                    "token revocation and session termination processes.");
                            continue;
                        }
                        OAuth2ServiceComponentHolder.getInstance()
                                .getRevocationProcessor()
                                .revokeTokens(userName, userStoreManager, roleId);
                        OAuthUtil.removeUserClaimsFromCache(userName, userStoreManager);
                    } catch (UserSessionException e) {
                        String errorMsg = "Error occurred while revoking access token for user Id: " + userId;
                        log.error(errorMsg, e);
                        throw new IdentityEventException(errorMsg, e);
                    }
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error occurred while retrieving user manager";
            log.error(errorMsg, e);
            throw new IdentityEventException(errorMsg, e);
        }
    }
}
