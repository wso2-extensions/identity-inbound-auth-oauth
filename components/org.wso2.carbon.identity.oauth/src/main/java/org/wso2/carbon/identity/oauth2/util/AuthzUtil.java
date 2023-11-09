/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.util.OrganizationSharedUserUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.NotImplementedException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.INTERNAL_LOGIN_SCOPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.OIDC_ROLE_CLAIM_URI;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.APPLICATION;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.ORGANIZATION;
import static org.wso2.carbon.user.core.UserCoreConstants.APPLICATION_DOMAIN;
import static org.wso2.carbon.user.core.UserCoreConstants.INTERNAL_DOMAIN;

/**
 * Utility methods for the authorization related functionality.
 */
public class AuthzUtil {

    private static final Log LOG = LogFactory.getLog(AuthzUtil.class);

    /**
     * Get the user roles.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User roles.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving user roles.
     */
    public static List<String> getUserRoles(AuthenticatedUser authenticatedUser, String appId)
            throws IdentityOAuth2Exception {

        if (authenticatedUser.isFederatedUser()) {
            if (StringUtils.isNotBlank(authenticatedUser.getAccessingOrganization())) {
                if (!authenticatedUser.getAccessingOrganization()
                        .equals(authenticatedUser.getUserResidentOrganization())) {
                    // Handle switching organization scenario.
                    return getSwitchUserRoles(authenticatedUser);
                }
            }
            // Handler federated user scenario.
            return getFederatedUserRoles(authenticatedUser, appId);
        }
        if (StringUtils.isNotBlank(authenticatedUser.getAccessingOrganization())) {
            if (!authenticatedUser.getAccessingOrganization()
                    .equals(authenticatedUser.getUserResidentOrganization())) {
                return getSwitchUserRoles(authenticatedUser);
            }
        }
        return getRoles(getUserId(authenticatedUser), authenticatedUser.getTenantDomain());
    }

    /**
     * Get switching user roles.
     *
     * @param authenticatedUser Authenticated User.
     * @return Switching user roles.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of switching user.
     */
    private static List<String> getSwitchUserRoles(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        String accessingTenantDomain = getAccessingTenantDomain(authenticatedUser);
        String accessingUserId = getUserIdOfAssociatedUser(authenticatedUser);
        return getRoles(accessingUserId, accessingTenantDomain);
    }

    /**
     * Get the role ids.
     *
     * @param userId User ID.
     * @param tenantDomain Tenant domain.
     * @return Role ids of user.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of user.
     */
    private static List<String> getRoles(String userId, String tenantDomain) throws IdentityOAuth2Exception {

        List<String> roleIds = new ArrayList<>(getRoleIdsOfUser(userId, tenantDomain));
        List<String> groups = getUserGroups(userId, tenantDomain);
        if (!groups.isEmpty()) {
            roleIds.addAll(getRoleIdsOfGroups(groups, tenantDomain));
        }
        return roleIds;
    }

    /**
     * Get the federated role ids.
     *
     * @param authenticatedUser Authenticated user.
     * @return Federated role ids of user.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of user.
     */
    private static List<String> getFederatedUserRoles(AuthenticatedUser authenticatedUser, String appId)
            throws IdentityOAuth2Exception {

        String tenantDomain = authenticatedUser.getTenantDomain();
        String roleNamesString = null;
        Map<ClaimMapping, String> claimMappingStringMap = authenticatedUser.getUserAttributes();
        if (claimMappingStringMap == null) {
            return new ArrayList<>();
        }
        for (Map.Entry<ClaimMapping, String> entry : claimMappingStringMap.entrySet()) {
            if (OIDC_ROLE_CLAIM_URI.equals(entry.getKey().getLocalClaim().getClaimUri())) {
                roleNamesString = entry.getValue();
                break;
            }
        }
        List<String> roleNames = null;
        if (StringUtils.isNotBlank(roleNamesString)) {
            roleNames =  Arrays.asList(roleNamesString.split(FrameworkUtils.getMultiAttributeSeparator()));
        }
        if (roleNames == null || roleNames.isEmpty()) {
            return new ArrayList<>();
        }

        String allowedAppAudience = getApplicationAllowedAudience(appId, tenantDomain);
        if (ORGANIZATION.equalsIgnoreCase(allowedAppAudience)) {

            return getRoleIdsFromNames(roleNames, ORGANIZATION, getOrganizationId(tenantDomain), tenantDomain);
        }
        return getRoleIdsFromNames(roleNames, APPLICATION, appId, tenantDomain);
    }

    /**
     * Get accessing tenant domain of authenticated user.
     *
     * @param authenticatedUser Authenticated user.
     * @return Accessing tenant domain.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving accessing tenant domain.
     */
    private static String getAccessingTenantDomain(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {
        try {
            return OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(authenticatedUser.getAccessingOrganization());
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving accessing tenant domain", e);
        }
    }

    /**
     * Get user ID corresponds to the accessing user ID of authenticated user.
     *
     * @param authenticatedUser Authenticated user.
     * @return The user ID.
     * @throws IdentityOAuth2Exception If an error occurs while resolving the user ID.
     */
    private static String getUserIdOfAssociatedUser(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        String associatedUserId;
        /* When user ID resolving for the organization SSO federated users, the associated user ID can be found from the
         userName of the authenticated user object. */
        if (authenticatedUser.isFederatedUser()) {
            String userName = MultitenantUtils.getTenantAwareUsername(authenticatedUser.getUserName());
            userName = UserCoreUtil.removeDomainFromName(userName);
            associatedUserId = userName;
        } else {
            associatedUserId = getUserId(authenticatedUser);
        }
        try {
            Optional<String> optionalOrganizationUserId = OrganizationSharedUserUtil
                    .getUserIdOfAssociatedUserByOrgId(associatedUserId, authenticatedUser.getAccessingOrganization());
            return optionalOrganizationUserId.orElseThrow(() ->
                    new IdentityOAuth2ClientException("User is not allowed to access the organization"));
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving shared user ID" , e);
        }
    }

    /**
     * Get the associated scopes for the roles.
     *
     * @param roles Roles.
     * @param tenantDomain Tenant domain.
     * @return List of associated scopes.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving scope list of roles.
     */
    public static List<String> getAssociatedScopesForRoles(List<String> roles, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            List<String> permissionListOfRoles = OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getPermissionListOfRoles(roles, tenantDomain);
            if (permissionListOfRoles == null) {
                permissionListOfRoles = new ArrayList<>();
            }
            // Every user should get internal_login permission.
            permissionListOfRoles.add(INTERNAL_LOGIN_SCOPE);
            return permissionListOfRoles;
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving scope list of roles : "
                    + StringUtils.join(roles, ",") + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Check whether user has the request permissions.
     * This is added to be used in basic authentication flow.
     *
     * @param requestedPermissions Requested scopes.
     * @param authenticatedUser    Authenticated user.
     * @return True if user has the requested permissions.
     * @throws IdentityOAuth2Exception if an error occurs while checking user authorization.
     */
    public static boolean isUserAuthorized(AuthenticatedUser authenticatedUser, List<String> requestedPermissions)
            throws IdentityOAuth2Exception {

        // Application id is not required for basic authentication flow.
        List<String> roleIds = getUserRoles(authenticatedUser, null);
        List<String> permissions = getAssociatedScopesForRoles(roleIds, authenticatedUser.getTenantDomain());
        return new HashSet<>(permissions).containsAll(requestedPermissions);
    }

    /**
     * Get the role ids of user.
     *
     * @param userId User ID.
     * @param tenantDomain Tenant domain.
     * @return Role ids of user.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of user.
     */
    private static List<String> getRoleIdsOfUser(String userId, String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfUser(userId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving role id list of user : " + userId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get user id of the user
     *
     * @param authenticatedUser Authenticated user.
     * @return User id.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving user id of user.
     */
    private static String getUserId(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        try {
            return authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("Error while resolving user id of user" , e);
        }
    }

    /**
     * Get organization id
     *
     * @param tenantDomain Tenant domain.
     * @return Organization Id.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving org id.
     */
    private static String getOrganizationId(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving org id of tenant : " + tenantDomain , e);
        }
    }

    /**
     * Get application allowed audience.
     *
     * @param appId App id.
     * @param tenantDomain Tenant domain.
     * @return Allowed audience of app.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving allowed audience of app.
     */
    private static String getApplicationAllowedAudience(String appId, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getApplicationMgtService()
                    .getAllowedAudienceForRoleAssociation(appId, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving allowed audience of app : " + appId , e);
        }
    }

    /**
     * Get the role ids from role names.
     *
     * @param roleNames Role names.
     * @param tenantDomain Tenant domain.
     * @param roleAudience Role audience.
     * @param roleAudienceId Role audience id.
     * @return Role ids of idp groups.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of idp groups.
     */
    private static List<String> getRoleIdsFromNames(List<String> roleNames, String roleAudience, String roleAudienceId,
                                                    String tenantDomain)
            throws IdentityOAuth2Exception {

        List<String> roleIds = new ArrayList<>();
        try {
            for (String roleName: roleNames) {
                roleIds.add(OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                        .getRoleIdByName(roleName, roleAudience, roleAudienceId, tenantDomain));
            }
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving role ids of  list of role anme : "
                    + StringUtils.join(roleNames, ",") + "tenant domain : " + tenantDomain, e);
        }
        return roleIds;
    }

    /**
     * Get the groups of the authenticated user.
     *
     * @param userId User id.
     * @param tenantDomain Tenant domain.
     * @return - Groups of the user.
     */
    private static List<String> getUserGroups(String userId, String tenantDomain) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started group fetching for scope validation.");
        }
        List<String> userGroups = new ArrayList<>();
        RealmService realmService = UserCoreUtil.getRealmService();
        try {
            int tenantId = OAuth2Util.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            List<Group> groups =
                    ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(userId,
                            null, null);
            for (Group group : groups) {
                String groupName = group.getGroupName();
                String groupDomainName = UserCoreUtil.extractDomainFromName(groupName);
                if (!INTERNAL_DOMAIN.equalsIgnoreCase(groupDomainName) &&
                        !APPLICATION_DOMAIN.equalsIgnoreCase(groupDomainName)) {
                    userGroups.add(group.getGroupID());
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        } catch (UserStoreException e) {
            if (isDoGetGroupListOfUserNotImplemented(e)) {
                return userGroups;
            }
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Completed group fetching for scope validation.");
        }
        return userGroups;
    }

    /**
     * Get the role ids of groups.
     *
     * @param groups Groups.
     * @param tenantDomain Tenant domain.
     * @return Role ids of groups.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of groups.
     */
    private static List<String> getRoleIdsOfGroups(List<String> groups, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfGroups(groups, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving role id list of groups : "
                    + StringUtils.join(groups, ",") + "tenant domain : " + tenantDomain, e);
        }
    }


    /**
     * Check if the UserStoreException occurred due to the doGetGroupListOfUser method not being implemented.
     *
     * @param e UserStoreException.
     * @return true if the UserStoreException was caused by the doGetGroupListOfUser method not being implemented,
     * false otherwise.
     */
    private static boolean isDoGetGroupListOfUserNotImplemented(UserStoreException e) {

        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof NotImplementedException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    /**
     * Check whether legacy authorization runtime is enabled.
     *
     * @return True if legacy authorization runtime is enabled.
     */
    public static boolean isLegacyAuthzRuntime() {

        return CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME;
    }

    /**
     * Check whether the authenticated user is accessing the resident organization where the identity is managed.
     *
     * @param authenticatedUser The authenticated user.
     * @return True if the authenticated user is accessing the resident organization.
     */
    public static boolean isUserAccessingResidentOrganization(AuthenticatedUser authenticatedUser) {

        return authenticatedUser.getAccessingOrganization() == null ||
                authenticatedUser.getAccessingOrganization().equals(authenticatedUser.getUserResidentOrganization());
    }
}
