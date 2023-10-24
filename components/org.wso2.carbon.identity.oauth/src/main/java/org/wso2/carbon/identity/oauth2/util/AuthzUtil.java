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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdPGroup;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.NotImplementedException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
    public static List<String> getUserRoles(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        List<String> roleIds = new ArrayList<>();
        // Get role id list of the user.
        List<String> roleIdsOfUser = getRoleIdsOfUser(authenticatedUser);
        if (!roleIdsOfUser.isEmpty()) {
            roleIds.addAll(roleIdsOfUser);
        }
        // Get groups of the user.
        List<String> groups = getUserGroups(authenticatedUser);
        if (!groups.isEmpty()) {
            List<String> roleIdsOfGroups = getRoleIdsOfGroups(groups, authenticatedUser.getTenantDomain());
            if (!roleIdsOfGroups.isEmpty()) {
                roleIds.addAll(roleIdsOfGroups);
            }
        }
        if (authenticatedUser.isFederatedUser()) {
            List<String> roleIdsOfIdpGroups = getRoleIdsOfIdpGroups(getUserIdpGroups(authenticatedUser),
                    authenticatedUser.getTenantDomain());
            if (!roleIdsOfIdpGroups.isEmpty()) {
                roleIds.addAll(roleIdsOfIdpGroups);
            }
        }
        return roleIds;
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
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getPermissionListOfRoles(roles, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving scope list of roles : "
                    + StringUtils.join(roles, ",") + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get the role ids of user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return Role ids of user.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of user.
     */
    private static List<String> getRoleIdsOfUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        String tenantDomain = authenticatedUser.getTenantDomain();
        if (authenticatedUser.getAccessingOrganization() != null) {
            try {
                tenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(authenticatedUser.getUserResidentOrganization());
            } catch (OrganizationManagementException e) {
                throw new RuntimeException(e);
            }
        }
        String userId;
        try {
            userId = authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("Error while resolving user id of user" , e);
        }
        if (userId == null) {
            throw new IdentityOAuth2Exception("user not found");
        }
        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfUser(userId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving role id list of user : " + userId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get the role ids of user.
     *
     * @param userId User id.
     * @param tenantDomain Tenant domain.
     * @return Role ids of user.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of user.
     */
    private static List<String> getRoleIdsOfUser2(String userId, String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfUser(userId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving role id list of user : " + userId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get the role ids of idp groups
     *
     * @param groups Groups.
     * @param tenantDomain Tenant domain.
     * @return Role ids of idp groups.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving role id list of idp groups.
     */
    private static List<String> getRoleIdsOfIdpGroups(List<String> groups, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfIdpGroups(groups, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving role id list of groups : "
                    + StringUtils.join(groups, ",") + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get the groups of the authenticated user.
     *
     * @param authenticatedUser  Authenticated user.
     * @return - Groups of the user.
     */
    private static List<String> getUserGroups(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started group fetching for scope validation.");
        }
        List<String> userGroups = new ArrayList<>();
        RealmService realmService = UserCoreUtil.getRealmService();
        try {
            int tenantId = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            List<Group> groups =
                    ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(authenticatedUser.getUserId(),
                            null, null);
            for (Group group : groups) {
                String groupName = group.getGroupName();
                String groupDomainName = UserCoreUtil.extractDomainFromName(groupName);
                if (!INTERNAL_DOMAIN.equalsIgnoreCase(groupDomainName) &&
                        !APPLICATION_DOMAIN.equalsIgnoreCase(groupDomainName)) {
                    userGroups.add(group.getGroupID());
                }
            }
        } catch (UserIdNotFoundException | IdentityOAuth2Exception e) {
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
     * Get the groups of the authenticated user.
     *
     * @param authenticatedUser  Authenticated user.
     * @return - Groups of the user.
     */
    private static List<String> getUserIdpGroups(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        LOG.debug("Started group fetching for scope validation.");

        String idpName = authenticatedUser.getFederatedIdPName();
        String tenantDomain = authenticatedUser.getTenantDomain();
        IdentityProvider federatedIdP = getIdentityProvider(idpName, tenantDomain);
        List<IdPGroup> idpGroups  = new ArrayList<>(Arrays.asList(federatedIdP.getIdPGroupConfig()));
        // Convert idPGroups into a map for quick lookup
        Map<String, String> groupNameToIdMap = new HashMap<>();
        for (IdPGroup group : idpGroups) {
            groupNameToIdMap.put(group.getIdpGroupName(), group.getIdpGroupId());
        }
        if (federatedIdP != null) {
            String idpGroupsClaimUri = Arrays.stream(federatedIdP.getClaimConfig().getClaimMappings())
                    .filter(claimMapping -> claimMapping.getLocalClaim().getClaimUri()
                            .equals(FrameworkConstants.GROUPS_CLAIM))
                    .map(claimMapping -> claimMapping.getRemoteClaim().getClaimUri())
                    .findFirst()
                    .orElse(null);
            // If there is no group claim mapping, no need to proceed.
            if (idpGroupsClaimUri == null) {
                return new ArrayList<>();
            }
            Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                ClaimMapping claimMapping = entry.getKey();
                if (idpGroupsClaimUri.equals(claimMapping.getRemoteClaim().getClaimUri())) {
                    String idPGroupsClaim = entry.getValue();
                    if (StringUtils.isNotBlank(idPGroupsClaim)) {
                        List<String> groupNames = new ArrayList<>(Arrays.asList(idPGroupsClaim
                                .split(Pattern.quote(FrameworkUtils.getMultiAttributeSeparator()))));
                        return groupNames.stream().map(groupNameToIdMap::get).collect(Collectors.toList());
                    }
                }
            }
        }
        return new ArrayList<>();
    }

    /**
     * Get the Identity Provider object for the given identity provider name.
     *
     * @param idpName      Identity provider name.
     * @param tenantDomain Tenant domain.
     * @return Identity Provider object.
     * @throws IdentityOAuth2Exception Exception thrown when getting the identity provider.
     */
    private static IdentityProvider getIdentityProvider(String idpName, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getIdpManager().getIdPByName(idpName, tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving idp by idp name : " + idpName, e);
        }
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
}
