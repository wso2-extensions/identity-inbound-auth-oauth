package org.wso2.carbon.identity.oauth2.validators.policyhandler.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdPGroup;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationHandlerException;
import org.wso2.carbon.identity.role.v2.mgt.core.IdentityRoleManagementException;
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
 * RoleBasedScopeValidationHandler
 */
public class RoleBasedScopeValidationHandler implements ScopeValidationHandler {

    private static final Log LOG = LogFactory.getLog(DefaultOAuth2ScopeValidator.class);

    @Override
    public boolean canHandle(ScopeValidationContext scopeValidationContext) {

        return getPolicyID().equals(scopeValidationContext.getPolicyId())
                && !OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(scopeValidationContext.getGrantType());
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                       ScopeValidationContext scopeValidationContext)
            throws ScopeValidationHandlerException {

        List<String> userRoles = getUserRoles(scopeValidationContext.getAuthenticatedUser(),
                scopeValidationContext.getAppId());
        List<String> associatedScopes = getAssociatedScopesForRoles(userRoles,
                scopeValidationContext.getAuthenticatedUser().getTenantDomain());
        List<String> filteredScopes = appAuthorizedScopes.stream().filter(associatedScopes::contains)
                .collect(Collectors.toList());
        return requestedScopes.stream().filter(filteredScopes::contains).collect(Collectors.toList());
    }

    private List<String> getAssociatedScopesForRoles(List<String> roles, String tenantDomain)
            throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getPermissionListOfRoles(roles, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving scope list of roles : "
                    + StringUtils.join(roles, ",") + "tenant domain : " + tenantDomain, e);
        }
    }

    private List<String> getUserRoles(AuthenticatedUser authenticatedUser, String appId)
            throws ScopeValidationHandlerException {

        List<String> roleIds = new ArrayList<>();
        // Get role id list of the user.
        try {
            List<String> roleIdsOfUser = getRoleIdsOfUser(authenticatedUser.getUserId(),
                    authenticatedUser.getTenantDomain());
            if (!roleIdsOfUser.isEmpty()) {
                roleIds.addAll(roleIdsOfUser);
            }
        } catch (UserIdNotFoundException e) {
            throw new ScopeValidationHandlerException("Error while resolving user id of user", e);
        }
        // Get groups of the user.
        List<String> groups = getUserGroups(authenticatedUser);
        if (groups.isEmpty()) {
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
        if (!roleIds.isEmpty()) {
            return getFilteredRoleIds(roleIds, appId, authenticatedUser.getTenantDomain());
        }
        return new ArrayList<>();
    }

    private List<String> getFilteredRoleIds(List<String> roleId, String appId, String tenantDomain)
            throws ScopeValidationHandlerException {

        List<String> rolesAssociatedWithApp = getRoleIdsAssociatedWithApp(appId, tenantDomain);
        return roleId.stream().distinct().filter(rolesAssociatedWithApp::contains).collect(Collectors.toList());
    }

    private List<String> getRoleIdsAssociatedWithApp(String appId, String tenantDomain)
            throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getApplicationMgtService()
                    .getAssociatedRolesOfApplication(appId, tenantDomain).stream().map(RoleV2::getId)
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (IdentityApplicationManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving role id list of app : " + appId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    private List<String> getRoleIdsOfUser(String userId, String tenantDomain) throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfUser(userId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving role id list of user : " + userId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    private List<String> getRoleIdsOfGroups(List<String> groups, String tenantDomain)
            throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfGroups(groups, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving role id list of groups : "
                    + StringUtils.join(groups, ",") + "tenant domain : " + tenantDomain, e);
        }
    }

    private List<String> getRoleIdsOfIdpGroups(List<String> groups, String tenantDomain)
            throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getRoleManagementServiceV2()
                    .getRoleIdListOfIdpGroups(groups, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving role id list of groups : "
                    + StringUtils.join(groups, ",") + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get the groups of the authenticated user.
     *
     * @param authenticatedUser  Authenticated user.
     * @return - Groups of the user.
     */
    private List<String> getUserGroups(AuthenticatedUser authenticatedUser)
            throws ScopeValidationHandlerException {

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
            throw new ScopeValidationHandlerException(e.getMessage(), e);
        } catch (UserStoreException e) {
            if (isDoGetGroupListOfUserNotImplemented(e)) {
                return userGroups;
            }
            throw new ScopeValidationHandlerException(e.getMessage(), e);
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
    private List<String> getUserIdpGroups(AuthenticatedUser authenticatedUser)
            throws ScopeValidationHandlerException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started group fetching for scope validation.");
        }
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
     * @throws ScopeValidationHandlerException Exception thrown when getting the identity provider.
     */
    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain)
            throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getIdpManager().getIdPByName(idpName, tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving idp by idp name : " + idpName, e);
        }
    }


    /**
     * Check if the UserStoreException occurred due to the doGetGroupListOfUser method not being implemented.
     *
     * @param e UserStoreException.
     * @return true if the UserStoreException was caused by the doGetGroupListOfUser method not being implemented,
     * false otherwise.
     */
    private boolean isDoGetGroupListOfUserNotImplemented(UserStoreException e) {

        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof NotImplementedException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    @Override
    public String getPolicyID() {

        return "RBAC";
    }

    @Override
    public String getName() {

        return "RoleBasedScopeValidationHandler";
    }
}
