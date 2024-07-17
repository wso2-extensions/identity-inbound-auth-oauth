/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.validators.validationhandler.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerClientException;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Role based scope validation handler validate scopes based on users roles.
 */
public class RoleBasedScopeValidationHandler implements ScopeValidationHandler {

    private static final Log LOG = LogFactory.getLog(RoleBasedScopeValidationHandler.class);

    @Override
    public boolean canHandle(ScopeValidationContext scopeValidationContext) {

        return getPolicyID().equals(scopeValidationContext.getPolicyId())
                && !OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(scopeValidationContext.getGrantType()) &&
                !(OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(scopeValidationContext.getGrantType()) &&
                        OAuthConstants.UserType.APPLICATION.equals(scopeValidationContext.getUserType()));
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                       ScopeValidationContext scopeValidationContext)
            throws ScopeValidationHandlerException {

        try {
            List<String> userRoles = AuthzUtil.getUserRoles(scopeValidationContext.getAuthenticatedUser(),
                    scopeValidationContext.getAppId());
            if (userRoles.isEmpty()) {
                return new ArrayList<>();
            }
            String tenantDomain = scopeValidationContext.getAuthenticatedUser().getTenantDomain();
            // When user is not accessing the resident organization, resolve the tenant domain of the accessing org.
            if (!AuthzUtil.isUserAccessingResidentOrganization(scopeValidationContext.getAuthenticatedUser())) {
                tenantDomain = resolveTenantDomainByOrgId(scopeValidationContext.getAuthenticatedUser()
                        .getAccessingOrganization());
            }
            List<String> filteredRoleIds = getFilteredRoleIds(userRoles, scopeValidationContext.getAppId(),
                    tenantDomain);
            if (filteredRoleIds.isEmpty()) {
                return new ArrayList<>();
            }
            List<String> associatedScopes = AuthzUtil.getAssociatedScopesForRoles(filteredRoleIds, tenantDomain);
            /*
            TODO: Refactor this to drop internal_ scopes when getting associated scopes for roles.
            When user is not accessing the resident organization, retain only the internal_org_ scopes
            from system scopes.
            */
            if (StringUtils.isNotBlank(scopeValidationContext.getAuthenticatedUser().getAccessingOrganization())) {
                List<String> internalOrgScopes = associatedScopes.stream()
                        .filter(scope -> scope.startsWith(Oauth2ScopeConstants.INTERNAL_ORG_SCOPE_PREFIX))
                        .collect(Collectors.toList());
                associatedScopes.removeIf(scope -> scope.startsWith(Oauth2ScopeConstants.INTERNAL_SCOPE_PREFIX));
                associatedScopes.addAll(internalOrgScopes);
            }
            List<String> filteredScopes = appAuthorizedScopes.stream().filter(associatedScopes::contains)
                    .collect(Collectors.toList());
            return requestedScopes.stream().filter(filteredScopes::contains).collect(Collectors.toList());
        } catch (IdentityOAuth2ClientException e) {
            throw new ScopeValidationHandlerClientException(e.getMessage(), e);
        } catch (IdentityOAuth2Exception | IdentityRoleManagementException e) {
            throw new ScopeValidationHandlerException("Error while validation scope with RBAC Scope Validation " +
                    "handler", e);
        }
    }

    /**
     * Get the filtered role ids.
     *
     * @param roleIds Role id list.
     * @param appId App id.
     * @param tenantDomain tenant domain.
     * @return Filtered role ids.
     * @throws ScopeValidationHandlerException if an error occurs while retrieving filtered role id list.
     */
    private List<String> getFilteredRoleIds(List<String> roleIds, String appId, String tenantDomain)
            throws ScopeValidationHandlerException, IdentityOAuth2Exception, IdentityRoleManagementException {

        List<String> rolesAssociatedWithApp;
        String allowedAudience = getApplicationAllowedAudience(appId, tenantDomain);

        if (RoleConstants.APPLICATION.equalsIgnoreCase(allowedAudience)) {
            rolesAssociatedWithApp = getRoleIdsAssociatedWithApp(appId);
        } else {
             /*If the application allowed audience is organization, associate all organization roles with the
             application*/
            rolesAssociatedWithApp = getAllOrganizationRoles(tenantDomain).stream()
                    .map(RoleBasicInfo::getId)
                    .collect(Collectors.toList());
        }

        return roleIds.stream()
                .distinct()
                .filter(rolesAssociatedWithApp::contains)
                .collect(Collectors.toList());
    }

    private List<RoleBasicInfo> getAllOrganizationRoles(String tenantDomain) throws IdentityRoleManagementException {

        RoleManagementService roleManagementService = OAuthComponentServiceHolder.getInstance()
                .getRoleV2ManagementService();
        List<RoleBasicInfo> chunkOfRoles;
        int offset = 1;
        int maximumPage = IdentityUtil.getMaximumItemPerPage();
        List<RoleBasicInfo> allRoles = new ArrayList<>();
        if (roleManagementService != null) {
            do {
                chunkOfRoles = roleManagementService.getRoles(RoleConstants.AUDIENCE + " " +
                                RoleConstants.EQ + " " + RoleConstants.ORGANIZATION, maximumPage, offset, null,
                        null, tenantDomain);
                if (!chunkOfRoles.isEmpty()) {
                    allRoles.addAll(chunkOfRoles);
                    offset += chunkOfRoles.size(); // Move to the next chunk
                }
            } while (chunkOfRoles.size() == maximumPage);
        }
        return allRoles;
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
            throw new IdentityOAuth2Exception("Error while retrieving allowed audience of application : " + appId , e);
        }
    }

    /**
     * Get the role ids associated with app.
     *
     * @param appId App id.
     * @return Role ids associated with app.
     * @throws ScopeValidationHandlerException if an error occurs while retrieving role id list of app.
     */
    private List<String> getRoleIdsAssociatedWithApp(String appId) throws ScopeValidationHandlerException {

        ApplicationManagementService applicationManagementService =
                OAuthComponentServiceHolder.getInstance().getApplicationManagementService();
        try {
            int applicationTenantId = applicationManagementService.getTenantIdByApp(appId);
            return applicationManagementService.getAssociatedRolesOfApplication(appId,
                            IdentityTenantUtil.getTenantDomain(applicationTenantId)).stream()
                    .map(RoleV2::getId).collect(Collectors.toCollection(ArrayList::new));
        } catch (IdentityApplicationManagementException e) {
            throw new ScopeValidationHandlerException("Error while retrieving role id list of app : " + appId, e);
        }
    }

    @Override
    public String getPolicyID() {

        return "RBAC";
    }

    @Override
    public String getName() {

        return "RoleBasedScopeValidationHandler";
    }

    private String resolveTenantDomainByOrgId(String organizationId) throws ScopeValidationHandlerException {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(organizationId);
        } catch (OrganizationManagementException e) {
            throw new ScopeValidationHandlerException("Error while resolving the tenant domain of the org ID: " +
                    organizationId, e);
        }
    }
}
