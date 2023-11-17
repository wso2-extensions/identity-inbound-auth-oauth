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

package org.wso2.carbon.identity.oauth2.validators.validationhandler.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Role based scope validation handler validate scopes based on users roles.
 */
public class RoleBasedScopeValidationHandler implements ScopeValidationHandler {

    private static final Log LOG = LogFactory.getLog(DefaultOAuth2ScopeValidator.class);

    @Override
    public boolean canHandle(ScopeValidationContext scopeValidationContext) {

        return getPolicyID().equals(scopeValidationContext.getPolicyId())
                && !OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(scopeValidationContext.getGrantType())
                && !OAuthConstants.GrantTypes.ORGANIZATION_SWITCH_CC.equals(scopeValidationContext.getGrantType());
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
        } catch (IdentityOAuth2Exception e) {
            throw new ScopeValidationHandlerException("Error while validation scope with RBAC Scope Validation " +
                    "handler", e);
        }
    }

    /**
     * Get the filtered role ids.
     *
     * @param roleId Role id list.
     * @param appId App id.
     * @param tenantDomain Tenant domain.
     * @return Filtered role ids.
     * @throws ScopeValidationHandlerException if an error occurs while retrieving filtered role id list.
     */
    private List<String> getFilteredRoleIds(List<String> roleId, String appId, String tenantDomain)
            throws ScopeValidationHandlerException {

        List<String> rolesAssociatedWithApp = getRoleIdsAssociatedWithApp(appId, tenantDomain);
        return roleId.stream().distinct().filter(rolesAssociatedWithApp::contains).collect(Collectors.toList());
    }

    /**
     * Get the role ids associated with app.
     *
     * @param appId App id.
     * @param tenantDomain Tenant domain.
     * @return Role ids associated with app.
     * @throws ScopeValidationHandlerException if an error occurs while retrieving role id list of app.
     */
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
