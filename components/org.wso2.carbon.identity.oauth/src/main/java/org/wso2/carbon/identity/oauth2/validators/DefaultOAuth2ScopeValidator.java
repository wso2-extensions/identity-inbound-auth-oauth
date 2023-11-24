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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceMgtException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AuthorizedScopes;
import org.wso2.carbon.identity.application.common.model.Scope;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.SharedAppResolveDAO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.INTERNAL_LOGIN_SCOPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.OPENID_SCOPE;

/**
 * Default oauth2 scope validator which validate application authorized scopes.
 */
public class DefaultOAuth2ScopeValidator {

    public static final String CLIENT_TYPE = "oauth2";

    private static final Log LOG = LogFactory.getLog(DefaultOAuth2ScopeValidator.class);

    private static final String NO_POLICY_HANDLER = "NoPolicyScopeValidationHandler";

    /**
     * Validate scope.
     *
     * @param authzReqMessageContext AuthzReqMessageContext.
     * @return List of scopes.
     * @throws IdentityOAuth2Exception Error when performing the scope validation.
     */
    public List<String> validateScope(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (isScopesEmpty(authzReqMessageContext.getAuthorizationReqDTO().getScopes())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested scope list is empty. Therefore, default OAuth2 scope validation is skipped.");
            }
            return new ArrayList<>();
        }
        List<String> requestedScopes = Arrays.asList(authzReqMessageContext.getAuthorizationReqDTO().getScopes());
        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String appId = getApplicationId(clientId, tenantDomain);
        // When user is not accessing the resident organization, resolve the application id from the shared app table.
        if (!AuthzUtil.isUserAccessingResidentOrganization(authzReqMessageContext.getAuthorizationReqDTO().getUser())) {
            String orgId = authzReqMessageContext.getAuthorizationReqDTO().getUser().getAccessingOrganization();
            String appResideOrgId = resolveOrgIdByTenantDomain(tenantDomain);
            appId = SharedAppResolveDAO.resolveSharedApplication(appResideOrgId, appId, orgId);
        }
        List<String> authorizedScopes = getAuthorizedScopes(requestedScopes, authzReqMessageContext
                        .getAuthorizationReqDTO().getUser(), appId, null, tenantDomain);
        handleInternalLoginScope(requestedScopes, authorizedScopes);
        removeRegisteredScopes(authzReqMessageContext);
        return authorizedScopes;
    }

    /**
     * Validate scope.
     *
     * @param tokenReqMessageContext tokenReqMessageContext.
     * @return List of scopes.
     * @throws IdentityOAuth2Exception Error when performing the scope validation.
     */
    public List<String> validateScope(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (isScopesEmpty(tokenReqMessageContext.getScope())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested scope list is empty. Therefore, default OAuth2 scope validation is skipped.");
            }
            return new ArrayList<>();
        }
        List<String> requestedScopes = Arrays.asList(tokenReqMessageContext.getScope());
        String tenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        String appId = getApplicationId(clientId, tenantDomain);
        // When user is not accessing the resident organization, resolve the application id from the shared app table.
        if (!AuthzUtil.isUserAccessingResidentOrganization(tokenReqMessageContext.getAuthorizedUser())) {
            String orgId = tokenReqMessageContext.getAuthorizedUser().getAccessingOrganization();
            String appResideOrgId = resolveOrgIdByTenantDomain(tenantDomain);
            appId = SharedAppResolveDAO.resolveSharedApplication(appResideOrgId, appId, orgId);
        }
        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        List<String> authorizedScopes = getAuthorizedScopes(requestedScopes, tokenReqMessageContext
                .getAuthorizedUser(), appId, grantType, tenantDomain);
        removeRegisteredScopes(tokenReqMessageContext);
        handleInternalLoginScope(requestedScopes, authorizedScopes);
        if (OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(grantType)
                || OAuthConstants.GrantTypes.ORGANIZATION_SWITCH_CC.equals(grantType)) {
            authorizedScopes.remove(INTERNAL_LOGIN_SCOPE);
            authorizedScopes.remove(OPENID_SCOPE);
        }
        return authorizedScopes;
    }

    /**
     * Get authorized scopes.
     *
     * @param requestedScopes   Requested scopes.
     * @param authenticatedUser Authenticated user.
     * @param appId             App ID.
     * @param grantType         Grant type.
     * @param tenantDomain      Tenant domain.
     * @return Authorized scopes.
     * @throws IdentityOAuth2Exception if any error occurs during getting authorized scopes.
     */
    private List<String> getAuthorizedScopes(List<String> requestedScopes, AuthenticatedUser authenticatedUser,
                                             String appId, String grantType, String tenantDomain)
            throws IdentityOAuth2Exception {

        // Filter OIDC scopes and add to approved scopes list.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Filtering OIDC scopes from requested scopes: " + StringUtils.join(requestedScopes, " "));
        }
        Set<String> requestedOIDCScopes = getRequestedOIDCScopes(tenantDomain, requestedScopes);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Requested OIDC scopes : " + StringUtils.join(requestedOIDCScopes, " "));
        }
        /* Here, we add the user-requested OIDC scopes to the approved scope list and remove from requested scope list
        before we pass the scopes to the authorization service. Otherwise, the OIDC scopes will be dropped from
        the approved scope list. */
        List<String> approvedScopes = new ArrayList<>(requestedOIDCScopes);
        requestedScopes = removeOIDCScopes(requestedScopes, requestedOIDCScopes);
        if (requestedScopes.contains(SYSTEM_SCOPE)) {
            requestedScopes.addAll(getInternalScopes(tenantDomain));
            requestedScopes.addAll(getConsoleScopes(tenantDomain));
        }
        List<AuthorizedScopes> authorizedScopesList = getAuthorizedScopes(appId, tenantDomain);
        List<ScopeValidationHandler> scopeValidationHandlers =
                OAuthComponentServiceHolder.getInstance().getScopeValidationHandlers();
        Map<String, List<String>> validatedScopesByHandler = new HashMap<>();
        for (AuthorizedScopes authorizedScopes : authorizedScopesList) {
            String policyId = authorizedScopes.getPolicyId();
            ScopeValidationContext scopeValidationContext = new ScopeValidationContext();
            scopeValidationContext.setAuthenticatedUser(authenticatedUser);
            scopeValidationContext.setAppId(appId);
            scopeValidationContext.setPolicyId(policyId);
            scopeValidationContext.setGrantType(grantType);
            for (ScopeValidationHandler scopeValidationHandler : scopeValidationHandlers) {
                if (scopeValidationHandler.canHandle(scopeValidationContext)) {
                    scopeValidationContext.setValidatedScopesByHandler(validatedScopesByHandler);
                    List<String> validatedScopes;
                    try {
                        validatedScopes = scopeValidationHandler.validateScopes(requestedScopes,
                                authorizedScopes.getScopes(), scopeValidationContext);
                    } catch (ScopeValidationHandlerException e) {
                        throw new IdentityOAuth2Exception("Error while validating policies roles from " +
                                "authorization service.", e);
                    }
                    validatedScopesByHandler.put(scopeValidationHandler.getName(), validatedScopes);
                }
            }
        }

        // If "NoPolicyScopeValidationHandler" exists, add all its scopes to the result
        Set<String> scopes = new HashSet<>(validatedScopesByHandler.getOrDefault(NO_POLICY_HANDLER,
                Collections.emptyList()));

        // Separate "NoPolicyScopeValidationHandler" and get the intersection of the rest of the scopes validated
        // by other validators
        List<List<String>> otherHandlerScopes = new ArrayList<>(validatedScopesByHandler.values());
        otherHandlerScopes.remove(validatedScopesByHandler.get(NO_POLICY_HANDLER));

        List<String> intersection = new ArrayList<>();
        if (!otherHandlerScopes.isEmpty()) {
            intersection = otherHandlerScopes.get(0);
            for (int i = 1; i < otherHandlerScopes.size(); i++) {
                intersection = intersection.stream().filter(otherHandlerScopes.get(i)::contains)
                        .collect(Collectors.toList());
            }
        }
        scopes.addAll(intersection);
        approvedScopes.addAll(scopes);
        return approvedScopes;
    }

    /**
     * Get the authorized scopes for the given appId and tenant domain.
     *
     * @param appId        App id.
     * @param tenantDomain Tenant domain.
     * @return Authorized scopes.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving authorized scopes for app.
     */
    private List<AuthorizedScopes> getAuthorizedScopes(String appId, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance()
                    .getAuthorizedAPIManagementService().getAuthorizedScopes(appId, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving authorized scopes for app : " + appId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    /**
     * Get the internal scopes.
     *
     * @param tenantDomain Tenant domain.
     * @return Internal scopes.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving internal scopes for tenant domain.
     */
    private List<String> getInternalScopes(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            List<Scope> scopes = OAuth2ServiceComponentHolder.getInstance()
                    .getApiResourceManager().getScopesByTenantDomain(tenantDomain, "name sw internal_");
            return scopes.stream().map(Scope::getName).collect(Collectors.toCollection(ArrayList::new));
        } catch (APIResourceMgtException e) {
            throw new IdentityOAuth2Exception("Error while retrieving internal scopes for tenant domain : "
                    + tenantDomain, e);
        }
    }

    /**
     * Get the Console scopes.
     *
     * @param tenantDomain Tenant domain.
     * @return Console scopes.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving console scopes for tenant domain.
     */
    private List<String> getConsoleScopes(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            List<Scope> scopes = OAuth2ServiceComponentHolder.getInstance()
                    .getApiResourceManager().getScopesByTenantDomain(tenantDomain, "name sw console:");
            return scopes.stream().map(Scope::getName).collect(Collectors.toCollection(ArrayList::new));
        } catch (APIResourceMgtException e) {
            throw new IdentityOAuth2Exception("Error while retrieving console scopes for tenant domain : "
                    + tenantDomain, e);
        }
    }

    /**
     * Get the registered scopes.
     *
     * @param tenantDomain Tenant domain.
     * @return Registered scopes.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving internal scopes for tenant domain.
     */
    private List<String> getRegisteredScopes(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            List<Scope> scopes = OAuth2ServiceComponentHolder.getInstance()
                    .getApiResourceManager().getScopesByTenantDomain(tenantDomain, null);
            return scopes.stream().map(Scope::getName).collect(Collectors.toCollection(ArrayList::new));
        } catch (APIResourceMgtException e) {
            throw new IdentityOAuth2Exception("Error while retrieving internal scopes for tenant domain : "
                    + tenantDomain, e);
        }
    }

    /**
     * Remove registered scopes.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @throws IdentityOAuth2Exception Error while remove registered scopes.
     */
    private void removeRegisteredScopes(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (authzReqMessageContext.getAuthorizationReqDTO().getScopes() == null) {
            return;
        }
        List<String> registeredScopes = getRegisteredScopes(authzReqMessageContext.getAuthorizationReqDTO()
                .getTenantDomain());
        List<String> scopes = new ArrayList<>();
        for (String scope : authzReqMessageContext.getAuthorizationReqDTO().getScopes()) {
            if (!registeredScopes.contains(scope)) {
                scopes.add(scope);
            }
        }
        authzReqMessageContext.getAuthorizationReqDTO().setScopes(scopes.toArray(new String[0]));
    }

    /**
     * Remove registered scopes.
     *
     * @param tokenReqMessageContext OAuthTokenReqMessageContext
     * @throws IdentityOAuth2Exception Error while remove registered scopes.
     */
    private void removeRegisteredScopes(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (tokenReqMessageContext.getScope() == null) {
            return;
        }
        List<String> registeredScopes = getRegisteredScopes(tokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getTenantDomain());
        List<String> scopes = new ArrayList<>();
        for (String scope : tokenReqMessageContext.getScope()) {
            if (!registeredScopes.contains(scope)) {
                scopes.add(scope);
            }
        }
        tokenReqMessageContext.setScope(scopes.toArray(new String[0]));
    }

    /**
     * Get the requested OIDC scopes
     *
     * @param tenantDomain    Tenant domain.
     * @param requestedScopes Requested scopes.
     * @return Requested OIDC scopes.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving oidc scopes.
     */
    private Set<String> getRequestedOIDCScopes(String tenantDomain, List<String> requestedScopes)
            throws IdentityOAuth2Exception {

        OAuthAdminServiceImpl oAuthAdminServiceImpl = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService();
        try {
            List<String> oidcScopes = oAuthAdminServiceImpl.getRegisteredOIDCScope(tenantDomain);
            return requestedScopes.stream().distinct().filter(oidcScopes::contains).collect(Collectors.toSet());
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityOAuth2Exception("Error while retrieving oidc scopes for tenant domain : "
                    + tenantDomain, e);
        }
    }

    /**
     * Remove OIDC scopes from the list.
     *
     * @param requestedScopes Requested scopes.
     * @param oidcScopes      OIDC scopes.
     * @return List of scopes.
     */
    private List<String> removeOIDCScopes(List<String> requestedScopes, Set<String> oidcScopes) {

        return requestedScopes.stream().distinct().filter(s -> !oidcScopes.contains(s)).collect(Collectors.toList());
    }

    /**
     * Get the application resource id for the given client id
     *
     * @param clientId   Client Id.
     * @param tenantName Tenant name.
     * @return Application resource id.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving application resource id.
     */
    private String getApplicationId(String clientId, String tenantName) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            return applicationMgtService.getApplicationResourceIDByInboundKey(clientId, CLIENT_TYPE, tenantName);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving application resource id for client : " +
                    clientId + " tenant : " + tenantName, e);
        }
    }

    /**
     * Checks if the scopes list is empty
     *
     * @param scopes Scopes list
     * @return true if scopes list is empty
     */
    private boolean isScopesEmpty(String[] scopes) {

        return ArrayUtils.isEmpty(scopes);
    }

    private String resolveOrgIdByTenantDomain(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error occured while resolving organization for tenant domain: "
                    + tenantDomain, e);
        }
    }

    /**
     * This is to persist the previous behaviour with the "internal_login" scope.
     *
     * @param requestedScopes requested scopes.
     * @param authorizedScopes authorized scopes.
     */
    private static void handleInternalLoginScope(List<String> requestedScopes, List<String> authorizedScopes) {

        if ((requestedScopes.contains(SYSTEM_SCOPE) || requestedScopes.contains(INTERNAL_LOGIN_SCOPE))
                && !authorizedScopes.contains(INTERNAL_LOGIN_SCOPE)) {
            authorizedScopes.add(INTERNAL_LOGIN_SCOPE);
        }
    }

}
