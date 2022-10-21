/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeBindingCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeBindingCacheKey;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;

/**
 * The JDBC Scope Validation implementation. This validates the Resource's scope (stored in IDN_OAUTH2_RESOURCE_SCOPE)
 * against the Access Token's scopes.
 */
public class JDBCPermissionBasedInternalScopeValidator {

    private static final String PERMISSION_ROOT = "/permission";

    private static final Log log = LogFactory.getLog(JDBCPermissionBasedInternalScopeValidator.class);
    private static final String PERMISSION_BINDING_TYPE = "PERMISSION";
    private static final String ROOT = "/";
    private static final String ADMIN_PERMISSION_ROOT = "/permission/admin";
    private static final String EVERYONE_PERMISSION = "everyone_permission";
    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();

    /**
     * Execute Internal scope Validation.
     * @param tokReqMsgCtx Oauth token request message.
     * @return array of validated scopes.
     */
    public String[] validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) {

        // filter internal scopes
        String[] requestedScopes = Oauth2ScopeUtils.getRequestedScopes(tokReqMsgCtx.getScope());
        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }
        List<Scope> userAllowedScopes = getUserAllowedScopes(tokReqMsgCtx.getAuthorizedUser(), requestedScopes,
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
        String[] userAllowedScopesAsArray = getScopes(userAllowedScopes);
        if (ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
            return userAllowedScopesAsArray;
        }

        List<String> scopesToRespond = new ArrayList<>();
        for (String scope : requestedScopes) {
            if (ArrayUtils.contains(userAllowedScopesAsArray, scope)) {
                scopesToRespond.add(scope);
            }
        }
        return scopesToRespond.toArray(new String[0]);
    }

    /**
     * Execute Internal Scope Validation.
     * @param authzReqMessageContext OAuth authorization request message.
     * @return array of validated scopes.
     */
    public String[] validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) {

        // Remove openid scope from the list if available
        String[] requestedScopes = Oauth2ScopeUtils.getRequestedScopes(authzReqMessageContext.getAuthorizationReqDTO
                ().getScopes());
        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }
        return validateScope(requestedScopes, authzReqMessageContext.getAuthorizationReqDTO().getUser(),
                authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
    }

    /**
     * Execute Internal Scope Validation.
     * @param requestedScopes Array of scopes that needs to be validated.
     * @param authenticatedUser Authenticated user.
     * @param clientId ID of the client.
     * @return Array of validated scopes.
     */
    public String[] validateScope(String[] requestedScopes, AuthenticatedUser authenticatedUser, String clientId) {

        List<Scope> userAllowedScopes = getUserAllowedScopes(authenticatedUser, requestedScopes, clientId);

        String[] userAllowedScopesAsArray = getScopes(userAllowedScopes);
        if (ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
            return userAllowedScopesAsArray;
        }

        List<String> scopesToRespond = new ArrayList<>();
        for (String scope : requestedScopes) {
            if (ArrayUtils.contains(userAllowedScopesAsArray, scope)) {
                scopesToRespond.add(scope);
            }
        }
        return scopesToRespond.toArray(new String[0]);
    }

    private String[] getScopes(List<Scope> scopes) {

        return scopes.stream()
                .map(Scope::getName).toArray(String[]::new);
    }

    private List<Scope> getUserAllowedScopes(AuthenticatedUser authenticatedUser, String[] requestedScopes,
                                             String clientId) {
        List<Scope> userAllowedScopes = new ArrayList<>();

        try {
            if (requestedScopes == null) {
                return new ArrayList<>();
            }
            boolean isSystemScope = ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE);
            int tenantId = IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain());
            startTenantFlow(authenticatedUser.getTenantDomain(), tenantId);
            AuthorizationManager authorizationManager = OAuthComponentServiceHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId).getAuthorizationManager();
            String[] allowedUIResourcesForUser;
            /*
            Here we handle scope validation for federated user and local user separately.
            For local users - user store is used to get user roles.
            For federated user - get user roles from user attributes.
            Note that if there is association between a federated user and local user () 'Assert identity using
            mapped local subject identifier' flag will be set as true. So authenticated user will be associated
            local user not federated user.
             */
            if (authenticatedUser.isFederatedUser()) {
                /*
                There is a flow where 'Assert identity using mapped local subject identifier' flag enabled but the
                federated user doesn't have any association in localIDP, to handle this case we check for 'Assert
                identity using mapped local subject identifier' flag and get roles from userStore.
                 */
                if (isSPAlwaysSendMappedLocalSubjectId(clientId)) {
                    allowedUIResourcesForUser = getAllowedUIResourcesOfUser(authenticatedUser, authorizationManager);
                } else {
                    // Handle not account associated federated users.
                    allowedUIResourcesForUser =
                            getAllowedUIResourcesForNotAssociatedFederatedUser(authenticatedUser, authorizationManager);
                }
            } else {
                allowedUIResourcesForUser = getAllowedUIResourcesOfUser(authenticatedUser, authorizationManager);
            }
            Set<Scope> allScopes = getScopesOfPermissionType(tenantId);
            if (ArrayUtils.contains(allowedUIResourcesForUser, ROOT) || ArrayUtils.contains(allowedUIResourcesForUser,
                    PERMISSION_ROOT)) {
                return new ArrayList<>(allScopes);
            } else if (ArrayUtils.contains(allowedUIResourcesForUser, ADMIN_PERMISSION_ROOT)) {
                return new ArrayList<>(getAdminAllowedScopes(allScopes, requestedScopes));
            }

            for (Scope scope : allScopes) {
                if (!isSystemScope && !ArrayUtils.contains(requestedScopes, scope.getName())) {
                    continue;
                }
                List<ScopeBinding> bindings = scope.getScopeBindings();
                boolean isScopeAllowed = true;
                for (ScopeBinding scopeBinding : bindings) {
                    if (PERMISSION_BINDING_TYPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                        for (String binding : scopeBinding.getBindings()) {
                            boolean isAllowed = false;
                            for (String allowedScope : allowedUIResourcesForUser) {
                                if ((binding + "/").startsWith(allowedScope + "/")) {
                                    isAllowed = true;
                                    break;
                                }
                            }
                            if (!isAllowed) {
                                isScopeAllowed = false;
                                break;
                            }
                        }
                    }
                }

                if (isScopeAllowed) {
                    userAllowedScopes.add(scope);
                }
            }
        } catch (UserStoreException e) {
            log.error("Error while accessing Authorization Manager.", e);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while accessing identity provider manager.", e);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving oAuth2 scopes.", e);
        } catch (UserIdNotFoundException e) {
            log.error("User id not available for user: " + authenticatedUser.getLoggableUserId(), e);
        } finally {
            endTenantFlow();
        }
        return userAllowedScopes;
    }

    private boolean isSPAlwaysSendMappedLocalSubjectId(String clientId) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
        if (serviceProvider != null) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                return claimConfig.isAlwaysSendMappedLocalSubjectId();
            }
            throw new IdentityOAuth2Exception(
                    "Unable to find claim configuration for service provider of client id " + clientId);
        }
        throw new IdentityOAuth2Exception("Unable to find service provider for client id " + clientId);
    }

    /**
     * Method user to get list of federated users permissions using idp role mapping for not account associated
     * federated users.
     * @param authenticatedUser    FederatedAuthenticatedUser
     * @param authorizationManager AuthorizationManager
     * @return List of permissions
     * @throws UserStoreException      UserStoreException
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private String[] getAllowedUIResourcesForNotAssociatedFederatedUser(AuthenticatedUser authenticatedUser,
                                                                        AuthorizationManager authorizationManager)
            throws UserStoreException, IdentityOAuth2Exception {

        List<String> userRolesList = new ArrayList<>();
        List<String> allowedUIResourcesListForUser = new ArrayList<>();
        IdentityProvider identityProvider =
                OAuth2Util.getIdentityProvider(authenticatedUser.getFederatedIdPName(),
                        authenticatedUser.getTenantDomain());
        /*
        Values of Groups consists mapped local roles and Internal/everyone corresponding to
        authenticated user.
        Role mapping consists mapped federated roles with local roles corresponding to IDP.
        By cross checking role mapped local roles and values of groups we can filter valid local roles which mapped
        to a federated role of authenticated user.
         */
        List<String> valuesOfGroups = getValuesOfGroupsFromUserAttributes(authenticatedUser.getUserAttributes());
        if (CollectionUtils.isNotEmpty(valuesOfGroups)) {
            for (RoleMapping roleMapping : identityProvider.getPermissionAndRoleConfig().getRoleMappings()) {
                if (roleMapping != null && roleMapping.getLocalRole() != null) {
                    if (valuesOfGroups.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        userRolesList.add(roleMapping.getLocalRole().getLocalRoleName());
                    }
                }
            }
        }
        // Loop through each local role and get permissions.
        for (String userRole : userRolesList) {
            for (String allowedUIResource : authorizationManager.getAllowedUIResourcesForRole(userRole, "/")) {
                if (!allowedUIResourcesListForUser.contains(allowedUIResource)) {
                    allowedUIResourcesListForUser.add(allowedUIResource);
                }
            }
        }
        // Add everyone permission to allowed permission.
        allowedUIResourcesListForUser.add(EVERYONE_PERMISSION);

        return allowedUIResourcesListForUser.toArray(new String[0]);
    }

    /**
     * Get groups params Roles from User attributes.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private List<String> getValuesOfGroupsFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if (entry.getKey().getRemoteClaim() != null) {
                    if (StringUtils.equals(entry.getKey().getRemoteClaim().getClaimUri(), OAuth2Constants.GROUPS)) {
                        return Arrays.asList(entry.getValue().split(Pattern.quote(ATTRIBUTE_SEPARATOR)));
                    }
                }
            }
        }
        return null;
    }

    private String[] getAllowedUIResourcesOfUser(AuthenticatedUser authenticatedUser,
                                                 AuthorizationManager authorizationManager)
            throws UserStoreException, UserIdNotFoundException {

        String username = authenticatedUser.getUserName();
        if (username == null) {
            username = OAuth2Util
                    .resolveUsernameFromUserId(authenticatedUser.getTenantDomain(), authenticatedUser.getUserId());
        }
        if (StringUtils.isNotEmpty(authenticatedUser.getUserStoreDomain())) {
            username = UserCoreUtil.addDomainToName(username, authenticatedUser.getUserStoreDomain());
        }
        String[] allowedUIResourcesForUser =
                authorizationManager.getAllowedUIResourcesForUser(username, "/");
        return (String[]) ArrayUtils.add(allowedUIResourcesForUser, EVERYONE_PERMISSION);
    }

    private Set<Scope> getScopesOfPermissionType(int tenantId) throws IdentityOAuth2ScopeServerException {

        if (Oauth2ScopeUtils.isSystemLevelInternalSystemScopeManagementEnabled()) {
            List<Scope> oauthScopeBinding = OAuth2ServiceComponentHolder.getInstance().getOauthScopeBinding();
            return new HashSet<>(oauthScopeBinding);
        }
        Scope[] scopesFromCache = OAuthScopeBindingCache.getInstance()
                .getValueFromCache(new OAuthScopeBindingCacheKey(PERMISSION_BINDING_TYPE), tenantId);
        Set<Scope> allScopes;
        if (scopesFromCache != null) {
            allScopes = Arrays.stream(scopesFromCache).collect(Collectors.toSet());
        } else {
            allScopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopes(tenantId,
                    PERMISSION_BINDING_TYPE);
            if (CollectionUtils.isNotEmpty(allScopes)) {
                OAuthScopeBindingCache.getInstance().addToCache(new OAuthScopeBindingCacheKey(PERMISSION_BINDING_TYPE
                ), allScopes.toArray(new Scope[0]), tenantId);
            }
        }
        return allScopes;
    }

    private void startTenantFlow(String tenantDomain, int tenantId) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
    }

    private void endTenantFlow() {

        PrivilegedCarbonContext.endTenantFlow();
    }

    private Set<Scope> getAdminAllowedScopes(Set<Scope> allScopes, String[] requestedScopes) {

        Set<Scope> adminAllowedScopes = new HashSet<>(allScopes);
        for (Scope scope : allScopes) {
            if (!ArrayUtils.contains(requestedScopes, scope.getName())) {
                continue;
            }
            List<ScopeBinding> scopeBindings = scope.getScopeBindings();
            for (ScopeBinding scopeBinding : scopeBindings) {
                if (PERMISSION_BINDING_TYPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                    List<String> bindings = scopeBinding.getBindings();
                    for (String binding : bindings) {
                        if (!binding.startsWith(ADMIN_PERMISSION_ROOT) && !binding.equals(EVERYONE_PERMISSION)) {
                            adminAllowedScopes.remove(scope);
                            break;
                        }
                    }
                }
            }
        }
        return adminAllowedScopes;
    }
}
