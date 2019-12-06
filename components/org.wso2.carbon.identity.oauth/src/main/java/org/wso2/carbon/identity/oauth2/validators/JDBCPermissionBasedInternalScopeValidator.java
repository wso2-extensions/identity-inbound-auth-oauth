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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    private static final String INTERNAL_SCOPE_PREFIX = "internal_";

    public String[] validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) {

        // filter internal scopes
        String[] requestedScopes = getRequestedScopes(tokReqMsgCtx.getScope());
        List<Scope> userAllowedScopes = getUserAllowedScopes(tokReqMsgCtx.getAuthorizedUser(), requestedScopes);
        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }

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

    public String[] validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) {

        // Remove openid scope from the list if available
        String[] requestedScopes = getRequestedScopes(authzReqMessageContext.getAuthorizationReqDTO
                ().getScopes());
        List<Scope> userAllowedScopes =
                getUserAllowedScopes(authzReqMessageContext.getAuthorizationReqDTO().getUser(), requestedScopes);
        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }

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

    private String[] getRequestedScopes(String[] scopes) {

        List<String> requestedScopes = new ArrayList<>();
        if (scopes == null) {
            return null;
        }
        for (String scope : scopes) {
            if (scope.startsWith(INTERNAL_SCOPE_PREFIX) || scope.equalsIgnoreCase(SYSTEM_SCOPE)) {
                requestedScopes.add(scope);
            }
        }
        return requestedScopes.toArray(new String[0]);
    }

    private String[] getScopes(List<Scope> scopes) {

        return scopes.stream()
                .map(Scope::getName).toArray(String[]::new);
    }

    private List<Scope> getUserAllowedScopes(AuthenticatedUser authenticatedUser, String[] requestedScopes) {

        List<Scope> userAllowedScopes = new ArrayList<>();

        try {
            if (requestedScopes == null) {
                return new ArrayList<>();
            }
            int tenantId = IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain());
            startTenantFlow(authenticatedUser.getTenantDomain(), tenantId);
            AuthorizationManager authorizationManager = OAuthComponentServiceHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId).getAuthorizationManager();
            String[] allowedUIResourcesForUser = authorizationManager.getAllowedUIResourcesForUser(IdentityUtil
                    .addDomainToName(authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), "/");
            Set<Scope> allScopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopes(tenantId,
                    PERMISSION_BINDING_TYPE);
            if (ArrayUtils.contains(allowedUIResourcesForUser, ROOT) || ArrayUtils.contains(allowedUIResourcesForUser,
                    PERMISSION_ROOT)) {
                return new ArrayList<>(allScopes);
            } else if (ArrayUtils.contains(allowedUIResourcesForUser, ADMIN_PERMISSION_ROOT)) {
                return new ArrayList<>(getAdminAllowedScopes(allScopes, requestedScopes));
            }

            for (Scope scope : allScopes) {
                if (!ArrayUtils.contains(requestedScopes, scope.getName())) {
                    continue;
                }
                List<ScopeBinding> bindings = scope.getScopeBindings();
                boolean isScopeAllowed = true;
                for (ScopeBinding scopeBinding : bindings) {
                    if (PERMISSION_BINDING_TYPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                        for (String binding : scopeBinding.getBindings()) {
                            if (!ArrayUtils.contains(allowedUIResourcesForUser, binding)) {
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
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving oAuth2 scopes.", e);
        } finally {
            endTenantFlow();
        }
        return userAllowedScopes;
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
                        if (!binding.startsWith(ADMIN_PERMISSION_ROOT)) {
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
