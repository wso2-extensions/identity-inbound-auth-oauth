/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.CONSOLE_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;

/**
 * The role based internal console scopes validation implementation. This will validate the configured console scopes
 * for the system roles against the access token's scopes.
 */
public class RoleBasedInternalScopeValidator {

    private static final Log log = LogFactory.getLog(RoleBasedInternalScopeValidator.class);

    /**
     * Method to validate scopes in the token request and return the allowed scopes.
     *
     * @param tokReqMsgCtx Token request.
     * @return Allowed scopes.
     */
    public String[] validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        // Filter system and console scopes.
        String[] requestedScopes = getRequestedScopes(tokReqMsgCtx.getScope());
        // If the token is not requested for specific scopes, return no validation needed.
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }

        // Get the roles of the authenticated user.
        AuthenticatedUser authenticatedUser = tokReqMsgCtx.getAuthorizedUser();
        List<String> roles = getRolesOfTheUser(authenticatedUser);
        List<String> rolesWithoutInternalDomain = removeInternalDomain(roles);

        // Get the configured system roles list with the scopes.
        Map<String, Set<String>> systemRolesWithScopes = IdentityUtil.getSystemRolesWithScopes();

        // Get the intersection of the configured system roles and users roles.
        rolesWithoutInternalDomain.retainAll(systemRolesWithScopes.keySet());

        // Get the distinct set of allowed console scopes based on the user roles.
        Set<String> userAllowedScopes = new HashSet<>();
        for (String role : rolesWithoutInternalDomain) {
            userAllowedScopes.addAll(systemRolesWithScopes.get(role));
        }

        // If the SYSTEM scope is requested, all the internal console scopes will be sent.
        if (ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
            return userAllowedScopes.toArray(new String[0]);
        }

        Set<String> scopesToRespond = new HashSet<>();
        for (String scope : requestedScopes) {
            if (userAllowedScopes.contains(scope)) {
                scopesToRespond.add(scope);
            }
        }
        return scopesToRespond.toArray(new String[0]);
    }

    /**
     * Method to validate scopes in the authorization request and return the allowed scopes.
     *
     * @param authzReqMessageContext Authorization request.
     * @return Allowed scopes.
     */
    public String[] validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {

        // Filter system and console scopes.
        String[] requestedScopes = getRequestedScopes(authzReqMessageContext.getAuthorizationReqDTO().getScopes());
        // If the token is not requested for specific scopes, return no validation needed.
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }

        // Get the roles of the authenticated user.
        AuthenticatedUser authenticatedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        List<String> roles = getRolesOfTheUser(authenticatedUser);
        List<String> rolesWithoutInternalDomain = removeInternalDomain(roles);

        // Get the configured system roles list with the scopes.
        Map<String, Set<String>> systemRolesWithScopes = IdentityUtil.getSystemRolesWithScopes();

        // Get the intersection of the configured system roles and users roles.
        rolesWithoutInternalDomain.retainAll(systemRolesWithScopes.keySet());

        // Get the distinct set of allowed console scopes based on the user roles.
        Set<String> userAllowedScopes = new HashSet<>();
        for (String role : rolesWithoutInternalDomain) {
            userAllowedScopes.addAll(systemRolesWithScopes.get(role));
        }

        // If the SYSTEM scope is requested, all the internal console scopes will be sent.
        if (ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
            return userAllowedScopes.toArray(new String[0]);
        }

        Set<String> scopesToRespond = new HashSet<>();
        for (String scope : requestedScopes) {
            if (userAllowedScopes.contains(scope)) {
                scopesToRespond.add(scope);
            }
        }
        return scopesToRespond.toArray(new String[0]);
    }

    private List<String> getRolesOfTheUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        try {
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(authenticatedUser.getTenantDomain());

            AbstractUserStoreManager userStoreManager
                    = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();

            String userName = userStoreManager.getUserNameFromUserID(authenticatedUser.getUserId());

            return userStoreManager.getHybridRoleListOfUser(UserCoreUtil.removeDomainFromName(userName),
                    authenticatedUser.getUserStoreDomain());

        } catch (UserStoreException e) {
            String error =
                    "Error occurred while getting roles of the user: " + authenticatedUser.getLoggableUserId();
            throw new IdentityOAuth2Exception(error, e);
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("User id not available for user: "
                    + authenticatedUser.getLoggableUserId(), e);
        }
    }

    private List<String> removeInternalDomain(List<String> roleNames) {

        return roleNames.stream().map(this::removeInternalDomain).collect(Collectors.toList());
    }

    private String removeInternalDomain(String roleName) {

        if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(IdentityUtil.extractDomainFromName(roleName))) {
            return UserCoreUtil.removeDomainFromName(roleName);
        }
        return roleName;
    }

    private String[] getRequestedScopes(String[] scopes) {

        if (scopes == null) {
            return null;
        }
        List<String> requestedScopes = new ArrayList<>();
        for (String scope : scopes) {
            if (scope.startsWith(CONSOLE_SCOPE_PREFIX) || scope.equalsIgnoreCase(SYSTEM_SCOPE)) {
                requestedScopes.add(scope);
            }
        }
        return requestedScopes.toArray(new String[0]);
    }
}
