/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ResourceScopeCacheEntry;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The JDBC Scope Validation implementation. This validates the Resource's scope (stored in IDN_OAUTH2_RESOURCE_SCOPE)
 * against the Access Token's scopes.
 */
public class JDBCScopeValidator extends OAuth2ScopeValidator {

    // The following constants are as same as the constants defined in
    // org.wso2.carbon.apimgt.keymgt.handlers.ResourceConstants.
    // If any changes are taking place in that these should also be updated accordingly.
    // Setting the "retrieveRolesFromUserStoreForScopeValidation" as a System property which is used when
    // skipping the scope role validation during token issuing using JWT bearer grant.
    public static final String CHECK_ROLES_FROM_SAML_ASSERTION = "checkRolesFromSamlAssertion";
    public static final String RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION =
            "retrieveRolesFromUserStoreForScopeValidation";
    private static final String SCOPE_VALIDATOR_NAME = "Role based scope validator";
    private static final String OPENID = "openid";
    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();
    private static final String PRESERVE_CASE_SENSITIVITY = "preservedCaseSensitive";

    private static final Log log = LogFactory.getLog(JDBCScopeValidator.class);

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {

        // Return true if there is no resource to validate the token against.
        if (resource == null) {
            return true;
        }

        //Get the list of scopes associated with the access token
        String[] scopes = accessTokenDO.getScope();

        //If no scopes are associated with the token
        if (scopes == null || scopes.length == 0) {
            return true;
        }

        String resourceScope = null;
        int resourceTenantId = -1;

        boolean cacheHit = false;
        // Check the cache, if caching is enabled.
        OAuthCacheKey cacheKey = new OAuthCacheKey(resource);
        CacheEntry result = OAuthCache.getInstance().getValueFromCache(cacheKey);

        //Cache hit
        if (result !=  null && result instanceof ResourceScopeCacheEntry) {
            resourceScope = ((ResourceScopeCacheEntry) result).getScope();
            resourceTenantId = ((ResourceScopeCacheEntry) result).getTenantId();
            cacheHit = true;
        }


        // Cache was not hit. So retrieve from database.
        if (!cacheHit) {
            Pair<String, Integer> scopeMap = OAuthTokenPersistenceFactory.getInstance()
                    .getTokenManagementDAO().findTenantAndScopeOfResource(resource);

            if (scopeMap != null) {
                resourceScope = scopeMap.getLeft();
                resourceTenantId = scopeMap.getRight();
            }

            cacheKey = new OAuthCacheKey(resource);
            ResourceScopeCacheEntry cacheEntry = new ResourceScopeCacheEntry(resourceScope);
            cacheEntry.setTenantId(resourceTenantId);
            //Store resourceScope in cache even if it is null (to avoid database calls when accessing resources for
            //which scopes haven't been defined).
            OAuthCache.getInstance().addToCache(cacheKey, cacheEntry);

        }

        //Return TRUE if - There does not exist a scope definition for the resource
        if (resourceScope == null) {
            if (log.isDebugEnabled()) {
                log.debug("Resource '" + resource + "' is not protected with a scope");
            }
            return true;
        }

        List<String> scopeList = new ArrayList<>(Arrays.asList(scopes));

        // If the access token does not bear the scope required for accessing the Resource.
        if (!scopeList.contains(resourceScope)) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token '" + accessTokenDO.getAccessToken() + "' does not bear the scope '" +
                            resourceScope + "'");
            }
            return false;
        }

        // If a federated user and CHECK_ROLES_FROM_SAML_ASSERTION system property is set to true,
        // or if a federated user and RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION system property is false,
        // avoid validating user roles.
        // This system property is set at server start using -D option, Thus will be a permanent property.
        if (accessTokenDO.getAuthzUser().isFederatedUser()
                && (Boolean.parseBoolean(System.getProperty(CHECK_ROLES_FROM_SAML_ASSERTION)) ||
                !(Boolean.parseBoolean(System.getProperty(RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION))))) {
            return true;
        }

        try {
            AuthenticatedUser authzUser = accessTokenDO.getAuthzUser();
            int tenantId = getTenantId(authzUser);
            String[] userRoles = getUserRoles(authzUser);

            if (ArrayUtils.isEmpty(userRoles)) {
                if (log.isDebugEnabled()) {
                    log.debug("No roles associated for the user " + authzUser.getLoggableUserId());
                }
                return false;
            }

            return isUserAuthorizedForScope(resourceScope, userRoles, tenantId);

        } catch (UserStoreException e) {
            //Log and return since we do not want to stop issuing the token in case of scope validation failures.
            log.error("Error when getting the tenant's UserStoreManager or when getting roles of user ", e);
            return false;
        }
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws
            UserStoreException, IdentityOAuth2Exception {

        return validateScope(tokReqMsgCtx.getScope(), tokReqMsgCtx.getAuthorizedUser(),
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws
            UserStoreException, IdentityOAuth2Exception {

        return validateScope(authzReqMessageContext.getAuthorizationReqDTO().getScopes(),
                authzReqMessageContext.getAuthorizationReqDTO().getUser(),
                authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
    }

    /**
     * Validate given set of scopes against an authenticated user.
     *
     * @param requestedScopes Scopes to be validated.
     * @param user Authenticated user.
     * @param clientId        Client ID.
     * @return True is all scopes are valid. False otherwise.
     * @throws UserStoreException If were unable to get tenant or user roles.
     * @throws IdentityOAuth2Exception by an Underline method.
     */
    private boolean validateScope(String[] requestedScopes, AuthenticatedUser user, String clientId)
            throws UserStoreException, IdentityOAuth2Exception {

        // Remove openid scope from the list if available
        requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, OPENID);

        // Remove OIDC scopes from the list if exists.
        try {
            String[] oidcScopes = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().getScopeNames();
            for (String oidcScope : oidcScopes) {
                requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, oidcScope);
            }

        } catch (IdentityOAuthAdminException e) {
            log.error("Unable to obtain OIDC scopes list.");
            return false;
        }

        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return true;
        }

        String[] userRoles = null;
        int tenantId = getTenantId(user);

        /*
        Here we handle scope validation for federated user and local user separately.
        For local users - user store is used to get user roles.
        For federated user - get user roles from user attributes.
        Note that if there is association between a federated user and local user () 'Assert identity using mapped local
        subject identifier' flag will be set as true. So authenticated user will be associated local user not
        federated user.
         */
        if (user.isFederatedUser()) {
            /*
            There is a flow where 'Assert identity using mapped local subject identifier' flag enabled but the
            federated user doesn't have any association in localIDP, to handle this case we check for 'Assert
            identity using mapped local subject identifier' flag and get roles from userStore.
             */
            if (isSPAlwaysSendMappedLocalSubjectId(clientId)) {
                userRoles = getUserRoles(user);
            } else {
                // Handle not account associated federated users.
                userRoles = getUserRolesForNotAssociatedFederatedUser(user);
            }
        } else {
            userRoles = getUserRoles(user);
        }
        if (ArrayUtils.isNotEmpty(userRoles)) {
            for (String scope : requestedScopes) {
                if (!isScopeValid(scope, tenantId)) {
                    // If the scope is not registered return false.
                    if (log.isDebugEnabled()) {
                        log.debug("Requested scope " + scope + " is invalid");
                    }
                    return false;
                }
                if (!isUserAuthorizedForScope(scope, userRoles, tenantId)) {
                    if (log.isDebugEnabled()) {
                        log.debug("User " + user.getLoggableUserId() + "in not authorised for scope " + scope);
                    }
                    return false;
                }
            }
        } else {
            return false;
        }
        return true;
    }

    private boolean isSPAlwaysSendMappedLocalSubjectId(String clientId) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
        if (serviceProvider != null) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                return claimConfig.isAlwaysSendMappedLocalSubjectId();
            }
            throw new IdentityOAuth2Exception("Unable to find claim configuration for service provider of client " +
                        "id " + clientId);
        }
        throw new IdentityOAuth2Exception("Unable to find service provider for client id " + clientId);
    }

    private String[] getUserRolesForNotAssociatedFederatedUser(AuthenticatedUser user)
            throws IdentityOAuth2Exception {

        List<String> userRolesList = new ArrayList<>();
        IdentityProvider identityProvider =
                OAuth2Util.getIdentityProvider(user.getFederatedIdPName(), user.getTenantDomain());
        /*
        Values of Groups consists unmapped federated roles, mapped local roles and Internal/everyone corresponding to
        authenticated user.
        Role mapping consists mapped federated roles with local roles corresponding to IDP.
        By cross checking federated role mapped local roles and values of groups we can filter valid local roles which
        mapped to the federated role of authenticated user.
         */
        List<String> valuesOfGroups = getValuesOfGroupsFromUserAttributes(user.getUserAttributes());
        if (CollectionUtils.isNotEmpty(valuesOfGroups)) {
            for (RoleMapping roleMapping : identityProvider.getPermissionAndRoleConfig().getRoleMappings()) {
                if (roleMapping != null && roleMapping.getLocalRole() != null) {
                    if (valuesOfGroups.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        userRolesList.add(roleMapping.getLocalRole().getLocalRoleName());
                    }
                }
            }
        }
        // By default we provide Internal/everyone role for all users.
        String internalEveryoneRole = OAuth2Util.getInternalEveryoneRole(user);
        if (StringUtils.isNotBlank(internalEveryoneRole)) {
            userRolesList.add(internalEveryoneRole);
        }
        return userRolesList.toArray(new String[0]);
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

    @Override
    public String getValidatorName() {
        return SCOPE_VALIDATOR_NAME;
    }

    private boolean isScopeValid(String scopeName, int tenantId) {

        Scope scope = null;

        try {
            scope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeByName(scopeName, tenantId);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving scope with name :" + scopeName);
        }

        return scope != null;
    }

    private boolean isUserAuthorizedForScope(String scopeName, String[] userRoles, int tenantId)
            throws IdentityOAuth2Exception {

        Set<String> rolesOfScope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().
                getBindingsOfScopeByScopeName(scopeName, tenantId);

        if (CollectionUtils.isEmpty(rolesOfScope)) {
            if (log.isDebugEnabled()) {
                log.debug("Did not find any roles associated to the scope " + scopeName);
            }
            return true;
        }

        if (log.isDebugEnabled()) {
            StringBuilder logMessage = new StringBuilder("Found roles of scope '" + scopeName + "' ");
            logMessage.append(String.join(",", rolesOfScope));
            log.debug(logMessage.toString());
        }

        if (ArrayUtils.isEmpty(userRoles)) {
            if (log.isDebugEnabled()) {
                log.debug("User does not have required roles for scope " + scopeName);
            }
            return false;
        }
        boolean preservedCaseSensitive = Boolean.parseBoolean(System.getProperty(PRESERVE_CASE_SENSITIVITY));

        //Check if the user still has a valid role for this scope.
        Set<String> scopeRoles = new HashSet<>(rolesOfScope);
        if (preservedCaseSensitive) {
            rolesOfScope.retainAll(Arrays.asList(userRoles));
        } else {
            Set<String> rolesOfScopeLowerCase = new HashSet<>();
            for (String roleOfScope : rolesOfScope) {
                rolesOfScopeLowerCase.add(roleOfScope.toLowerCase());
            }
            rolesOfScope = rolesOfScopeLowerCase;
            ArrayList<String> userRolesLowercase = new ArrayList<>();
            for (String userRole : userRoles) {
                userRolesLowercase.add(userRole.toLowerCase());
            }
            rolesOfScope.retainAll(userRolesLowercase);
        }
        rolesOfScope.retainAll(Arrays.asList(userRoles));

        if (rolesOfScope.isEmpty()) {
            // when the role is an internal one, check if the user has valid role
            boolean validInternalUserRole = validateInternalUserRoles(scopeRoles, userRoles);

            if (validInternalUserRole) {
                return true;
            }
            if (log.isDebugEnabled()) {
                log.debug("User does not have required roles for scope " + scopeName);
            }
            return false;
        }

        return true;
    }

    /**
     * This method used to validate scopes which bind with internal roles
     * @param scopeRoles roles in scope
     * @param userRoles user roles
     * @return
     */
    private boolean validateInternalUserRoles(Set<String> scopeRoles,  String[] userRoles) {
        for (String role : scopeRoles) {
            int index = role.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
            if (index > 0) {
                String domain = role.substring(0, index);
                if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)) {
                    for (String userRole : userRoles) {
                        if (role.equalsIgnoreCase(userRole)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private String[] getUserRoles(AuthenticatedUser user) throws UserStoreException {

        UserStoreManager userStoreManager;
        String[] userRoles;
        boolean tenantFlowStarted = false;

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        int tenantId = getTenantId(user);
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(
                        realmService.getTenantManager().getDomain(tenantId), true);
                tenantFlowStarted = true;
            }

            userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            userRoles = userStoreManager.getRoleListOfUser(
                    MultitenantUtils.getTenantAwareUsername(user.toFullQualifiedUsername()));
        } finally {
            if (tenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }

        if (ArrayUtils.isNotEmpty(userRoles)) {
            if (log.isDebugEnabled()) {
                String logMessage = "Found roles of user " + user.getLoggableUserId() + " "
                        + String.join(",", userRoles);
                log.debug(logMessage);
            }
        }
        return userRoles;
    }

    private int getTenantId (User user) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());

        return tenantId;
    }
}
