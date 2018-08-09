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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ResourceScopeCacheEntry;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;


/**
 * The JDBC Scope Validation implementation. This validates the Resource's scope (stored in IDN_OAUTH2_RESOURCE_SCOPE)
 * against the Access Token's scopes.
 */
public class JDBCScopeValidator extends OAuth2ScopeValidator {

    // The following constants are as same as the constants defined in
    // org.wso2.carbon.apimgt.keymgt.handlers.ResourceConstants.
    // If any changes are taking place in that these should also be updated accordingly.
    public static final String CHECK_ROLES_FROM_SAML_ASSERTION = "checkRolesFromSamlAssertion";
    private static final String SCOPE_VALIDATOR_NAME = "Role based scope validator";
    private static final String OPENID = "openid";

    Log log = LogFactory.getLog(JDBCScopeValidator.class);

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
            if(log.isDebugEnabled()){
                log.debug("Resource '" + resource + "' is not protected with a scope");
            }
            return true;
        }

        List<String> scopeList = new ArrayList<>(Arrays.asList(scopes));

        //If the access token does not bear the scope required for accessing the Resource.
        if(!scopeList.contains(resourceScope)){
            if(log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)){
                log.debug("Access token '" + accessTokenDO.getAccessToken() + "' does not bear the scope '" +
                            resourceScope + "'");
            }
            return false;
        }

        // If a federated user and CHECK_ROLES_FROM_SAML_ASSERTION system property is set to true,
        // avoid validating user roles.
        // This system property is set at server start using -D option, Thus will be a permanent property.
        if (accessTokenDO.getAuthzUser().isFederatedUser()
                && Boolean.parseBoolean(System.getProperty(CHECK_ROLES_FROM_SAML_ASSERTION))) {
            return true;
        }

        try {
            User authzUser = accessTokenDO.getAuthzUser();
            int tenantId = getTenantId(authzUser);
            String[] userRoles = getUserRoles(authzUser);

            if (ArrayUtils.isEmpty(userRoles)) {
                if(log.isDebugEnabled()){
                    log.debug("No roles associated for the user " + authzUser.getUserName());
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

        String[] requestedScopes = tokReqMsgCtx.getScope();
        // Remove openid scope from the list if available
        requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, OPENID);

        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return true;
        }

        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        int tenantId = getTenantId(user);
        String[] userRoles = getUserRoles(user);

        for (String scope : requestedScopes) {
            if (!isScopeValid(scope, tenantId)) {
                //If the scope is not registered return false
                log.error("Requested scope " + scope + " is invalid");
                return false;
            }
            if (!isUserAuthorizedForScope(scope, userRoles, tenantId)) {
                return false;
            }
        }
        return true;
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
        //Check if the user still has a valid role for this scope.
        rolesOfScope.retainAll(Arrays.asList(userRoles));

        if (rolesOfScope.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("User does not have required roles for scope " + scopeName);
            }
            return false;
        }

        return true;
    }

    private String[] getUserRoles(User user) throws UserStoreException {

        UserStoreManager userStoreManager;
        String[] userRoles;
        boolean tenantFlowStarted = false;

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        int tenantId = getTenantId(user);
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(
                        realmService.getTenantManager().getDomain(tenantId),true);
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
                StringBuilder logMessage = new StringBuilder("Found roles of user ");
                logMessage.append(user.getUserName());
                logMessage.append(" ");
                logMessage.append(String.join(",", userRoles));
                log.debug(logMessage.toString());
            }
        }
        return userRoles;
    }

    private int getTenantId (User user) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());

        if (tenantId == 0 || tenantId == -1) {
            tenantId = IdentityTenantUtil.getTenantIdOfUser(user.getUserName());
        }

        return tenantId;
    }

}
