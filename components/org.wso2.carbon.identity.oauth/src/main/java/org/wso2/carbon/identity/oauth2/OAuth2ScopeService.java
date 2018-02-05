/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCacheKey;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.ScopeMgtDAO;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * OAuth2ScopeService use for scope handling
 */
public class OAuth2ScopeService {
    private static final Log log = LogFactory.getLog(OAuth2ScopeService.class);
    private static ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

    /**
     * Register a scope with the bindings
     *
     * @param scope details of the scope to be registered
     * @throws IdentityOAuth2ScopeServerException
     * @throws IdentityOAuth2ScopeClientException
     */
    public Scope registerScope(Scope scope) throws IdentityOAuth2ScopeException {

        int tenantID = Oauth2ScopeUtils.getTenantID();

        // check whether the scope name is provided
        if (StringUtils.isBlank(scope.getName())) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        // check whether the scope description is provided
        if (StringUtils.isBlank(scope.getDisplayName())) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_NOT_SPECIFIED, null);
        }

        // check whether a scope exists with the provided scope name
        boolean isScopeExists = isScopeExists(scope.getName());
        if (isScopeExists) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE, scope.getName());
        }

        try {
            scopeMgtDAO.addScope(scope, tenantID);
            if (log.isDebugEnabled()) {
                log.debug("Scope is added to the database. \n" + scope.toString());
            }
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_REGISTER_SCOPE, scope.toString(), e);
        }

        OAuthScopeCache.getInstance().addToCache(new OAuthScopeCacheKey(scope.getName(), Integer.toString(tenantID)), scope);
        return scope;
    }

    /**
     * Retrieve the available scope list
     *
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @return Scope list
     * @throws IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getScopes(Integer startIndex, Integer count)
            throws IdentityOAuth2ScopeServerException {

        Set<Scope> scopes;

        // check for no query params.
        if (startIndex == null && count == null) {
            try {
                scopes = scopeMgtDAO.getAllScopes(Oauth2ScopeUtils.getTenantID());
            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_ALL_SCOPES, e);
            }
        } else {
            //check if it is a pagination request.
            scopes = listScopesWithPagination(startIndex, count);
        }
        return scopes;
    }

    /**
     * @param name Name of the scope which need to get retrieved
     * @return Retrieved Scope
     * @throws IdentityOAuth2ScopeException
     */
    public Scope getScope(String name) throws IdentityOAuth2ScopeException {

        Scope scope;
        int tenantID = Oauth2ScopeUtils.getTenantID();

        if (StringUtils.isBlank(name)) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        scope = OAuthScopeCache.getInstance().getValueFromCache(new OAuthScopeCacheKey(name, Integer.toString(tenantID)));

        if (scope == null) {
            try {
                scope = scopeMgtDAO.getScopeByName(name, tenantID);
                if (scope != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Scope is getting from the database. \n" + scope.toString());
                    }
                    OAuthScopeCache.getInstance().addToCache(new OAuthScopeCacheKey(name, Integer.toString(tenantID)), scope);
                }

            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME, name, e);
            }
        }

        if (scope == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE, name);
        }

        return scope;
    }

    /**
     * Check the existence of a scope
     *
     * @param name Name of the scope
     * @return true if scope with the given scope name exists
     * @throws IdentityOAuth2ScopeException
     */
    public boolean isScopeExists(String name) throws IdentityOAuth2ScopeException {

        boolean isScopeExists;
        int tenantID = Oauth2ScopeUtils.getTenantID();

        if (name == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        Scope scopeFromCache = OAuthScopeCache.getInstance()
                .getValueFromCache(new OAuthScopeCacheKey(name, Integer.toString(tenantID)));

        if (scopeFromCache != null) {
            isScopeExists = true;
        } else {
            try {
                isScopeExists = scopeMgtDAO.isScopeExists(name, tenantID);
            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME, name, e);
            }
        }

        return isScopeExists;
    }

    /**
     * Delete the scope for the given scope ID
     *
     * @param name Scope ID of the scope which need to get deleted
     * @throws IdentityOAuth2ScopeException
     */
    public void deleteScope(String name) throws IdentityOAuth2ScopeException {

        int tenantID = Oauth2ScopeUtils.getTenantID();
        if (name == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        // check whether a scope exists with the provided scope name which to be deleted
        boolean isScopeExists = isScopeExists(name);
        if (!isScopeExists) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE, name);
        }

        OAuthScopeCache.getInstance().clearCacheEntry(new OAuthScopeCacheKey(name, Integer.toString(tenantID)));

        try {
            scopeMgtDAO.deleteScopeByName(name, tenantID);
            if (log.isDebugEnabled()) {
                log.debug("Scope: " + name + " is deleted from the database.");
            }
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_DELETE_SCOPE_BY_NAME, name, e);
        }
    }

    /**
     * Update the scope of the given scope ID
     *
     * @param updatedScope details of updated scope
     * @return updated scope
     * @throws IdentityOAuth2ScopeException
     */
    public Scope updateScope(Scope updatedScope) throws IdentityOAuth2ScopeException {

        int tenantID = Oauth2ScopeUtils.getTenantID();
        if (updatedScope.getName() == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        // check whether the scope description is provided
        if (StringUtils.isBlank(updatedScope.getDisplayName())) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_NOT_SPECIFIED, null);
        }

        // check whether a scope exists with the provided scope name which to be updated
        boolean isScopeExists = isScopeExists(updatedScope.getName());
        if (!isScopeExists) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE, updatedScope.getName());
        }

        try {
            scopeMgtDAO.updateScopeByName(updatedScope, tenantID);
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_UPDATE_SCOPE_BY_NAME, updatedScope.getName(), e);
        }

        OAuthScopeCache.getInstance().addToCache(new OAuthScopeCacheKey(updatedScope.getName(),
                Integer.toString(tenantID)), updatedScope);
        return updatedScope;
    }

    /**
     * List scopes with filtering
     *
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @return List of available scopes
     * @throws IdentityOAuth2ScopeServerException
     */
    private Set<Scope> listScopesWithPagination(Integer startIndex, Integer count)
            throws IdentityOAuth2ScopeServerException {

        Set<Scope> scopes;

        if (count == null || count < 0) {
            count = Oauth2ScopeConstants.MAX_FILTER_COUNT;
        }

        if (startIndex == null || startIndex < 1) {
            startIndex = 1;
        }

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }

        try {
            scopes = scopeMgtDAO.getScopesWithPagination(startIndex, count, Oauth2ScopeUtils.getTenantID());
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_ALL_SCOPES_PAGINATION, e);
        }
        return scopes;
    }
}
