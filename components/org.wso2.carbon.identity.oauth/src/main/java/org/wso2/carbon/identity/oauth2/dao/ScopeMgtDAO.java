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

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import java.util.Set;

/**
 * Data Access Layer functionality for Scope management. This includes storing, updating, deleting and retrieving scopes
 */
@Deprecated
public class ScopeMgtDAO {

    /**
     * Add a scope
     *
     * @param scope    Scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2ScopeException IdentityOAuth2ScopeException
     */
    public void addScope(Scope scope, int tenantID) throws IdentityOAuth2ScopeException {

        OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().addScope(scope, tenantID);
    }


    /**
     * Get all available scopes
     *
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getAllScopes(int tenantID) throws IdentityOAuth2ScopeServerException {

        return OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getAllScopes(tenantID);
    }

    /**
     * Get Scopes with pagination
     *
     * @param offset   start index of the result set
     * @param limit    number of elements of the result set
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID) throws IdentityOAuth2ScopeServerException {

        return OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopesWithPagination(offset, limit, tenantID);
    }

    /**
     * Get a scope by name
     *
     * @param name     name of the scope
     * @param tenantID tenant ID
     * @return Scope for the provided ID
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public Scope getScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException {

        return OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeByName(name, tenantID);
    }

    /**
     * Get existence of scope for the provided scope name
     *
     * @param scopeName name of the scope
     * @param tenantID tenant ID
     * @return true if scope is exists
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public boolean isScopeExists(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException {

       return OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().isScopeExists(scopeName, tenantID);
    }

    /**
     * Get scope ID for the provided scope name
     *
     * @param scopeName name of the scope
     * @param tenantID  tenant ID
     * @return scope ID for the provided scope name
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public int getScopeIDByName(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException {

        return OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeIDByName(scopeName, tenantID);
    }

    /**
     * Delete a scope of the provided scope ID
     *
     * @param name     name of the scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public void deleteScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException {

        OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().deleteScopeByName(name, tenantID);
    }

    /**
     * Update a scope of the provided scope name
     *
     * @param updatedScope details of the updated scope
     * @param tenantID     tenant ID
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    public void updateScopeByName(Scope updatedScope, int tenantID) throws IdentityOAuth2ScopeServerException {

        OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().updateScopeByName(updatedScope, tenantID);
    }
}
