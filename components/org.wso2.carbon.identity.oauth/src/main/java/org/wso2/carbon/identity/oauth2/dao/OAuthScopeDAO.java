/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import java.sql.Connection;
import java.util.Set;
/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public interface OAuthScopeDAO {

    void addScope(Scope scope, int tenantID) throws IdentityOAuth2ScopeException;

    Set<Scope> getAllScopes(int tenantID) throws IdentityOAuth2ScopeServerException;

    Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID) throws IdentityOAuth2ScopeServerException;

    Scope getScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException;

    boolean isScopeExists(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException;

    int getScopeIDByName(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException;

    void deleteScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException;

    void updateScopeByName(Scope updatedScope, int tenantID) throws IdentityOAuth2ScopeServerException;

    boolean validateScope(Connection connection, String accessToken, String resourceUri);

    Set<String> getBindingsOfScopeByScopeName(String scopeName, int tenantId) throws IdentityOAuth2Exception;
}
