/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect.dao;

import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.util.List;

/**
 * Interface used in openid connect to handle all the scope claim mapping related db operations.
 */
public interface ScopeClaimMappingDAO {

    /**
     * To insert oidc scopes and claims in the related db tables.
     *
     * @param tenantId       tenant Id
     * @param scopeClaimsMap map of oidc scope claims
     * @throws IdentityOAuth2Exception if an error occurs when inserting scopes or claims.
     */
    void addScope(int tenantId, List<ScopeDTO> scopeClaimsMap) throws IdentityOAuth2Exception;

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @param tenantId tenant Id
     * @return all persisted scopes and claims
     * @throws IdentityOAuth2Exception if an error occurs when loading scopes and claims.
     */
    List<ScopeDTO> getScopesClaims(int tenantId) throws IdentityOAuth2Exception;

    /**
     * To retrieve all persisted oidc scopes.
     *
     * @param tenantId tenant Id
     * @return list of scopes persisted.
     * @throws IdentityOAuth2Exception if an error occurs when loading oidc scopes.
     */
    List<String> getScopes(int tenantId) throws IdentityOAuth2Exception;

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope oidc scope
     * @throws IdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     */
    void deleteScope(String scope, int tenantId) throws IdentityOAuthAdminException;

    /**
     * To add new claims for an existing scope.
     *
     * @param scope    scope name
     * @param tenantId tenant Id
     * @param claims   list of oidc claims
     * @throws IdentityOAuth2Exception if an error occurs when adding a new claim for a scope.
     */
    void updateScope(String scope, int tenantId, boolean isAdd, List<String> claims) throws IdentityOAuth2Exception;

    /**
     * To retrieve oidc claims mapped to an oidc scope.
     *
     * @param scope    scope
     * @param tenantId tenant Id
     * @return list of claims which are mapped to the oidc scope.
     * @throws IdentityOAuth2Exception if an error occurs when lading oidc claims.
     */
    List<String> getClaimsByScope(String scope, int tenantId) throws IdentityOAuth2Exception;

    /**
     * To load top record of the scope table.
     *
     * @return scope id
     * @throws IdentityOAuth2Exception if an error occurs when loading the top scope record.
     */
    boolean isScopeExist(int tenantId) throws IdentityOAuth2Exception;

    /**
     * To check whether the scope is existing.
     *
     * @param scope    scope name
     * @param tenantId tenant id
     * @return true if the scope is already existing.
     * @throws IdentityOAuth2Exception
     */
    boolean isScopeExist(String scope, int tenantId) throws IdentityOAuth2Exception;

}
