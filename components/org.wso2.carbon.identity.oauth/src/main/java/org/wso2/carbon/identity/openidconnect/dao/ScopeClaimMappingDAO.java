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
     * To add OIDC scopes and claims in the related db tables.
     *
     * @param tenantId       tenant Id
     * @param scopeClaimsMap map of oidc scope claims
     * @throws IdentityOAuth2Exception if an error occurs when inserting scopes or claims.
     */
    void addScopes(int tenantId, List<ScopeDTO> scopeClaimsMap) throws IdentityOAuth2Exception;

    /**
     * To add OIDC scope for a specific tenant.
     *
     * @param tenantId tenant Id
     * @param scope    scope
     * @throws IdentityOAuth2Exception if an error occurs when adding a scope.
     */
    void addScope(int tenantId, String scope, String[] claimsList) throws IdentityOAuth2Exception;

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @param tenantId tenant Id
     * @return all persisted scopes and claims
     * @throws IdentityOAuth2Exception if an error occurs when loading scopes and claims.
     */
    List<ScopeDTO> getScopes(int tenantId) throws IdentityOAuth2Exception;

    /**
     * To retrieve all persisted oidc scopes.
     *
     * @param tenantId tenant Id
     * @return list of scopes persisted.
     * @throws IdentityOAuth2Exception if an error occurs when loading oidc scopes.
     */
    List<String> getScopeNames(int tenantId) throws IdentityOAuth2Exception;

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope oidc scope
     * @throws IdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     */
    void deleteScope(String scope, int tenantId) throws IdentityOAuth2Exception;

    /**
     * To add new claims for an existing scope.
     *
     * @param scope        scope name
     * @param tenantId     tenant Id
     * @param addClaims    list of oidc claims to be added
     * @param deleteClaims list of oidc claims to be deleted
     * @throws IdentityOAuth2Exception if an error occurs when adding a new claim for a scope.
     */
    void updateScope(String scope, int tenantId, List<String> addClaims, List<String> deleteClaims)
            throws IdentityOAuth2Exception;

    /**
     * To retrieve oidc claims mapped to an oidc scope.
     *
     * @param scope    scope
     * @param tenantId tenant Id
     * @return list of claims which are mapped to the oidc scope.
     * @throws IdentityOAuth2Exception if an error occurs when lading oidc claims.
     */
    ScopeDTO getClaims(String scope, int tenantId) throws IdentityOAuth2Exception;

    /**
     * To load top record of the scope table.
     *
     * @return scope id
     * @throws IdentityOAuth2Exception if an error occurs when loading the top scope record.
     */
    boolean hasScopesPopulated(int tenantId) throws IdentityOAuth2Exception;

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
