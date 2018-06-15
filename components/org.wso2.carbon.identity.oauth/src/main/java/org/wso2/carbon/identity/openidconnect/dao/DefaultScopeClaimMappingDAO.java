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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.openidconnect.model.Scope;

import java.util.List;

/**
 * Interface used in OIDC to handle all the scope claim mapping related db operations.
 */
public interface DefaultScopeClaimMappingDAO {

    /**
     * To insert oidc scopes and claims in the related db tables.
     *
     * @param tenantId           tenant Id
     * @param listOIDCScopeClaim list of oidc scope claims mapping object
     * @throws IdentityOAuth2Exception if an error occurs when inserting scopes or claims.
     */
    void insertAllScopesAndClaims(int tenantId, List<Scope> listOIDCScopeClaim) throws IdentityOAuth2Exception;

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @param tenantId tenant Id
     * @return all persisted scopes and claims
     * @throws IdentityOAuth2Exception if an error occurs when loading scopes and claims.
     */
    List<Scope> loadScopesClaimsMapping(int tenantId) throws IdentityOAuth2Exception;

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope oidc scope
     * @throws IdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     */
    void deleteScopeAndClaims(String scope, int tenantId) throws IdentityOAuthAdminException;

    /**
     * To add new claims for an existing scope.
     *
     * @param scope    scope
     * @param tenantId tenant Id
     * @param claims   list of oidc claims
     * @throws IdentityOAuth2Exception if an error occurs when adding a new claim for a scope.
     */
    void addNewClaimsForScope(String scope, List<String> claims, int tenantId) throws IdentityOAuth2Exception;

    /**
     * To load top record of the scope table
     *
     * @return scope id
     * @throws IdentityOAuth2Exception if an error occurs when loading the top scope record.
     */
    int loadSingleScopeRecord(int tenantId) throws IdentityOAuth2Exception;

}
