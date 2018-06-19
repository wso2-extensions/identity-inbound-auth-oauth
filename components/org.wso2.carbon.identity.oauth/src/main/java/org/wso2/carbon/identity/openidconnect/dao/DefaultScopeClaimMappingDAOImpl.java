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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.RowMapper;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.database.utils.jdbc.exceptions.TransactionException;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JdbcUtils;
import org.wso2.carbon.identity.openidconnect.model.Scope;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;

/**
 * Default implementation of {@link DefaultScopeClaimMappingDAO}. This handles {@link Scope} related db layer operations.
 */
public class DefaultScopeClaimMappingDAOImpl implements DefaultScopeClaimMappingDAO {

    private final Log log = LogFactory.getLog(DefaultScopeClaimMappingDAOImpl.class);

    @Override
    public void insertAllScopesAndClaims(int tenantId, List<Scope> oidcScopeClaimList) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        for (Scope scopeClaim : oidcScopeClaimList) {
            String scope = scopeClaim.getName();
            List<String> claims = scopeClaim.getClaim();
            if (loadScopeId(scope) == -1) {
                try {
                    int scopeClaimMappingId = jdbcTemplate.executeInsert(SQLQueries.STORE_IDN_OIDC_SCOPES,
                            (preparedStatement -> {
                                preparedStatement.setString(1, scope);
                                preparedStatement.setInt(2, tenantId);
                            }), null, true);
                    if (scopeClaimMappingId > -1) {
                        insertAllClaims(tenantId, scopeClaimMappingId, claims);
                    }
                } catch (DataAccessException e) {
                    String errorMessage = "Error while persisting new claims for the scope for the tenant: " + tenantId;
                    log.error(errorMessage, e);
                    throw new IdentityOAuth2Exception(errorMessage, e);
                }
            }

        }
    }

    @Override
    public List<Scope> loadScopesClaimsMapping(int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_SCOPES_CLAIMS;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<Scope> oidcScopeClaimList = new ArrayList<>();
        try {

            Map<String, List<String>> scopeClaimMap = new HashMap<>();
            jdbcTemplate.executeQuery(sql, (RowMapper<Scope>) (resultSet, i) -> {

                List<String> claimsList = new ArrayList<>();
                String key = resultSet.getString(1);
                if (!scopeClaimMap.containsKey(key)) {
                    claimsList.add(resultSet.getString(2));
                    scopeClaimMap.put(key, claimsList);
                } else {
                    for (String claim : scopeClaimMap.get(resultSet.getString(1))) {
                        claimsList.add(claim);
                    }
                    claimsList.add(resultSet.getString(2));
                    scopeClaimMap.put(resultSet.getString(1), claimsList);

                }
                return null;
            }, preparedStatement ->
                    preparedStatement.setInt(1, tenantId));
            for (Map.Entry<String, List<String>> scopeClaimEntry : scopeClaimMap.entrySet()) {
                Scope scopeClaimMapping = new Scope();
                scopeClaimMapping.setName(scopeClaimEntry.getKey());
                scopeClaimMapping.setClaim(scopeClaimEntry.getValue());
                oidcScopeClaimList.add(scopeClaimMapping);
            }
        } catch (DataAccessException e) {
            String errorMessage = "Error while loading scopes claims mapping.";
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return oidcScopeClaimList;
    }

    @Override
    public void deleteScopeAndClaims(String scope, int tenantId) throws IdentityOAuthAdminException {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            jdbcTemplate.executeUpdate(SQLQueries.DELETE_SCOPE_CLAIM_MAPPING, preparedStatement -> {
                        preparedStatement.setString(1, scope);
                        preparedStatement.setInt(1, tenantId);
                    }

            );
        } catch (DataAccessException e) {
            throw handleError("Error while deleting the scope: " + scope + " and related claims.", e);
        }
    }

    @Override
    public void addNewClaimsForScope(String scope, List<String> claims, int tenantId) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        int scopeClaimMappingId = -1;
        try {
            jdbcTemplate.withTransaction(template -> {
                template.executeBatchInsert(SQLQueries.INSERT_NEW_CLAIMS_FOR_SCOPE, (preparedStatement -> {

                    try {
                        //Get the scope id of the existing scope.
                        int scopeId = loadScopeId(scope);
                        for (String claim : claims) {
                            //Get the claim id for the related claim_uri
                            int claimId = loadOIDCClaimId(claim);

                            preparedStatement.setInt(1, scopeId);
                            preparedStatement.setInt(2, claimId);
                            preparedStatement.addBatch();
                        }
                    } catch (IdentityOAuth2Exception e) {
                        String errorMessage = "Error while Fetching scope id and claims id for scope: " + scope;
                        log.error(errorMessage);
                    }

                }), scopeClaimMappingId);
                return null;
            });
        } catch (TransactionException e) {
            String errorMsg = "Error while inserting new claims for the scope: " + scope;
            log.error(errorMsg);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    private void insertAllClaims(int tenantId, int scopeId, List<String> claimsList) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        int scopeClaimMappingId = -1;
        try {
            jdbcTemplate.withTransaction(template -> {
                template.executeBatchInsert(SQLQueries.STORE_IDN_OIDC_CLAIMS, (preparedStatement -> {
                    if (CollectionUtils.isNotEmpty(claimsList)) {
                        for (String claim : claimsList) {
                            preparedStatement.setInt(1, scopeId);
                            preparedStatement.setInt(2, tenantId);
                            preparedStatement.setString(3, claim);
                            preparedStatement.addBatch();
                            if (log.isDebugEnabled()) {
                                log.debug("Claim value :" + claim + " is added to the batch.");
                            }
                        }
                    }

                }), scopeClaimMappingId);
                return null;
            });
        } catch (TransactionException e) {
            String errorMessage = "Error when storing oidc claims.";
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
    }

    public int loadSingleScopeRecord(int tenantId) throws IdentityOAuth2Exception {

        Integer id;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            id = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_ALL_IDN_OIDC_SCOPES, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setInt(1, tenantId);
                    }));
            if (id == null) {
                id = -1;
            }
        } catch (TransactionException e) {
            String errorMessage = "Error while loading the top scope id.";
            log.error(errorMessage);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return id;
    }

    private int loadOIDCClaimId(String claim) throws IdentityOAuth2Exception {

        Integer oidcClaimId;
        try {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            oidcClaimId = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_OIDC_CLAIM_ID, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setString(1, claim);
                    }));
            if (oidcClaimId == null) {
                oidcClaimId = -1;
            }
        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + claim;
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return oidcClaimId;
    }

    private int loadScopeId(String scope) throws IdentityOAuth2Exception {

        Integer scopeId;
        try {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            scopeId = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_IDN_OIDC_SCOPE_ID, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setString(1, scope);
                    }));
            if (scopeId == null) {
                scopeId = -1;
            }
        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + scope;
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return scopeId;
    }

}
