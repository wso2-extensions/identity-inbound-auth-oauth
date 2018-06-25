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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.RowMapper;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.database.utils.jdbc.exceptions.TransactionException;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JdbcUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;

/**
 * Default implementation of {@link ScopeClaimMappingDAO}. This handles {@link ScopeDTO} related db layer operations.
 */
public class ScopeClaimMappingDAOImpl implements ScopeClaimMappingDAO {

    private final Log log = LogFactory.getLog(ScopeClaimMappingDAOImpl.class);

    @Override
    public void insertAllScopesAndClaims(int tenantId, List<ScopeDTO> scopeClaimsList) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        //scopeClaimsList is not a null.
        for (ScopeDTO scopeDTO : scopeClaimsList) {
            String scope = scopeDTO.getName();
            String[] claims = scopeDTO.getClaim();
            if (loadScopeId(scope, tenantId) == -1) {
                try {
                    int scopeClaimMappingId = jdbcTemplate.executeInsert(SQLQueries.STORE_IDN_OIDC_SCOPES,
                            (preparedStatement -> {
                                preparedStatement.setString(1, scope);
                                preparedStatement.setInt(2, tenantId);
                            }), null, true);
                    if (scopeClaimMappingId > 0 && ArrayUtils.isNotEmpty(claims)) {
                        Set<String> claimsSet = new HashSet<>(Arrays.asList(claims));
                        insertAllClaims(tenantId, scopeClaimMappingId, claimsSet);
                    }
                    if (log.isDebugEnabled() && ArrayUtils.isNotEmpty(claims)) {
                        String message = "inserted for the tenant: ";
                        logMessage(scope, Arrays.asList(claims), tenantId, message);
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
    public List<ScopeDTO> loadScopesClaimsMapping(int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_SCOPES_CLAIMS;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<ScopeDTO> oidcScopeClaimList;

        try {

            Map<String, List<String>> scopeClaimMap = new HashMap<>();
            jdbcTemplate.executeQuery(sql, (RowMapper<ScopeDTO>) (resultSet, i) -> {

                List<String> claimsList = new ArrayList<>();
                String scope = resultSet.getString(1);
                if (!scopeClaimMap.containsKey(scope)) {
                    claimsList.add(resultSet.getString(2));
                    scopeClaimMap.put(scope, claimsList);
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
            oidcScopeClaimList = buildScopeDTO(scopeClaimMap, tenantId);
        } catch (DataAccessException e) {
            String errorMessage = "Error occured while loading scopes claims mapping.";
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return oidcScopeClaimList;
    }

    private List<ScopeDTO> buildScopeDTO(Map<String, List<String>> scopeClaimMap, int tenantId) {

        List<ScopeDTO> oidcScopeClaimList = new ArrayList<>();
        for (Map.Entry<String, List<String>> scopeClaimEntry : scopeClaimMap.entrySet()) {
            ScopeDTO scopeDTO = new ScopeDTO();
            String scopeName = scopeClaimEntry.getKey();
            List<String> claimsList = scopeClaimEntry.getValue();
            scopeDTO.setName(scopeClaimEntry.getKey());
            if (CollectionUtils.isNotEmpty(claimsList)) {
                scopeDTO.setClaim(claimsList.toArray(new String[claimsList.size()]));
            }
            oidcScopeClaimList.add(scopeDTO);
            if (log.isDebugEnabled()) {
                String message = "loaded  for the tenant: ";
                logMessage(scopeName, claimsList, tenantId, message);
            }
        }
        return oidcScopeClaimList;
    }

    @Override
    public List<String> loadScopes(int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_SCOPES;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<String> scopeList = new ArrayList<>();
        try {

            jdbcTemplate.executeQuery(sql, (RowMapper<ScopeDTO>) (resultSet, i) -> {

                String scopes = resultSet.getString(1);
                scopeList.add(scopes);
                return null;
            }, preparedStatement ->
                    preparedStatement.setInt(1, tenantId));
            if (log.isDebugEnabled()) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String scope : scopeList) {
                    stringBuilder.append(scope);
                    stringBuilder.append(",");
                }
                int commaPosition = stringBuilder.toString().lastIndexOf(",");
                String scopes = stringBuilder.toString().substring(0, commaPosition);
                log.debug("The scopes: " + scopes + "are successfully loaded for the tenant: " + tenantId);
            }
        } catch (DataAccessException e) {
            String errorMessage = "Error while loading OIDC scopes.";
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return scopeList;
    }

    @Override
    public List<String> loadClaims(int tenantId, String scope) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_CLAIMS;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<String> claimsList = new ArrayList<>();
        try {

            jdbcTemplate.executeQuery(sql, (RowMapper<ScopeDTO>) (resultSet, i) -> {

                String claims = resultSet.getString(1);
                claimsList.add(claims);
                return null;
            }, preparedStatement ->
            {
                preparedStatement.setInt(1, tenantId);
                preparedStatement.setString(2, scope);
            });
            if (log.isDebugEnabled()) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String claim : claimsList) {
                    stringBuilder.append(claim);
                    stringBuilder.append(",");
                }
                int commaPosition = stringBuilder.toString().lastIndexOf(",");
                String claims = stringBuilder.toString().substring(0, commaPosition);
                log.debug("The claims: " + claims + "are successfully loaded for the tenant: " + tenantId);
            }
        } catch (DataAccessException e) {
            String errorMessage = "Error while loading OIDC claims for the scope: " + scope;
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return claimsList;
    }

    @Override
    public void deleteScopeAndClaims(String scope, int tenantId) throws IdentityOAuthAdminException {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            jdbcTemplate.executeUpdate(SQLQueries.DELETE_SCOPE_CLAIM_MAPPING, preparedStatement -> {
                        preparedStatement.setString(1, scope);
                        preparedStatement.setInt(2, tenantId);
                    }

            );
            if (log.isDebugEnabled()) {
                log.debug("The scope: " + scope + "in the tenant: " + tenantId + "is successfully deleted.");
            }
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
                        int scopeId = loadScopeId(scope, tenantId);
                        for (String claim : claims) {
                            //Get the claim id for the related claim_uri
                            int claimId = loadOIDCClaimId(claim);

                            preparedStatement.setInt(1, scopeId);
                            preparedStatement.setInt(2, claimId);
                            preparedStatement.addBatch();
                        }
                    } catch (IdentityOAuth2Exception e) {
                        String errorMessage = "Error while fetching scope id and claims id for scope: " + scope;
                        log.error(errorMessage);
                    }

                }), scopeClaimMappingId);
                return null;
            });
            if (log.isDebugEnabled()) {
                String message = "inserted for the tenant: ";
                logMessage(scope, claims, tenantId, message);
            }
        } catch (TransactionException e) {
            String errorMsg = "Error while inserting new claims for the scope: " + scope;
            log.error(errorMsg);
            throw new IdentityOAuth2Exception(errorMsg, e);
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
            if (log.isDebugEnabled()) {
                log.debug("Scope id: " + id + "is returned for the tenant: " + tenantId);
            }
        } catch (TransactionException e) {
            String errorMessage = "Error while loading the top scope id.";
            log.error(errorMessage);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return id;
    }

    public int loadScopeId(String scope, int tenantId) throws IdentityOAuth2Exception {

        Integer scopeId;
        try {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            scopeId = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_IDN_OIDC_SCOPE_ID, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setString(1, scope);
                        preparedStatement.setInt(2, tenantId);
                    }));
            if (scopeId == null) {
                scopeId = -1;
            }
            if (log.isDebugEnabled()) {
                log.debug("Scope id: " + scopeId + "is returned for the tenant: " + tenantId + "and scope: " + scope);
            }
        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + scope;
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return scopeId;
    }

    public boolean isScopeClaimMappingExisting(String scope, String claim, int tenantId) {

        Integer scopeId;
        try {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            scopeId = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_IDN_OIDC_SCOPE_ID_FOR_SCOPE, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setInt(1, tenantId);
                        preparedStatement.setString(2, scope);
                        preparedStatement.setString(3, claim);
                    }));
            if (log.isDebugEnabled()) {
                log.debug("Scope id: " + scopeId + "is returned for the tenant: " + tenantId + "and scope: " + scope +
                        "and the claim: " + claim);
            }
            if (scopeId == null) {
                return false;
            }

        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + scope;
            log.error(errorMessage, e);
            return false;
        }

        return true;
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
            if (log.isDebugEnabled()) {
                log.debug("Claim id: " + oidcClaimId + "is returned.");
            }
        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + claim;
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return oidcClaimId;
    }

    private void logMessage(String scope, List<String> claims, int tenantId, String message) {

        StringBuilder stringBuilder = new StringBuilder();
        for (String oidcClaim : claims) {
            stringBuilder.append(oidcClaim);
            stringBuilder.append(",");
        }
        int commaPosition = stringBuilder.toString().lastIndexOf(",");
        String claimsList = stringBuilder.toString().substring(0, commaPosition);
        log.debug("The scope: " + scope + " and the claims: " + claimsList + "are successfully " + message +
                tenantId);
    }

    private void insertAllClaims(int tenantId, int scopeId, Set<String> claimsList) throws IdentityOAuth2Exception {

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
}
