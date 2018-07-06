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

import static org.wso2.carbon.identity.core.util.LambdaExceptionUtils.rethrowConsumer;

/**
 * Default implementation of {@link ScopeClaimMappingDAO}. This handles {@link ScopeDTO} related db layer operations.
 */
public class ScopeClaimMappingDAOImpl implements ScopeClaimMappingDAO {

    private final Log log = LogFactory.getLog(ScopeClaimMappingDAOImpl.class);

    @Override
    public void addScopes(int tenantId, List<ScopeDTO> scopeClaimsList) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        scopeClaimsList.forEach(rethrowConsumer(scopeDTO -> {
            String scope = scopeDTO.getName();
            String[] claims = scopeDTO.getClaim();
            try {
                if (!isScopeExist(scope, tenantId)) {
                    int scopeClaimMappingId = jdbcTemplate.withTransaction(tempate ->
                            tempate.executeInsert(SQLQueries.STORE_IDN_OIDC_SCOPES,
                                    (preparedStatement -> {
                                        preparedStatement.setString(1, scope);
                                        preparedStatement.setInt(2, tenantId);
                                    }), null, true));
                    if (scopeClaimMappingId > 0 && ArrayUtils.isNotEmpty(claims)) {
                        Set<String> claimsSet = new HashSet<>(Arrays.asList(claims));
                        insertClaims(tenantId, scopeClaimMappingId, claimsSet);
                    }
                    if (log.isDebugEnabled() && ArrayUtils.isNotEmpty(claims)) {
                        log.debug("The scope: " + scope + " and the claims: " + Arrays.asList(claims) + "are successfully" +
                                " inserted for the tenant: " + tenantId);
                    }
                } else {
                    String errorMessage = "Error while adding scopes. Duplicate scopes can not be added for the tenant: "
                            + tenantId;
                    throw new IdentityOAuth2Exception(errorMessage);
                }
            } catch (TransactionException e) {
                String errorMessage = "Error while persisting new claims for the scope for the tenant: " + tenantId;
                throw new IdentityOAuth2Exception(errorMessage, e);
            }

        }));
    }

    @Override
    public void addScope(int tenantId, String scope, String[] claims) throws IdentityOAuth2Exception {

        if (!isScopeExist(scope, tenantId)) {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            try {
                int scopeClaimMappingId = jdbcTemplate.executeInsert(SQLQueries.STORE_IDN_OIDC_SCOPES,
                        (preparedStatement -> {
                            preparedStatement.setString(1, scope);
                            preparedStatement.setInt(2, tenantId);
                        }), null, true);
                if (scopeClaimMappingId > 0 && ArrayUtils.isNotEmpty(claims)) {
                    Set<String> claimsSet = new HashSet<>(Arrays.asList(claims));
                    insertClaims(tenantId, scopeClaimMappingId, claimsSet);
                }
                if (log.isDebugEnabled() && ArrayUtils.isNotEmpty(claims)) {
                    log.debug("The scope: " + scope + " and the claims: " + Arrays.asList(claims) + "are successfully" +
                            " inserted for the tenant: " + tenantId);
                }
            } catch (DataAccessException e) {
                String errorMessage = "Error while persisting scopes for the tenant: " + tenantId;
                throw new IdentityOAuth2Exception(errorMessage, e);
            }
        } else {
            String errorMessage = "The Scope: " + scope + " is already existing.";
            throw new IdentityOAuth2Exception(errorMessage);
        }
    }

    @Override
    public List<ScopeDTO> getScopes(int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_SCOPES_CLAIMS;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<ScopeDTO> oidcScopeClaimList;
        try {
            Map<String, List<String>> scopeClaimMap = new HashMap<>();
            jdbcTemplate.executeQuery(sql, (RowMapper<ScopeDTO>) (resultSet, i) -> {
                List<String> claimsList;

                String scope = resultSet.getString(1);
                if (!scopeClaimMap.containsKey(scope)) {
                    claimsList = new ArrayList<>();
                    claimsList.add(resultSet.getString(2));
                    scopeClaimMap.put(scope, claimsList);
                } else {
                    claimsList = scopeClaimMap.get(scope);
                    claimsList.add(resultSet.getString(2));
                    scopeClaimMap.put(scope, claimsList);
                }
                return null;
            }, preparedStatement ->
            {
                preparedStatement.setInt(1, tenantId);
                preparedStatement.setInt(2, tenantId);
            });
            oidcScopeClaimList = buildScopeDTO(scopeClaimMap, tenantId);
        } catch (DataAccessException e) {
            String errorMessage = "Error occured while loading scopes claims mapping.";
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return oidcScopeClaimList;
    }

    @Override
    public List<String> getScopeNames(int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_SCOPES;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            List<String> scopeList = jdbcTemplate.executeQuery(sql, (resultSet, i) -> resultSet.getString(1),
                    preparedStatement -> preparedStatement.setInt(1, tenantId));
            if (log.isDebugEnabled()) {
                log.debug("The scopes: " + String.join(",", scopeList) + " are successfully loaded for the tenant: " +
                        tenantId);
            }
            return scopeList;
        } catch (DataAccessException e) {
            String errorMessage = "Error while loading OIDC scopes.";
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
    }

    @Override
    public ScopeDTO getClaims(String scope, int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_CLAIMS;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        ScopeDTO scopeDTO = new ScopeDTO();
        try {
            List<String> claimsList = jdbcTemplate.executeQuery(sql, (resultSet, i) -> resultSet.getString(1)
                    , preparedStatement ->
                    {
                        preparedStatement.setString(1, scope);
                        preparedStatement.setInt(2, tenantId);
                    });
            scopeDTO.setName(scope);
            String[] claimsArr = new String[claimsList.size()];
            scopeDTO.setClaim(claimsList.toArray(claimsArr));
        } catch (DataAccessException e) {
            String errorMessage = "Error while loading OIDC claims for the scope: " + scope;
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return scopeDTO;
    }

    @Override
    public void deleteScope(String scope, int tenantId) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            if (isScopeExist(scope, tenantId)) {
                jdbcTemplate.executeUpdate(SQLQueries.DELETE_SCOPE_CLAIM_MAPPING, preparedStatement -> {
                            preparedStatement.setString(1, scope);
                            preparedStatement.setInt(2, tenantId);
                        }
                );
                if (log.isDebugEnabled()) {
                    log.debug("The scope: " + scope + "in the tenant: " + tenantId + "is successfully deleted.");
                }
            } else {
                String errorMessage = "The scope: " + scope + "does not exist to delete.";
                throw new IdentityOAuth2Exception(errorMessage);
            }
        } catch (DataAccessException e) {
            throw new IdentityOAuth2Exception("Error while deleting the scope: " + scope + " and related claims.", e);
        }
    }

    @Override
    public void updateScope(String scope, int tenantId, List<String> addClaims, List<String> deleteClaims)
            throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        int scopeClaimMappingId = -1;
        try {
            if (CollectionUtils.isNotEmpty(addClaims)) {
                int scopeId = getScopeId(scope, tenantId);
                addClaimsByScope(scopeId, tenantId, addClaims, jdbcTemplate, scopeClaimMappingId);
            }
            if (CollectionUtils.isNotEmpty(deleteClaims)) {
                deleteClaimsByScope(scope, tenantId, deleteClaims, jdbcTemplate, scopeClaimMappingId);
            }
        } catch (TransactionException e) {
            String errorMsg = "Error while inserting new claims for the scope: " + scope;
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    private void addClaimsByScope(int scopeId, int tenantId, List<String> claims, JdbcTemplate jdbcTemplate, int
            scopeClaimMappingId) throws TransactionException {

        jdbcTemplate.withTransaction(template -> {
            template.executeBatchInsert(SQLQueries.INSERT_NEW_CLAIMS_FOR_SCOPE, (preparedStatement -> {

                try {
                    for (String claim : claims) {
                        //Get the claim id for the related claim_uri
                        int claimId = loadOIDCClaimId(claim, tenantId);

                        preparedStatement.setInt(1, scopeId);
                        preparedStatement.setInt(2, claimId);
                        preparedStatement.addBatch();
                    }
                } catch (IdentityOAuth2Exception e) {
                    String errorMessage = "Error while fetching claims id. ";
                    log.error(errorMessage);
                }

            }), scopeClaimMappingId);
            return null;
        });
    }

    private void deleteClaimsByScope(String scope, int tenantId, List<String> claims, JdbcTemplate jdbcTemplate,
                                     int scopeClaimMappingId) throws TransactionException {

        jdbcTemplate.withTransaction(template -> {
            template.executeBatchInsert(SQLQueries.DELETE_CLAIMS_FROM_SCOPE, (preparedStatement -> {
                //Get the scope id of the existing scope.
                for (String claim : claims) {
                    preparedStatement.setString(1, scope);
                    preparedStatement.setString(2, claim);
                    preparedStatement.setInt(3, tenantId);
                    preparedStatement.setString(4, scope);
                    preparedStatement.addBatch();
                }

            }), scopeClaimMappingId);
            return null;
        });
    }

    public boolean hasScopesPopulated(int tenantId) throws IdentityOAuth2Exception {

        Integer id;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            id = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_ALL_IDN_OIDC_SCOPES, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setInt(1, tenantId);
                    }));
            if (id == 0) {
                return false;
            }
            if (log.isDebugEnabled()) {
                log.debug("Scope id: " + id + "is returned for the tenant: " + tenantId);
            }
        } catch (TransactionException e) {
            String errorMessage = "Error while loading the top scope id for the tenant: " + tenantId;
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return true;
    }

    @Override
    public boolean isScopeExist(String scope, int tenantId) throws IdentityOAuth2Exception {

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
                return false;
            }
            if (log.isDebugEnabled()) {
                log.debug("Scope id: " + scopeId + "is returned for the tenant: " + tenantId + "and scope: " + scope);
            }
        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + scope;
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return true;
    }

    private int getScopeId(String scope, int tenantId) throws IdentityOAuth2Exception {

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
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return scopeId;
    }

    private int loadOIDCClaimId(String claim, int tenantId) throws IdentityOAuth2Exception {

        Integer oidcClaimId;
        try {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            oidcClaimId = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_OIDC_CLAIM_ID, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setString(1, claim);
                        preparedStatement.setInt(2, tenantId);
                    }));
            if (oidcClaimId == null) {
                oidcClaimId = -1;
            }
            if (log.isDebugEnabled()) {
                log.debug("Claim id: " + oidcClaimId + "is returned.");
            }
        } catch (TransactionException e) {
            String errorMessage = "Error fetching data for oidc scope: " + claim;
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return oidcClaimId;
    }

    private void insertClaims(int tenantId, int scopeId, Set<String> claimsList) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        int scopeClaimMappingId = -1;
        try {
            jdbcTemplate.withTransaction(template -> {
                template.executeBatchInsert(SQLQueries.STORE_IDN_OIDC_CLAIMS, (preparedStatement -> {
                    if (CollectionUtils.isNotEmpty(claimsList)) {
                        for (String claim : claimsList) {
                            preparedStatement.setInt(1, scopeId);
                            preparedStatement.setString(2, claim);
                            preparedStatement.setInt(3, tenantId);
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
            String errorMessage = "Error when storing oidc claims for tenant: " + tenantId;
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
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
                log.debug("The scope: " + scopeName + " and the claims: " + String.join(",", claimsList) + "are successfully" +
                        " loaded for the tenant: " + tenantId);
            }
        }
        return oidcScopeClaimList;
    }
}
