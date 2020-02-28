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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.util.JdbcUtils;

import java.sql.SQLIntegrityConstraintViolationException;
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

    private static final Log log = LogFactory.getLog(ScopeClaimMappingDAOImpl.class);
    private static final String OIDC_DIALECT_URI = "http://wso2.org/oidc/claim";

    @Override
    public void addScopes(int tenantId, List<ScopeDTO> scopeClaimsList) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        scopeClaimsList.forEach(rethrowConsumer(scopeDTO -> {
            String scope = scopeDTO.getName();
            String[] claims = scopeDTO.getClaim();
            // We maintain the scope name as unique. We won't allow registering same scope name across OAuth2 and OIDC
            // scope endpoints. Hence we need to validate scope name exists or not across these two endpoints. If scope
            // name is exist will throw conflict error.
            if (!isScopeExist(scope, tenantId, true)) {
                try {
                    int scopeClaimMappingId = jdbcTemplate.executeInsert(SQLQueries.STORE_IDN_OAUTH2_SCOPE,
                            (preparedStatement -> {
                                preparedStatement.setString(1, scope);
                                preparedStatement.setString(2, scopeDTO.getDisplayName());
                                preparedStatement.setString(3, scopeDTO.getDescription());
                                preparedStatement.setInt(4, tenantId);
                                preparedStatement.setString(5, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
                            }), null, true, Oauth2ScopeConstants.SCOPE_ID);
                    if (scopeClaimMappingId > 0 && ArrayUtils.isNotEmpty(claims)) {
                        Set<String> claimsSet = new HashSet<>(Arrays.asList(claims));
                        insertClaims(tenantId, scopeClaimMappingId, claimsSet);
                    }
                    if (log.isDebugEnabled() && ArrayUtils.isNotEmpty(claims)) {
                        log.debug("The scope: " + scope + " and the claims: " + Arrays.asList(claims) + "are " +
                                "successfully inserted for the tenant: " + tenantId);
                    }
                } catch (DataAccessException e) {
                    if (e.getCause() instanceof SQLIntegrityConstraintViolationException) {
                        int scopeClaimMappingId = getScopeId(scope, tenantId);
                        if (scopeClaimMappingId > 0) {
                            log.warn("Scope " + scope + " already exist in tenant " + tenantId + " , hence ignoring");
                            return;
                        }
                    } else {
                        String errorMessage =
                                "Error while persisting new claims for the scope for the tenant: " + tenantId;
                        throw new IdentityOAuth2Exception(errorMessage, e);
                    }
                }

            } else {
                log.warn(String.format("Scope %s already exist in tenant %s.", scope, tenantId));
                throw new IdentityOAuth2ClientException(
                        Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getCode(),
                        String.format(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE
                                .getMessage(), scope));
            }
        }));
    }

    @Deprecated
    public void addScope(int tenantId, String scope, String[] claims) throws IdentityOAuth2Exception {

        // Since display name is mandatory add scope name as a displayName.
        ScopeDTO scopeDTO = new ScopeDTO(scope, scope, null, claims);
        addScope(scopeDTO, tenantId);
    }

    /**
     * To add OIDC scope for a specific tenant.
     *
     * @param scope    Scope.
     * @param tenantId Tenant Id.
     * @throws IdentityOAuth2Exception If an error occurs when adding a scope.
     */
    @Override
    public void addScope(ScopeDTO scope, int tenantId) throws IdentityOAuth2Exception {

        // We maintain the scope name as unique. We won't allow registering same scope name across OAuth2 and OIDC
        // scope endpoints. Hence we need to validate scope name exists or not across these two endpoints. If scope
        // name is exist will throw conflict error.
        if (!isScopeExist(scope.getName(), tenantId, true)) {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            try {
                int scopeClaimMappingId = jdbcTemplate.executeInsert(SQLQueries.STORE_IDN_OAUTH2_SCOPE,
                        (preparedStatement -> {
                            preparedStatement.setString(1, scope.getName());
                            preparedStatement.setString(2, scope.getDisplayName());
                            preparedStatement.setString(3, scope.getDescription());
                            preparedStatement.setInt(4, tenantId);
                            preparedStatement.setString(5, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
                        }), null, true, Oauth2ScopeConstants.SCOPE_ID);
                if (scopeClaimMappingId > 0 && ArrayUtils.isNotEmpty(scope.getClaim())) {
                    Set<String> claimsSet = new HashSet<>(Arrays.asList(scope.getClaim()));
                    insertClaims(tenantId, scopeClaimMappingId, claimsSet);
                }
                if (log.isDebugEnabled() && ArrayUtils.isNotEmpty(scope.getClaim())) {
                    log.debug(String.format("The scope %s and the claims %s are successfully inserted for the tenant:" +
                            " %s", scope.getName(), Arrays.asList(scope.getClaim()), tenantId));
                }
            } catch (DataAccessException e) {
                String errorMessage = "Error while persisting scopes for the tenant: " + tenantId;
                throw new IdentityOAuth2Exception(errorMessage, e);
            }
        } else {
            log.warn(String.format("Scope %s already exist in tenant %s.", scope.getName(), tenantId));
            throw new IdentityOAuth2ClientException(
                    Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getCode(),
                    String.format(
                            Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getMessage(),
                            scope.getName()));
        }
    }

    @Override
    public List<ScopeDTO> getScopes(int tenantId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.GET_IDN_OIDC_SCOPES_CLAIMS;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<ScopeDTO> oidcScopeClaimList;
        try {
            Map<String, ScopeDTO> scopeClaimMap = new HashMap<>();
            jdbcTemplate.executeQuery(sql, (RowMapper<ScopeDTO>) (resultSet, i) -> {

                String scope = resultSet.getString(1);
                if (!scopeClaimMap.containsKey(scope)) {
                    ScopeDTO tempScopeDTO =
                            new ScopeDTO(scope, resultSet.getString(2), resultSet.getString(3), new String[]{});
                    if (resultSet.getString(4) != null) {
                        tempScopeDTO.setClaim(new String[]{resultSet.getString(4)});
                    }
                    scopeClaimMap.put(scope, tempScopeDTO);
                } else {
                    if (resultSet.getString(4) != null) {
                        ScopeDTO tempScope = scopeClaimMap.get(scope);
                        tempScope.addNewClaimToExistingClaims(resultSet.getString(4));
                        scopeClaimMap.replace(scope, tempScope);
                    }
                }
                return null;
            }, preparedStatement -> {
                preparedStatement.setInt(1, tenantId);
                preparedStatement.setString(2, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
                preparedStatement.setInt(3, tenantId);
                preparedStatement.setInt(4, tenantId);
                preparedStatement.setString(5, OIDC_DIALECT_URI);
            });
            oidcScopeClaimList = new ArrayList<ScopeDTO>(scopeClaimMap.values());
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
                    preparedStatement -> {
                        preparedStatement.setInt(1, tenantId);
                        preparedStatement.setString(2, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
                    });
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
                    , preparedStatement -> {
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
                jdbcTemplate.executeUpdate(SQLQueries.DELETE_SCOPE_AND_CLAIM_MAPPING, preparedStatement -> {
                    preparedStatement.setString(1, scope);
                    preparedStatement.setInt(2, tenantId);
                    preparedStatement.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
                });
                if (log.isDebugEnabled()) {
                    log.debug(String.format("The scope: %s in the tenant: %s is successfully deleted.", scope,
                            tenantId));
                }
            } else {
                String errorMessage = "The scope: " + scope + " does not exist to delete.";
                throw new IdentityOAuth2Exception(errorMessage);
            }
        } catch (DataAccessException e) {
            throw new IdentityOAuth2Exception("Error while deleting the scope: " + scope + " and related claims.", e);
        }
    }

    @Deprecated
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

    /**
     * To add new claims for an existing scope.
     *
     * @param scope    Updated scope name.
     * @param tenantId Tenant Id.
     * @throws IdentityOAuth2Exception If an error occurs when adding a new claim for a scope.
     */
    @Override
    public void updateScope(ScopeDTO scope, int tenantId) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        try {
            int scopeId = getScopeId(scope.getName(), tenantId);
            if (scopeId != Oauth2ScopeConstants.INVALID_SCOPE_ID) {
                updateScopeDetails(scope, jdbcTemplate, scopeId);
                deleteClaimMappings(scopeId, jdbcTemplate);
                Set<String> claimsSet = new HashSet<>(Arrays.asList(scope.getClaim()));
                insertClaims(tenantId, scopeId, claimsSet);
            }
        } catch (DataAccessException e) {
            throw new IdentityOAuth2Exception(
                    "Error while updating the scope: " + scope.getName() + " and it's related claims.", e);
        }
    }

    /**
     * Delete existing OIDC claim mapping of a scope.
     *
     * @param jdbcTemplate JDBC template.
     * @throws DataAccessException
     */
    private void deleteClaimMappings(int scopeId, JdbcTemplate jdbcTemplate) throws DataAccessException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting existing OIDC claim mapping of scopeID: " + scopeId);
        }
        jdbcTemplate.executeUpdate(SQLQueries.DELETE_CLAIM_MAPPING_OF_SCOPE, preparedStatement -> {
            preparedStatement.setInt(1, scopeId);
        });
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
                    log.error(errorMessage, e);
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
                    preparedStatement.setString(5, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
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
                        preparedStatement.setString(2, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
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

        int scopeId = getScopeId(scope, tenantId);
        return scopeId != Oauth2ScopeConstants.INVALID_SCOPE_ID;
    }

    /**
     * Get OIDC scope details by scope name.
     *
     * @param scopeName Scope name.
     * @param tenantId  Tenant ID.
     * @return OIDC scope object.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public ScopeDTO getScope(String scopeName, int tenantId) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        String sql = SQLQueries.GET_IDN_OIDC_SCOPE_DETAILS;

        try {
            Map<String, ScopeDTO> tempScopeMap = new HashMap<>();
            jdbcTemplate.executeQuery(sql, (RowMapper<ScopeDTO>) (resultSet, i) -> {

                if (!tempScopeMap.containsKey(resultSet.getString(1))) {
                    ScopeDTO scopeDTO = new ScopeDTO(resultSet.getString(1), resultSet.getString(2),
                            resultSet.getString(3), new String[]{});
                    if (resultSet.getString(4) != null) {
                        scopeDTO.setClaim(new String[]{resultSet.getString(4)});
                    }
                    tempScopeMap.put(resultSet.getString(1), scopeDTO);
                } else {
                    if (resultSet.getString(4) != null) {
                        ScopeDTO tempScope = tempScopeMap.get(resultSet.getString(1));
                        tempScope.addNewClaimToExistingClaims(resultSet.getString(4));
                        tempScopeMap.replace(resultSet.getString(1), tempScope);
                    }
                }
                return null;
            }, preparedStatement -> {
                preparedStatement.setString(1, scopeName);
                preparedStatement.setInt(2, tenantId);
                preparedStatement.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
                preparedStatement.setInt(4, tenantId);
                preparedStatement.setInt(5, tenantId);
                preparedStatement.setString(6, OIDC_DIALECT_URI);
            });
            return tempScopeMap.get(scopeName);
        } catch (DataAccessException e) {
            String errorMessage = "Error while fetching scope details for scope: " + scopeName;
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
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
                        preparedStatement.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OIDC);
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

    /**
     * To check whether the scope is existing depends on the scope type.
     *
     * @param scope               Scope name.
     * @param tenantId            Tenant ID.
     * @param includeOAuth2Scopes Include OAUTH2 scopes as well in search.
     * @return True if the scope is already existing.
     * @throws IdentityOAuth2Exception
     */
    private boolean isScopeExist(String scope, int tenantId, boolean includeOAuth2Scopes)
            throws IdentityOAuth2Exception {

        int scopeId;

        if (includeOAuth2Scopes) {
            scopeId = getScopeIdWithoutScopeType(scope, tenantId);
        } else {
            scopeId = getScopeId(scope, tenantId);
        }
        return scopeId != Oauth2ScopeConstants.INVALID_SCOPE_ID;
    }

    /**
     * Obtain scope ID for proivded scope name regardless of scope type.
     *
     * @param scope    Scope name.
     * @param tenantId Tenant ID.
     * @return Scope ID.
     * @throws IdentityOAuth2Exception
     */
    private int getScopeIdWithoutScopeType(String scope, int tenantId) throws IdentityOAuth2Exception {

        Integer scopeId;

        try {
            JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
            scopeId = jdbcTemplate.withTransaction(template -> template.fetchSingleRecord
                    (SQLQueries.GET_IDN_OIDC_SCOPE_ID_WITHOUT_SCOPE_TYPE, (resultSet, rowNumber) ->
                            resultSet.getInt(1), preparedStatement -> {
                        preparedStatement.setString(1, scope);
                        preparedStatement.setInt(2, tenantId);
                    }));
            if (scopeId == null) {
                scopeId = Oauth2ScopeConstants.INVALID_SCOPE_ID;
            }
            if (log.isDebugEnabled()) {
                log.debug("Scope id: " + scopeId + "is returned for the tenant: " + tenantId + "and scope: " + scope);
            }
        } catch (TransactionException e) {
            String errorMessage = "Error while obtaining ID of scope: " + scope;
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
                        preparedStatement.setString(3, OIDC_DIALECT_URI);
                        preparedStatement.setInt(4, tenantId);
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
            String errorMessage = String.format("Error when storing oidc claims for scope ID: %s for tenant: %s",
                    scopeId, tenantId);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
    }

    /**
     * Update scope details on IDN_OAUTH2_SCOPE scope table.
     *
     * @param updatedScope Updated scope.
     * @param jdbcTemplate JDBC template.
     * @param scopeId      Scope ID.
     * @throws DataAccessException
     */
    private void updateScopeDetails(ScopeDTO updatedScope, JdbcTemplate jdbcTemplate, int scopeId)
            throws DataAccessException {

        if (log.isDebugEnabled()) {
            log.debug("Update scope details on IDN_OAUTH2_SCOPE scope table for scope: " + updatedScope.getName());
        }

        // Update scope details on IDN_OAUTH2_SCOPE table.
        jdbcTemplate.executeUpdate(SQLQueries.UPDATE_IDN_OAUTH2_SCOPE, preparedStatement -> {
            preparedStatement.setString(1, updatedScope.getDisplayName());
            preparedStatement.setString(2, updatedScope.getDescription());
            preparedStatement.setInt(3, scopeId);
        });
    }
}
