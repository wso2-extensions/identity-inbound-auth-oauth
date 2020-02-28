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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.util.NamedPreparedStatement;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.utils.DBUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.DEFAULT_SCOPE_BINDING;

/**
 * OAuth scope management data access object implementation.
 */
public class OAuthScopeDAOImpl implements OAuthScopeDAO {

    private static final Log log = LogFactory.getLog(OAuthScopeDAOImpl.class);

    /**
     * Add a scope
     *
     * @param scope    Scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2ScopeException IdentityOAuth2ScopeException
     */
    @Override
    public void addScope(Scope scope, int tenantID) throws IdentityOAuth2ScopeException {

        if (scope == null) {
            if (log.isDebugEnabled()) {
                log.debug("Scope is not defined");
            }

            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        if (log.isDebugEnabled()) {
            log.debug("Adding scope :" + scope.getName());
        }

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {
            try {
                addScope(scope, conn, tenantID);
                IdentityDatabaseUtil.commitTransaction(conn);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                String msg = "SQL error occurred while creating scope :" + scope.getName();
                throw new IdentityOAuth2ScopeServerException(msg, e1);
            }
        } catch (SQLException e) {
            String msg = "Error occurred while creating scope :" + scope.getName();
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get all available OAuth2 scopes.
     *
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public Set<Scope> getAllScopes(int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get all scopes for tenantId  :" + tenantID);
        }

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();
        String sql;

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            if (conn.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_ALL_OAUTH2_SCOPES_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_ALL_OAUTH2_SCOPES;
            }

            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, tenantID);
                ps.setString(2, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String displayName = rs.getString(3);
                        String description = rs.getString(4);
                        final String binding = rs.getString(5);
                        String bindingType = rs.getString(6);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
                            scopeMap.get(scopeID).setDisplayName(displayName);
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        } else {
                            scopeMap.put(scopeID, new Scope(name, displayName, new ArrayList<>(), description));
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        }
                    }
                }
            }

            for (Map.Entry<Integer, Scope> entry : scopeMap.entrySet()) {
                scopes.add(entry.getValue());
            }
            return scopes;
        } catch (SQLException e) {
            String msg = "Error occurred while getting all OAUTH2 scopes in tenant :" + tenantID;
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get all available scopes depends on scope type.
     *
     * @param tenantID          Tenant ID.
     * @param includeOIDCScopes Include OIDC scopes in the scope list.
     * @return List of scopes.
     * @throws IdentityOAuth2ScopeServerException
     */
    @Override
    public Set<Scope> getAllScopes(int tenantID, Boolean includeOIDCScopes) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get all scopes for tenantId  :" + tenantID + " including OIDC scope: " + includeOIDCScopes);
        }

        if (includeOIDCScopes) {
            // Get all scopes including OIDC scopes as well.
            return getAllScopesIncludingOIDCScopes(tenantID);
        } else {
            // Return all OAuth2 scopes only.
            return getAllScopes(tenantID);
        }
    }

    /**
     * Get all scopes including OAuth2 scopes and OIDC scopes as well.
     *
     * @param tenantID Tenant ID.
     * @return List of scopes.
     * @throws IdentityOAuth2ScopeServerException
     */
    private Set<Scope> getAllScopesIncludingOIDCScopes(int tenantID)
            throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get all scopes including OAUTH2 and OIDC scopes for tenantId  :" + tenantID);
        }

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();
        String sql;

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            if (conn.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_ALL_SCOPES_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_ALL_SCOPES;
            }

            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, tenantID);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String displayName = rs.getString(3);
                        String description = rs.getString(4);
                        final String binding = rs.getString(5);
                        String bindingType = rs.getString(6);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
                            scopeMap.get(scopeID).setDisplayName(displayName);
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        } else {
                            scopeMap.put(scopeID, new Scope(name, displayName, new ArrayList<>(), description));
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        }
                    }
                }
            }

            for (Map.Entry<Integer, Scope> entry : scopeMap.entrySet()) {
                scopes.add(entry.getValue());
            }
            return scopes;
        } catch (SQLException e) {
            String msg = "Error occurred while getting all scopes in tenant :" + tenantID;
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    @Override
    public Set<Scope> getRequestedScopesOnly(int tenantID, Boolean includeOIDCScopes, String requestedScopes)
            throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Get requested scopes for scopes: %s for tenantId: %s with includeOIDCScopes: %s",
                    requestedScopes, tenantID, includeOIDCScopes));
        }

        String sql;
        if (includeOIDCScopes) {
            sql = String.format(SQLQueries.RETRIEVE_REQUESTED_ALL_SCOPES_WITHOUT_SCOPE_TYPE);
        } else {
            sql = String.format(SQLQueries.RETRIEVE_REQUESTED_OAUTH2_SCOPES);
        }

        List<String> requestedScopeList = Arrays.asList(requestedScopes.split("\\s+"));
        String sqlIN = requestedScopeList.stream().map(x -> String.valueOf(x))
                .collect(Collectors.joining("\', \'", "(\'", "\')"));

        sql = sql.replace("(?)", sqlIN);

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, tenantID);
                if (!includeOIDCScopes) {
                    ps.setString(2, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
                }
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String displayName = rs.getString(3);
                        String description = rs.getString(4);
                        final String binding = rs.getString(5);
                        String bindingType = rs.getString(6);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
                            scopeMap.get(scopeID).setDisplayName(displayName);
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        } else {
                            scopeMap.put(scopeID, new Scope(name, displayName, new ArrayList<>(), description));
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        }
                    }
                }
            }

            for (Map.Entry<Integer, Scope> entry : scopeMap.entrySet()) {
                scopes.add(entry.getValue());
            }
            return scopes;
        } catch (SQLException e) {
            String msg = "Error occurred while getting requested scopes in tenant :" + tenantID;
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    @Override
    public Set<Scope> getScopes(int tenantID, String bindingType) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get scopes for tenantId  :" + tenantID + " and bindingType: " + bindingType);
        }

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPES_BY_BINDING_TYPE)) {
                ps.setInt(1, tenantID);
                ps.setString(2, bindingType);
                ps.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String displayName = rs.getString(3);
                        String description = rs.getString(4);
                        final String binding = rs.getString(5);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
                            scopeMap.get(scopeID).setDisplayName(displayName);
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        } else {
                            scopeMap.put(scopeID, new Scope(name, displayName, new ArrayList<>(), description));
                            if (binding != null) {
                                scopeMap.get(scopeID).addScopeBinding(bindingType, binding);
                            }
                        }
                    }
                }
            }

            for (Map.Entry<Integer, Scope> entry : scopeMap.entrySet()) {
                scopes.add(entry.getValue());
            }
            return scopes;
        } catch (SQLException e) {
            String msg = "Error occurred while getting all scopes ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get only OAUTH2 Scopes with pagination.
     *
     * @param offset   start index of the result set
     * @param limit    number of elements of the result set
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID)
            throws IdentityOAuth2ScopeServerException {

        // Default we won't reterive OIDC scopes via OAUTH2 endpoint. Hence includeOIDCScopes set to false.
        return getScopesWithPagination(offset, limit, tenantID, false);
    }

    /**
     * Get SQL statement for get OAuth2 scope with pagination.
     *
     * @param offset   Offset.
     * @param limit    Limit.
     * @param tenantID Tenet ID.
     * @param conn     Database connection.
     * @return
     * @throws SQLException
     */
    private NamedPreparedStatement getPreparedStatementForGetScopesWithPagination(Integer offset, Integer limit,
                                                                                  int tenantID, Connection conn)
            throws SQLException {

        String query;
        if (conn.getMetaData().getDriverName().contains("MySQL")
                || conn.getMetaData().getDriverName().contains("H2")) {
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_MYSQL;
        } else if (conn.getMetaData().getDatabaseProductName().contains("DB2")) {
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_DB2SQL;
        } else if (conn.getMetaData().getDriverName().contains("MS SQL")) {
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_MSSQL;
        } else if (conn.getMetaData().getDriverName().contains("Microsoft") || conn.getMetaData()
                .getDriverName().contains("microsoft")) {
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_MSSQL;
        } else if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_POSTGRESQL;
        } else if (conn.getMetaData().getDriverName().contains("Informix")) {
            // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_INFORMIX;
        } else {
            query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_ORACLE;
        }

        NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(conn, query);
        namedPreparedStatement
                .setString(Oauth2ScopeConstants.SQLPlaceholders.SCOPE_TYPE, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
        namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.TENANT_ID, tenantID);
        namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.OFFSET, offset);
        namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.LIMIT, limit);

        return namedPreparedStatement;
    }

    /**
     * Get SQL statement for get all scope with pagination. (including OAuth2 scopes and OIDC scopes).
     *
     * @param offset   Offset.
     * @param limit    Limit.
     * @param tenantID Tenet ID.
     * @param conn     Database connection.
     * @return
     * @throws SQLException
     */
    private NamedPreparedStatement getPreparedStatementForGetAllScopesWithPagination(Integer offset, Integer limit,
                                                                                     int tenantID, Connection conn)
            throws SQLException {

        String query;
        if (conn.getMetaData().getDriverName().contains("MySQL")
                || conn.getMetaData().getDriverName().contains("H2")) {
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_MYSQL;
        } else if (conn.getMetaData().getDatabaseProductName().contains("DB2")) {
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_DB2SQL;
        } else if (conn.getMetaData().getDriverName().contains("MS SQL")) {
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_MSSQL;
        } else if (conn.getMetaData().getDriverName().contains("Microsoft") || conn.getMetaData()
                .getDriverName().contains("microsoft")) {
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_MSSQL;
        } else if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_POSTGRESQL;
        } else if (conn.getMetaData().getDriverName().contains("Informix")) {
            // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_INFORMIX;
        } else {
            query = SQLQueries.RETRIEVE_ALL_SCOPES_WITH_PAGINATION_ORACLE;
        }

        NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(conn, query);
        namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.TENANT_ID, tenantID);
        namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.OFFSET, offset);
        namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.LIMIT, limit);

        return namedPreparedStatement;
    }

    @Override
    public Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID, Boolean includeOIDCScopes)
            throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get all scopes with pagination for tenantId  :" + tenantID + " including OIDC scope: " +
                    includeOIDCScopes);
        }

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {

            NamedPreparedStatement namedPreparedStatement;
            if (includeOIDCScopes) {
                namedPreparedStatement = getPreparedStatementForGetAllScopesWithPagination(offset, limit, tenantID,
                        conn);
            } else {
                namedPreparedStatement =
                        getPreparedStatementForGetScopesWithPagination(offset, limit, tenantID, conn);
            }

            try (PreparedStatement preparedStatement = namedPreparedStatement.getPreparedStatement();) {
                try (ResultSet rs = preparedStatement.executeQuery()) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String displayName = rs.getString(3);
                        String description = rs.getString(4);
                        final String binding = rs.getString(5);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
                            scopeMap.get(scopeID).setDisplayName(displayName);
                            if (binding != null) {
                                if (scopeMap.get(scopeID).getBindings() != null) {
                                    scopeMap.get(scopeID).addBinding(binding);
                                } else {
                                    scopeMap.get(scopeID).setBindings(new ArrayList<String>() {{
                                        add(binding);
                                    }});
                                }
                            }
                        } else {
                            scopeMap.put(scopeID, new Scope(name, displayName, description, new ArrayList<String>()));
                            if (binding != null) {
                                scopeMap.get(scopeID).addBinding(binding);

                            }
                        }
                    }
                }
            }

            for (Map.Entry<Integer, Scope> entry : scopeMap.entrySet()) {
                scopes.add(entry.getValue());
            }
            return scopes;
        } catch (SQLException e) {
            String msg = "Error occurred while getting all scopes with pagination ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get a scope by name
     *
     * @param name     name of the scope
     * @param tenantID tenant ID
     * @return Scope for the provided ID
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public Scope getScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get scope by name called for scope name:" + name);
        }

        Scope scope = null;
        String sql;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            if (conn.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_SCOPE_BY_NAME_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_SCOPE_BY_NAME;
            }
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, name);
                ps.setInt(2, tenantID);
                ps.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
                try (ResultSet rs = ps.executeQuery()) {

                    String description = null;
                    String displayName = null;

                    while (rs.next()) {
                        if (StringUtils.isBlank(description)) {
                            description = rs.getString(3);
                        }
                        if (StringUtils.isBlank(displayName)) {
                            displayName = rs.getString(2);
                        }

                        String bindingType = rs.getString(5);
                        if (bindingType == null) {
                            bindingType = DEFAULT_SCOPE_BINDING;
                        }

                        if (scope == null) {
                            scope = new Scope(name, displayName, new ArrayList<>(), description);
                        }
                        scope.addScopeBinding(bindingType, rs.getString(4));
                    }
                }
            }
            return scope;
        } catch (SQLException e) {
            String msg = "Error occurred while getting scope by ID ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get existence of OAuth2 scope for the provided scope name.
     *
     * @param scopeName name of the scope
     * @param tenantID  tenant ID
     * @return true if scope is exists
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public boolean isScopeExists(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Is scope exists called for scope:" + scopeName);
        }

        boolean isScopeExists = false;
        int scopeID = getScopeIDByName(scopeName, tenantID);
        if (scopeID != Oauth2ScopeConstants.INVALID_SCOPE_ID) {
            isScopeExists = true;
        }
        return isScopeExists;
    }

    /**
     * Get existence of scope for the provided scope name depends on the scope type.
     *
     * @param scopeName         Name of the scope.
     * @param tenantID          Tenant ID.
     * @param includeOIDCScopes Whether to include OIDC scopes in the search.
     * @return True if scope is exists.
     * @throws IdentityOAuth2ScopeServerException
     */
    @Override
    public boolean isScopeExists(String scopeName, int tenantID, Boolean includeOIDCScopes)
            throws IdentityOAuth2ScopeServerException {

        if (includeOIDCScopes) {
            if (log.isDebugEnabled()) {
                log.debug("Check scope exists regardless of scope type for scope:" + scopeName);
            }

            boolean isScopeExists = false;
            int scopeID = getScopeIDByNameWithoutScopeType(scopeName, tenantID);
            if (scopeID != Oauth2ScopeConstants.INVALID_SCOPE_ID) {
                isScopeExists = true;
            }
            return isScopeExists;
        } else {
            return isScopeExists(scopeName, tenantID);
        }
    }

    /**
     * Get scope ID for the provided scope name
     *
     * @param scopeName name of the scope
     * @param tenantID  tenant ID
     * @return scope ID for the provided scope name
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public int getScopeIDByName(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get scope ID by name called for scope name:" + scopeName);
        }

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            return getScopeId(scopeName, tenantID, conn);
        } catch (SQLException e) {
            String msg = "Error occurred while getting scope ID by name ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    private int getScopeId(String scopeName, int tenantID, Connection conn) throws SQLException {

        int scopeID = Oauth2ScopeConstants.INVALID_SCOPE_ID;
        try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME)) {
            ps.setString(1, scopeName);
            ps.setInt(2, tenantID);
            ps.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    scopeID = rs.getInt(1);
                }
            }
        }
        return scopeID;
    }

    /**
     * Get scope ID of the provided scope regardless of scope type.
     *
     * @param scopeName Scope name.
     * @param tenantID  Tenant ID.
     * @return
     * @throws IdentityOAuth2ScopeServerException
     */
    private int getScopeIDByNameWithoutScopeType(String scopeName, int tenantID)
            throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get scope ID regardless of scope type, for scope name: " + scopeName);
        }

        int scopeID = Oauth2ScopeConstants.INVALID_SCOPE_ID;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {

            try (PreparedStatement ps = conn
                    .prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME_WITHOUT_SCOPE_TYPE)) {
                ps.setString(1, scopeName);
                ps.setInt(2, tenantID);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        scopeID = rs.getInt(1);
                    }
                }
            }
            return scopeID;
        } catch (SQLException e) {
            String msg = "Error occurred while getting scope ID by name.";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Delete a scope of the provided scope ID
     *
     * @param name     name of the scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public void deleteScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Delete scope by name for scope name:" + name);
        }

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {
            try {
                deleteScope(name, tenantID, conn);
                IdentityDatabaseUtil.commitTransaction(conn);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                String msg = "Error occurred while deleting scopes ";
                throw new IdentityOAuth2ScopeServerException(msg, e1);
            }
        } catch (SQLException e) {
            String msg = "Error occurred while deleting scopes ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Update a scope of the provided scope name
     *
     * @param updatedScope details of the updated scope
     * @param tenantID     tenant ID
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public void updateScopeByName(Scope updatedScope, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Update scope by name for scope name:" + updatedScope.getName());
        }

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {
            try {
                int scopeId = getScopeId(updatedScope.getName(), tenantID, conn);
                if (scopeId != Oauth2ScopeConstants.INVALID_SCOPE_ID) {
                    updateScopeDetails(updatedScope, conn, scopeId);
                    deleteBindings(scopeId, conn);
                    addScopeBinding(updatedScope, conn, scopeId);
                    IdentityDatabaseUtil.commitTransaction(conn);
                }
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                String msg = "Error occurred while updating scope by ID ";
                throw new IdentityOAuth2ScopeServerException(msg, e1);
            }
        } catch (SQLException e) {
            String msg = "Error occurred while updating scope by ID ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Add an OIDC scope.
     *
     * @param scope    Scope.
     * @param conn     Databse connection.
     * @param tenantID Tenant ID.
     * @throws SQLException
     * @throws IdentityOAuth2ScopeClientException
     */
    private void addScope(Scope scope, Connection conn, int tenantID)
            throws SQLException {
        //Adding the scope
        if (scope != null) {
            int scopeID = 0;
            String dbProductName = conn.getMetaData().getDatabaseProductName();
            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE, new String[]{
                    DBUtils.getConvertedAutoGeneratedColumnName(dbProductName, Oauth2ScopeConstants.SCOPE_ID)})) {
                ps.setString(1, scope.getName());
                ps.setString(2, scope.getDisplayName());
                ps.setString(3, scope.getDescription());
                ps.setInt(4, tenantID);
                ps.setString(5, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
                ps.execute();

                try (ResultSet rs = ps.getGeneratedKeys()) {
                    if (rs.next()) {
                        scopeID = rs.getInt(1);
                    }
                }
            }

            // some JDBC Drivers returns this in the result, some don't
            if (scopeID == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("JDBC Driver did not return the scope id, executing Select operation");
                }
                try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME)) {
                    ps.setString(1, scope.getName());
                    ps.setInt(2, tenantID);
                    ps.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            scopeID = rs.getInt(1);
                        }
                    }
                }
            }
            addScopeBinding(scope, conn, scopeID);
        }
    }

    /**
     * Add bindings to a scope.
     *
     * @param scope   Scope.
     * @param conn    Connection.
     * @param scopeID Scope ID.
     * @throws SQLException
     * @throws IdentityOAuth2ScopeClientException
     */
    private void addScopeBinding(Scope scope, Connection conn, int scopeID)
            throws SQLException {

        // Adding scope bindings.
        try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE_BINDING)) {
            List<ScopeBinding> scopeBindings = scope.getScopeBindings();
            for (ScopeBinding scopeBinding : scopeBindings) {
                String bindingType = scopeBinding.getBindingType();
                for (String binding : scopeBinding.getBindings()) {
                    ps.setInt(1, scopeID);
                    ps.setString(2, binding);
                    ps.setString(3, bindingType);
                    ps.addBatch();
                }
            }
            ps.executeBatch();
        }
    }

    /**
     * Delete the complete scope object.
     *
     * @param scopeName Scope name.
     * @param tenantID  Tenant ID.
     * @param conn      Data-base connection object.
     * @throws SQLException
     */
    private void deleteScope(String scopeName, int tenantID, Connection conn) throws SQLException {

        // Delete the entire scope entry.
        try (PreparedStatement ps = conn.prepareStatement(SQLQueries.DELETE_SCOPE_BY_NAME)) {
            ps.setString(1, scopeName);
            ps.setInt(2, tenantID);
            ps.setString(3, Oauth2ScopeConstants.SCOPE_TYPE_OAUTH2);
            ps.execute();
        }
    }

    /**
     * Delete binding of the provided scope.
     *
     * @param conn      Data-base connection.
     * @throws SQLException
     */
    private void deleteBindings(int scopeId, Connection conn) throws SQLException {

        // Delete only the binding part of the given scope.
        if (log.isDebugEnabled()) {
            log.debug("OIDC claim mapping exists for the scope ID: " + scopeId + ", hence delete only the " +
                    "bindings of the scope");
        }
        try (PreparedStatement ps = conn.prepareStatement(SQLQueries.DELETE_BINDINGS_OF_SCOPE)) {
            ps.setInt(1, scopeId);
            ps.execute();
        }
    }

    /**
     * This method is to get resource scope key of the resource uri
     *
     * @param resourceUri Resource Path
     * @return Scope key of the resource
     * @throws IdentityOAuth2Exception if failed to find the resource scope
     */
    @Deprecated
    public String findScopeOfResource(String resourceUri) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving scope for resource: " + resourceUri);
        }
        String sql;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            if (connection.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_SCOPE_NAME_FOR_RESOURCE_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_SCOPE_NAME_FOR_RESOURCE;
            }
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, resourceUri);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("NAME");
                    }
                }
                return null;
            }
        } catch (SQLException e) {
            String errorMsg = "Error getting scopes for resource - " + resourceUri + " : " + e.getMessage();
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    @Override
    public boolean validateScope(Connection connection, String accessToken, String resourceUri) {

        return false;
    }

    /**
     * Get the list of roles associated for a given scope.
     *
     * @param scopeName name of the scope.
     * @param tenantId  Tenant Id
     * @return The Set of roles associated with the given scope.
     * @throws IdentityOAuth2Exception If an SQL error occurs while retrieving the roles.
     */
    @Override
    public Set<String> getBindingsOfScopeByScopeName(String scopeName, int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving bindings of scope: " + scopeName + " tenant id: " + tenantId);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> bindings = new HashSet<>();
        String sql;

        try {

            if (connection.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_BINDINGS_OF_SCOPE_FOR_TENANT_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_BINDINGS_OF_SCOPE_FOR_TENANT;
            }

            ps = connection.prepareStatement(sql);
            ps.setString(1, scopeName);
            ps.setInt(2, tenantId);
            rs = ps.executeQuery();

            while (rs.next()) {
                String binding = rs.getString("SCOPE_BINDING");
                if (StringUtils.isNotEmpty(binding)) {
                    bindings.add(binding);
                }
            }
            if (log.isDebugEnabled()) {
                StringBuilder bindingStringBuilder = new StringBuilder();
                for (String binding : bindings) {
                    bindingStringBuilder.append(binding).append(" ");
                }
                log.debug("Binding for scope: " + scopeName + " found: " + bindingStringBuilder.toString() + " tenant" +
                        " id: " + tenantId);
            }
            return bindings;
        } catch (SQLException e) {
            String errorMsg = "Error getting bindings of scope - " + scopeName;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
    }

    /**
     * Get the list of roles associated for a given scope.
     *
     * @param scopeName Name of the scope.
     * @return The Set of roles associated with the given scope.
     * @throws IdentityOAuth2Exception If an SQL error occurs while retrieving the roles.
     */
    @Deprecated
    public Set<String> getBindingsOfScopeByScopeName(String scopeName) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving bindings of scope: " + scopeName);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> bindings = new HashSet<>();
        String sql;

        try {
            if (connection.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_BINDINGS_OF_SCOPE_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_BINDINGS_OF_SCOPE;
            }

            ps = connection.prepareStatement(sql);
            ps.setString(1, scopeName);
            rs = ps.executeQuery();

            while (rs.next()) {
                String binding = rs.getString("SCOPE_BINDING");
                if (StringUtils.isNotBlank(binding)) {
                    bindings.add(binding);
                }
            }
            if (log.isDebugEnabled()) {
                StringBuilder bindingsStringBuilder = new StringBuilder();
                for (String binding : bindings) {
                    bindingsStringBuilder.append(binding).append(" ");
                }
                log.debug("Binding for scope: " + scopeName + " found: " + bindingsStringBuilder.toString());
            }
            return bindings;
        } catch (SQLException e) {
            String errorMsg = "Error getting roles of scope - " + scopeName;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
    }

    /**
     * Update scope details on IDN_OAUTH2_SCOPE scope table.
     *
     * @param updatedScope Updated scope.
     * @param conn         Data-base connection.
     * @param scopeId      Scope ID.
     * @throws SQLException
     */
    public void updateScopeDetails(Scope updatedScope, Connection conn, int scopeId) throws SQLException {

        // Update scope details on IDN_OAUTH2_SCOPE table.
        try (PreparedStatement ps = conn.prepareStatement(SQLQueries.UPDATE_SCOPE)) {
            ps.setString(1, updatedScope.getDisplayName());
            ps.setString(2, updatedScope.getDescription());
            ps.setInt(3, scopeId);
            ps.execute();
        }
    }
}
