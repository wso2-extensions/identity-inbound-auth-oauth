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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.util.NamedPreparedStatement;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

/**
 * Data Access Layer functionality for Scope management. This includes storing, updating, deleting and retrieving scopes
 */
public class ScopeMgtDAO {
    private static final Log log = LogFactory.getLog(ScopeMgtDAO.class);

    /**
     * Add a scope
     *
     * @param scope    Scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2ScopeServerException
     */
    public void addScope(Scope scope, int tenantID) throws IdentityOAuth2ScopeServerException {

        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            if (scope != null) {
                int scopeID = 0;
                try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE, new String[]{scopeIdField});) {
                    ps.setString(1, scope.getName());
                    ps.setString(2, scope.getDescription());
                    ps.setInt(3, tenantID);
                    ps.execute();

                    try (ResultSet rs = ps.getGeneratedKeys();) {
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
                    try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME,
                            new String[]{scopeIdField});) {
                        ps.setString(1, scope.getName());
                        ps.setInt(2, tenantID);
                        try (ResultSet rs = ps.executeQuery();) {
                            if (rs.next()) {
                                scopeID = rs.getInt(1);
                            }
                        }
                    }
                }

                for (String binding : scope.getBindings()) {
                    try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE_BINDING,
                            new String[]{scopeIdField});) {
                        if (StringUtils.isNotBlank(binding)) {
                            ps.setInt(1, scopeID);
                            ps.setString(2, binding);
                            ps.addBatch();
                        }
                        ps.executeBatch();
                    }
                }
                conn.commit();
            }
        } catch (SQLException e) {
            String msg = "Error occurred while creating scopes ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get all available scopes
     *
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getAllScopes(int tenantID) throws IdentityOAuth2ScopeServerException {

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();

        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_ALL_SCOPES,
                    new String[]{scopeIdField});) {
                ps.setInt(1, tenantID);
                try (ResultSet rs = ps.executeQuery();) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String description = rs.getString(3);
                        final String binding = rs.getString(4);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
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
                            scopeMap.put(scopeID, new Scope(name, description, new ArrayList<String>()));
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
            String msg = "Error occurred while getting all scopes ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get Scopes with pagination
     *
     * @param offset   start index of the result set
     * @param limit    number of elements of the result set
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID) throws IdentityOAuth2ScopeServerException {

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();

        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

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
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.TENANT_ID, tenantID);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.OFFSET, offset);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.LIMIT, limit);
            try (PreparedStatement preparedStatement = namedPreparedStatement.getPreparedStatement();) {
                try (ResultSet rs = preparedStatement.executeQuery();) {
                    while (rs.next()) {
                        int scopeID = rs.getInt(1);
                        String name = rs.getString(2);
                        String description = rs.getString(3);
                        final String binding = rs.getString(4);
                        if (scopeMap.containsKey(scopeID) && scopeMap.get(scopeID) != null) {
                            scopeMap.get(scopeID).setName(name);
                            scopeMap.get(scopeID).setDescription(description);
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
                            scopeMap.put(scopeID, new Scope(name, description, new ArrayList<String>()));
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
     * @throws IdentityOAuth2ScopeServerException
     */
    public Scope getScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException {

        Scope scope = null;

        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_BY_NAME,
                    new String[]{scopeIdField});) {
                ps.setString(1, name);
                ps.setInt(2, tenantID);
                try (ResultSet rs = ps.executeQuery();) {

                    String description = null;
                    List<String> bindings = new ArrayList<>();

                    while (rs.next()) {
                        if (StringUtils.isBlank(description)) {
                            description = rs.getString(2);
                        }
                        bindings.add(rs.getString(3));
                    }

                    if (StringUtils.isNotBlank(name) && StringUtils.isNotBlank(description)) {
                        scope = new Scope(name, description, bindings);
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
     * Get existence of scope for the provided scope name
     *
     * @param scopeName name of the scope
     * @param tenantID tenant ID
     * @return true if scope is exists
     * @throws IdentityOAuth2ScopeServerException
     */
    public boolean isScopeExists(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException {
        boolean isScopeExists = false;
        int scopeID = getScopeIDByName(scopeName, tenantID);
        if (scopeID != -1) {
            isScopeExists = true;
        }
        return isScopeExists;
    }

    /**
     * Get scope ID for the provided scope name
     *
     * @param scopeName name of the scope
     * @param tenantID  tenant ID
     * @return scope ID for the provided scope name
     * @throws IdentityOAuth2ScopeServerException
     */
    public int getScopeIDByName(String scopeName, int tenantID) throws IdentityOAuth2ScopeServerException {

        int scopeID = -1;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME,
                    new String[]{scopeIdField});) {
                ps.setString(1, scopeName);
                ps.setInt(2, tenantID);
                try (ResultSet rs = ps.executeQuery();) {
                    if (rs.next()) {
                        scopeID = rs.getInt(1);
                    }
                }
            }
            return scopeID;
        } catch (SQLException e) {
            String msg = "Error occurred while getting scope ID by name ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Delete a scope of the provided scope ID
     *
     * @param name     name of the scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2ScopeServerException
     */
    public void deleteScopeByName(String name, int tenantID) throws IdentityOAuth2ScopeServerException {

        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.DELETE_SCOPE_BY_NAME,
                    new String[]{scopeIdField});) {
                ps.setString(1, name);
                ps.setInt(2, tenantID);
                ps.execute();
            }
            conn.commit();
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
     * @throws IdentityOAuth2ScopeServerException
     */
    public void updateScopeByName(Scope updatedScope, int tenantID) throws IdentityOAuth2ScopeServerException {
        try (Connection conn = IdentityDatabaseUtil.getDBConnection();) {

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.DELETE_SCOPE_BY_NAME,
                    new String[]{scopeIdField});) {
                ps.setString(1, updatedScope.getName());
                ps.setInt(2, tenantID);
                ps.execute();
            }

            int scopeID = 0;
            if (updatedScope != null) {
                try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE, new String[]{scopeIdField});) {
                    ps.setString(1, updatedScope.getName());
                    ps.setString(2, updatedScope.getDescription());
                    ps.setInt(3, tenantID);
                    ps.execute();

                    try (ResultSet rs = ps.getGeneratedKeys();) {
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
                    try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME,
                            new String[]{scopeIdField});) {
                        ps.setString(1, updatedScope.getName());
                        ps.setInt(2, tenantID);
                        try (ResultSet rs = ps.executeQuery();) {
                            if (rs.next()) {
                                scopeID = rs.getInt(1);
                            }
                        }
                    }
                }

                for (String binding : updatedScope.getBindings()) {
                    try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE_BINDING,
                            new String[]{scopeIdField});) {
                        if (StringUtils.isNotBlank(binding)) {
                            ps.setInt(1, scopeID);
                            ps.setString(2, binding);
                            ps.addBatch();
                        }
                        ps.executeBatch();
                    }
                }
            }
            conn.commit();
        } catch (SQLException e) {
            String msg = "Error occurred while updating scope by ID ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }
}
