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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.util.NamedPreparedStatement;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.utils.DBUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public class OAuthScopeDAOImpl implements OAuthScopeDAO {

    private final Log log = LogFactory.getLog(OAuthScopeDAOImpl.class);

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

            Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        if (log.isDebugEnabled()) {
            log.debug("Adding scope :" + scope.getName());
        }

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {

            addScope(scope, conn, tenantID);
            conn.commit();

        } catch (SQLException e) {
            String msg = "Error occurred while creating scope :" + scope.getName();
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    /**
     * Get all available scopes
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

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {

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
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Get scopes with pagination for tenantId  :" + tenantID);
        }

        Set<Scope> scopes = new HashSet<>();
        Map<Integer, Scope> scopeMap = new HashMap<>();

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {

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

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {
            if (conn.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_SCOPE_BY_NAME_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_SCOPE_BY_NAME;
            }
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, name);
                ps.setInt(2, tenantID);
                try (ResultSet rs = ps.executeQuery()) {

                    String description = null;
                    String displayName = null;
                    List<String> bindings = new ArrayList<>();

                    while (rs.next()) {
                        if (StringUtils.isBlank(description)) {
                            description = rs.getString(2);
                        }
                        if (StringUtils.isBlank(displayName)) {
                            displayName = rs.getString(3);
                        }
                        if (StringUtils.isNotBlank(rs.getString(4))) {
                            bindings.add(rs.getString(4));
                        }
                    }

                    if (StringUtils.isNotBlank(name) && StringUtils.isNotBlank(description)) {
                        scope = new Scope(name, displayName, description, bindings);
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

        int scopeID = Oauth2ScopeConstants.INVALID_SCOPE_ID;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {

            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME)) {
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
            String msg = "Error occurred while getting scope ID by name ";
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

            deleteScope(name, tenantID, conn);
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
     * @throws IdentityOAuth2ScopeServerException IdentityOAuth2ScopeServerException
     */
    @Override
    public void updateScopeByName(Scope updatedScope, int tenantID) throws IdentityOAuth2ScopeServerException {

        if (log.isDebugEnabled()) {
            log.debug("Updae scope by name for scope name:" + updatedScope.getName());
        }

        try (Connection conn = IdentityDatabaseUtil.getDBConnection()) {
            deleteScope(updatedScope.getName(), tenantID, conn);
            addScope(updatedScope, conn, tenantID);
            conn.commit();
        } catch (SQLException e) {
            String msg = "Error occurred while updating scope by ID ";
            throw new IdentityOAuth2ScopeServerException(msg, e);
        }
    }

    private void addScope(Scope scope, Connection conn, int tenantID) throws SQLException {
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
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            scopeID = rs.getInt(1);
                        }
                    }
                }
            }

            //Adding scope bindings
            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.ADD_SCOPE_BINDING)) {
                for (String binding : scope.getBindings()) {
                    if (StringUtils.isNotBlank(binding)) {
                        ps.setInt(1, scopeID);
                        ps.setString(2, binding);
                        ps.addBatch();
                    }
                }
                ps.executeBatch();
            }
        }
    }

    private void deleteScope(String name, int tenantID, Connection conn) throws SQLException {

        try (PreparedStatement ps = conn.prepareStatement(SQLQueries.DELETE_SCOPE_BY_NAME)) {
            ps.setString(1, name);
            ps.setInt(2, tenantID);
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
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            if (connection.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_SCOPE_NAME_FOR_RESOURCE_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_SCOPE_NAME_FOR_RESOURCE;
            }
            try(PreparedStatement ps = connection.prepareStatement(sql)) {
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

        Connection connection = IdentityDatabaseUtil.getDBConnection();

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
            connection.commit();
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

        Connection connection = IdentityDatabaseUtil.getDBConnection();

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
            connection.commit();
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

}
