/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class TestOAuthDAOBase extends PowerMockIdentityBaseTest {

    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    private static final String ADD_OAUTH_APP_SQL = "INSERT INTO IDN_OAUTH_CONSUMER_APPS " +
            "(CONSUMER_KEY, CONSUMER_SECRET, USERNAME, TENANT_ID, USER_DOMAIN, APP_NAME, OAUTH_VERSION," +
            " CALLBACK_URL, GRANT_TYPES, APP_STATE) VALUES (?,?,?,?,?,?,?,?,?,?) ";

    private static final String ADD_OAUTH_REQ_TOKEN = "INSERT INTO IDN_OAUTH1A_REQUEST_TOKEN " +
            "(REQUEST_TOKEN, REQUEST_TOKEN_SECRET, CONSUMER_KEY_ID, CALLBACK_URL, SCOPE, AUTHORIZED, " +
            "OAUTH_VERIFIER, AUTHZ_USER, TENANT_ID) VALUES (?,?,?,?,?,?,?,?,?) ";

    private static final String ADD_OAUTH_ACC_TOKEN = "INSERT INTO IDN_OAUTH1A_ACCESS_TOKEN " +
            "(ACCESS_TOKEN, ACCESS_TOKEN_SECRET, CONSUMER_KEY_ID, SCOPE, AUTHZ_USER, TENANT_ID) " +
            "VALUES (?,?,?,?,?,?) ";

    protected void initiateH2Base(String databaseName, String scriptPath) throws Exception {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + databaseName);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + scriptPath + "'");
        }
        dataSourceMap.put(databaseName, dataSource);
    }


    protected void closeH2Base(String databaseName) throws Exception {
        BasicDataSource dataSource =  dataSourceMap.get(databaseName);
        if(dataSource != null) {
            dataSource.close();
        }
    }

    public static Connection getConnection(String database) throws SQLException {
        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }

    public static String getFilePath(String fileName) {
        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    public static BasicDataSource getDatasource(String datasourceName){
        if (dataSourceMap.get(datasourceName) != null) {
            return dataSourceMap.get(datasourceName);
        }
        throw new RuntimeException("No datasource initiated for database: " + datasourceName);
    }

    protected int createBaseOAuthApp(String databaseName,
                                     String clientId,
                                     String secret,
                                     String username,
                                     String appName,
                                     String callback,
                                     String appState) throws Exception {

        PreparedStatement statement = null;
        try (Connection connection = getConnection(databaseName)) {
            statement = connection.prepareStatement(ADD_OAUTH_APP_SQL);
            statement.setString(1, clientId);
            statement.setString(2, secret);
            statement.setString(3, username);
            statement.setInt(4, -1234);
            statement.setString(5, "PRIMARY");
            statement.setString(6, appName);
            statement.setString(7, "OAuth-2.0");
            statement.setString(8, callback);
            statement.setString(9, "password");
            statement.setString(10, appState);
            statement.execute();

            ResultSet resultSet = statement.getGeneratedKeys();
            if (resultSet.next()) {
                return resultSet.getInt(1);
            }
        } finally {
            if (statement != null) {
                statement.close();
            }
        }
        return -1;
    }

    protected void createReqTokenTable(String databaseName,
                                       int consumerId,
                                       String requestToken,
                                       String requestTokenSecret,
                                       String scope,
                                       String callback,
                                       String oauthVerifier,
                                       String authzUser) throws Exception {

        PreparedStatement statementReq = null;
        try (Connection connection = getConnection(databaseName)) {
            statementReq = connection.prepareStatement(ADD_OAUTH_REQ_TOKEN);
            statementReq.setString(1, requestToken);
            statementReq.setString(2, requestTokenSecret);
            statementReq.setInt(3, consumerId);
            statementReq.setString(4, callback);
            statementReq.setString(5, scope);
            statementReq.setString(6, "fakeAuthorized");
            statementReq.setString(7, oauthVerifier);
            statementReq.setString(8, authzUser);
            statementReq.setInt(9, -1234);
            statementReq.execute();
        } finally {
            if (statementReq != null) {
                statementReq.close();
            }
        }
    }

    protected void createAccessTokenTable(String databaseName,
                                          int consumerId,
                                          String accessToken,
                                          String accessTokenSecret,
                                          String scope,
                                          String authzUser) throws Exception {

        PreparedStatement statementAcc = null;
        try (Connection connection = getConnection(databaseName)) {
            statementAcc = connection.prepareStatement(ADD_OAUTH_ACC_TOKEN);
            statementAcc.setString(1, accessToken);
            statementAcc.setString(2, accessTokenSecret);
            statementAcc.setInt(3, consumerId);
            statementAcc.setString(4, scope);
            statementAcc.setString(5, authzUser);
            statementAcc.setInt(6, -1234);
            statementAcc.execute();
        } finally {
            if (statementAcc != null) {
                statementAcc.close();
            }
        }
    }
}
