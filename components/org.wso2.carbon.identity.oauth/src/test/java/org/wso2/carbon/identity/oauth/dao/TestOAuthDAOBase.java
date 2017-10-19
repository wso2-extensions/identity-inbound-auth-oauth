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
import org.powermock.modules.testng.PowerMockTestCase;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class TestOAuthDAOBase extends PowerMockTestCase {

    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private static final String DB_Name = "testDB";

    private static final String ADD_OAUTH = "INSERT INTO IDN_OAUTH_CONSUMER_APPS " +
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

    public static Connection getConnection(String database) throws SQLException {
        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("Invalid datasource.");
    }

    public static String getFilePath(String fileName) {
        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbscripts", fileName)
                    .toString();
        }
        return null;
    }

    protected int createBase(String clientId, String secret, String username, String appName, String appState)
            throws Exception {

        PreparedStatement statement = null;
        try (Connection connection1 = this.getConnection(DB_Name)) {
            statement = connection1.prepareStatement(ADD_OAUTH);
            statement.setString(1, clientId);
            statement.setString(2, secret);
            statement.setString(3, username);
            statement.setInt(4, -1234);
            statement.setString(5, "PRIMARY");
            statement.setString(6, appName);
            statement.setString(7, "OAuth-2.0");
            statement.setString(8, "http://localhost:8080/redirect");
            statement.setString(9, "password");
            statement.setString(10, appState);
            statement.execute();

            ResultSet resultSet = statement.getGeneratedKeys();
            if(resultSet.next()) {
                return resultSet.getInt(1);
            }
        } finally {
            if (statement != null) {
                statement.close();
            }
        }
        return -1;
    }

    protected void createReqTokenTable(int consumerId, String req_tok, String req_tok_secret,
                                       String scope, String authz_user) throws Exception {

        PreparedStatement statementReq = null;
        try (Connection connection2 = this.getConnection(DB_Name)) {
            statementReq = connection2.prepareStatement(ADD_OAUTH_REQ_TOKEN);
            statementReq.setString(1, req_tok);
            statementReq.setString(2, req_tok_secret);
            statementReq.setInt(3, consumerId);
            statementReq.setString(4, "http://localhost:8080/redirect");
            statementReq.setString(5, scope);
            statementReq.setString(6, "fakeAuthorized");
            statementReq.setString(7, "fakeOauthVerifier");
            statementReq.setString(8, authz_user);
            statementReq.setInt(9, -1234);
            statementReq.execute();
        } finally {
            if (statementReq != null) {
                statementReq.close();
            }
        }
    }

    protected void createAccTokenTable(int consumerId, String acc_tok, String acc_tok_secret,
                                       String scope, String authz_user) throws Exception {

        PreparedStatement statementAcc = null;
        try (Connection connection3 = this.getConnection(DB_Name)) {
            statementAcc = connection3.prepareStatement(ADD_OAUTH_ACC_TOKEN);
            statementAcc.setString(1, acc_tok);
            statementAcc.setString(2, acc_tok_secret);
            statementAcc.setInt(3, consumerId);
            statementAcc.setString(4, scope);
            statementAcc.setString(5, authz_user);
            statementAcc.setInt(6, -1234);
            statementAcc.execute();
        } finally {
            if (statementAcc != null) {
                statementAcc.close();
            }
        }
    }

}
