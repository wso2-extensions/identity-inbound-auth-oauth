/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oidc.session.servlet;

import org.apache.commons.dbcp.BasicDataSource;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import java.sql.Connection;
import java.sql.PreparedStatement;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

public class TestOIDCSessionBase extends PowerMockIdentityBaseTest {

    private static final String ADD_OAUTH_APP_SQL = "INSERT INTO IDN_OAUTH_CONSUMER_APPS " +
            "(CONSUMER_KEY, CONSUMER_SECRET, USERNAME, TENANT_ID, USER_DOMAIN, APP_NAME, OAUTH_VERSION," +
            " CALLBACK_URL, GRANT_TYPES, APP_STATE) VALUES (?,?,?,?,?,?,?,?,?,?) ";

    protected Connection connection;
    protected BasicDataSource dataSource;

    protected void initiateInMemoryH2() throws Exception {
        dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test");

        connection = dataSource.getConnection();
        connection.createStatement().executeUpdate("RUNSCRIPT FROM 'src/test/resources/dbScripts/h2.sql'");
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenAnswer(invocationOnMock -> dataSource.getConnection());
    }

    protected void createOAuthApp(String clientId, String secret, String username, String appName, String appState,
                                  String callBackUrl)
            throws Exception {

        PreparedStatement statement = null;
        try {
            statement = connection.prepareStatement(ADD_OAUTH_APP_SQL);
            statement.setString(1, clientId);
            statement.setString(2, secret);
            statement.setString(3, username);
            statement.setInt(4, -1234);
            statement.setString(5, "PRIMARY");
            statement.setString(6, appName);
            statement.setString(7, "OAuth-2.0");
            statement.setString(8, callBackUrl);
            statement.setString(9, "password");
            statement.setString(10, appState);
            statement.execute();
        } finally {
            if (statement != null) {
                statement.close();
            }
        }
    }

    public void cleanData() throws Exception {
        dataSource.close();
    }
}
