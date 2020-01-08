/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuth2Util.class})
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
public class CibaMgtDAOImplTest extends PowerMockTestCase {

    protected BasicDataSource dataSource;
    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    @Mock
    OAuthServerConfiguration mockedServerConfig;

    CibaMgtDAOImpl cibaMgtDAO = (CibaMgtDAOImpl) CibaDAOFactory.getInstance().getCibaAuthMgtDAO();
    CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
    private String[] scopes;

    AuthenticatedUser authenticatedUser = new AuthenticatedUser();

    private static final String AUTH_REQ_ID = "2201e5aa-1c5f-4a17-90c9-1956a3540b19";
    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    private static final String AUTH_CODE_KEY = "039e8fff-1b24-420a-9dae-0ad745c96e97";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String NOT_EXISTING_SECRET = "sasaddewgefnhf44777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String DB_NAME = "testCibaAuthCode";
    private static final String BACKCHANNELLOGOUT_URL = "http://localhost:8080/backChannelLogout";

    private static final String ADD_OAUTH_APP_SQL = "INSERT INTO IDN_OAUTH_CONSUMER_APPS " +
            "(CONSUMER_KEY, CONSUMER_SECRET, USERNAME, TENANT_ID, USER_DOMAIN, APP_NAME, OAUTH_VERSION," +
            " CALLBACK_URL, GRANT_TYPES, APP_STATE, BACKCHANNELLOGOUT_URL) VALUES (?,?,?,?,?,?,?,?,?,?,?) ";

    @BeforeClass
    public void setUp() throws Exception {

        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long lastPolledTimeInMillis = issuedTimeInMillis;
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);
        scopes = new String[]{"openid", "sms", "email"};

        cibaAuthCodeDO.setAuthReqStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setCibaAuthCodeKey(AUTH_CODE_KEY);
        cibaAuthCodeDO.setAuthReqId(AUTH_REQ_ID);
        cibaAuthCodeDO.setConsumerKey(CONSUMER_KEY);
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setInterval(2L);
        cibaAuthCodeDO.setExpiresIn(3600L);
        cibaAuthCodeDO.setScopes(scopes);

        authenticatedUser.setTenantDomain("super.wso2");
        authenticatedUser.setUserName("randomUser");
        authenticatedUser.setUserStoreDomain("PRIMARY");

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
        storeIDP();
        createBaseOAuthApp(DB_NAME, CONSUMER_KEY, SECRET, USER_NAME, APP_NAME, CALLBACK, APP_STATE,
                BACKCHANNELLOGOUT_URL);

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);
            cibaMgtDAO.persistCibaAuthCode(cibaAuthCodeDO);
        }
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }


    @Test
    public void testUpdateStatus() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);
            cibaMgtDAO.updateStatus(AUTH_CODE_KEY, AuthReqStatus.CONSENT_DENIED);
        }
        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getAuthReqStatus(),
                    AuthReqStatus.CONSENT_DENIED);
        }
    }

    @Test
    public void testPersistAuthenticationSuccessStatus() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);
            cibaMgtDAO.updateStatus(AUTH_CODE_KEY, AuthReqStatus.AUTHENTICATED);
        }

        try (Connection connection2 = getConnection(DB_NAME)) {
            prepareConnection(connection2, false);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getAuthReqStatus(),
                    AuthReqStatus.AUTHENTICATED);
        }
    }

    @Test
    public void testGetCibaAuthCodeKey() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            assertEquals(cibaMgtDAO.getCibaAuthCodeKey(AUTH_REQ_ID), AUTH_CODE_KEY);
        }
    }

    @Test
    public void testUpdateLastPollingTime() throws Exception {

        long lastPolledTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);
            cibaMgtDAO.updateLastPollingTime(AUTH_CODE_KEY, lastPolledTime);
        }

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getLastPolledTime(), lastPolledTime);
        }
    }

    @Test
    public void testUpdatePollingInterval() throws Exception {

        long updatedInterval = 5;
        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);
            cibaMgtDAO.updatePollingInterval(AUTH_CODE_KEY, updatedInterval);
        }

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getInterval(), updatedInterval);
        }
    }


    @Test
    public void testGetCibaAuthCodeWithAuthReqID() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getConsumerKey(),
                    cibaAuthCodeDO.getConsumerKey());
        }
    }

    @Test
    public void testGetScope() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            List<String> scope = cibaMgtDAO.getScopes(AUTH_CODE_KEY);
            assertEquals(scope.toArray(new String[scope.size()]), scopes);
        }
    }

    protected void storeIDP() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);

            String sql = "INSERT INTO IDP (TENANT_ID, NAME, UUID) VALUES (1234, 'LOCAL', 5678)";
            PreparedStatement statement = connection1.prepareStatement(sql);
            statement.execute();
        }
    }

    protected void createBaseOAuthApp(String databaseName, String clientId, String secret, String username,
                                      String appName, String callback, String appState, String backchannelLogout)
            throws Exception {

        try (Connection connection4 = getConnection(DB_NAME)) {
            prepareConnection(connection4, false);
            PreparedStatement statement = connection4.prepareStatement(ADD_OAUTH_APP_SQL);
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
            statement.setString(11, backchannelLogout);
            statement.execute();
        }
    }

    private void prepareConnection(Connection connection1, boolean b) {

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(b)).thenReturn(connection1);
    }

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

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
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

    public static BasicDataSource getDatasource(String datasourceName) {

        if (dataSourceMap.get(datasourceName) != null) {
            return dataSourceMap.get(datasourceName);
        }
        throw new RuntimeException("No datasource initiated for database: " + datasourceName);
    }
}
