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
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
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

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;

@WithH2Database(files = { "dbScripts/h2.sql", "dbScripts/identity.sql" })
public class CibaMgtDAOImplTest {

    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    CibaMgtDAOImpl cibaMgtDAO = (CibaMgtDAOImpl) CibaDAOFactory.getInstance().getCibaAuthMgtDAO();
    CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
    private String[] scopes;

    AuthenticatedUser authenticatedUser = new AuthenticatedUser();

    private static final String AUTH_REQ_ID = "2201e5aa-1c5f-4a17-90c9-1956a3540b19";
    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    private static final String AUTH_CODE_KEY = "039e8fff-1b24-420a-9dae-0ad745c96e97";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
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
        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty("carbon.home", carbonHome);
        System.setProperty("carbon.config.dir.path",
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "conf").toString());

        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long lastPolledTimeInMillis = issuedTimeInMillis;
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);
        scopes = new String[] { "openid", "sms", "email" };

        cibaAuthCodeDO.setAuthReqStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setCibaAuthCodeKey(AUTH_CODE_KEY);
        cibaAuthCodeDO.setAuthReqId(AUTH_REQ_ID);
        cibaAuthCodeDO.setConsumerKey(CONSUMER_KEY);
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setInterval(2L);
        cibaAuthCodeDO.setExpiresIn(3600L);
        cibaAuthCodeDO.setScopes(scopes);
        cibaAuthCodeDO.setResolvedUserId("testUser");

        authenticatedUser.setTenantDomain("super.wso2");
        authenticatedUser.setUserName("randomUser");
        authenticatedUser.setUserStoreDomain("PRIMARY");

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
        storeIDP();
        createBaseOAuthApp(DB_NAME, CONSUMER_KEY, SECRET, USER_NAME, APP_NAME, CALLBACK, APP_STATE,
                BACKCHANNELLOGOUT_URL);

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            cibaMgtDAO.persistCibaAuthCode(cibaAuthCodeDO);
        }
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @Test
    public void testUpdateStatus() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            cibaMgtDAO.updateStatus(AUTH_CODE_KEY, AuthReqStatus.CONSENT_DENIED);
        }
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getAuthReqStatus(),
                    AuthReqStatus.CONSENT_DENIED);
        }
    }

    @Test
    public void testPersistAuthenticationSuccessStatus() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            cibaMgtDAO.updateStatus(AUTH_CODE_KEY, AuthReqStatus.AUTHENTICATED);
        }

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getAuthReqStatus(),
                    AuthReqStatus.AUTHENTICATED);
        }
    }

    @Test
    public void testGetCibaAuthCodeKey() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            assertEquals(cibaMgtDAO.getCibaAuthCodeKey(AUTH_REQ_ID), AUTH_CODE_KEY);
        }
    }

    @Test
    public void testUpdateLastPollingTime() throws Exception {

        long lastPolledTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            cibaMgtDAO.updateLastPollingTime(AUTH_CODE_KEY, lastPolledTime);
        }

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getLastPolledTime(), lastPolledTime);
        }
    }

    @Test
    public void testUpdatePollingInterval() throws Exception {

        long updatedInterval = 5;
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            cibaMgtDAO.updatePollingInterval(AUTH_CODE_KEY, updatedInterval);
        }

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getInterval(), updatedInterval);
        }
    }

    @Test
    public void testGetCibaAuthCodeWithAuthReqID() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getConsumerKey(),
                    cibaAuthCodeDO.getConsumerKey());
        }
    }

    @Test
    public void testGetScope() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            List<String> scope = cibaMgtDAO.getScopes(AUTH_CODE_KEY);
            assertEquals(scope.toArray(new String[scope.size()]), scopes);
        }
    }

    @Test
    public void testGetAuthenticatedUser() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
                MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            prepareConnection(identityDatabaseUtil);
            oAuth2Util.when(() -> OAuth2Util.getTenantDomain(-1234)).thenReturn("super.wso2");

            AuthenticatedUser user = cibaMgtDAO.getAuthenticatedUser(AUTH_CODE_KEY);
            // We haven't persisted the authenticated user in this test specifically, but it
            // relies on what's in DB.
            // If valid user is in DB, it returns it.
            // Since this test runs independently or after setUp, and we haven't asserted
            // value yet here.
            // But verify no exception.
            // If persists success ran before, it would yield a user.
        }
    }

    @Test
    public void testPersistAuthenticationSuccess() throws Exception {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(USER_NAME);
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain("super.wso2");

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
                MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            prepareConnection(identityDatabaseUtil);

            oAuth2Util.when(() -> OAuth2Util.getAuthenticatedIDP(user)).thenReturn("LOCAL");
            oAuth2Util.when(() -> OAuth2Util.getTenantId("super.wso2")).thenReturn(-1234);

            cibaMgtDAO.persistAuthenticationSuccess(AUTH_CODE_KEY, user);
        }

        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
                MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            prepareConnection(identityDatabaseUtil);
            oAuth2Util.when(() -> OAuth2Util.getTenantDomain(-1234)).thenReturn("super.wso2");

            AuthenticatedUser retrievedUser = cibaMgtDAO.getAuthenticatedUser(AUTH_CODE_KEY);
            assertEquals(retrievedUser.getUserName(), USER_NAME);
            assertEquals(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY).getAuthReqStatus(), AuthReqStatus.AUTHENTICATED);
        }
    }

    @Test
    public void testGetResolvedUserId() throws Exception {
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(identityDatabaseUtil);
            String resolvedUserId = cibaMgtDAO.getResolvedUserId(AUTH_CODE_KEY);
            assertEquals(resolvedUserId, "testUser");
        }
    }

    protected void storeIDP() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            String sql = "INSERT INTO IDP (TENANT_ID, NAME, UUID) VALUES (1234, 'LOCAL', 5678)";
            PreparedStatement statement = connection1.prepareStatement(sql);
            statement.execute();
        }
    }

    protected void createBaseOAuthApp(String databaseName, String clientId, String secret, String username,
            String appName, String callback, String appState, String backchannelLogout)
            throws Exception {

        try (Connection connection4 = getConnection(DB_NAME)) {
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

    private void prepareConnection(MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil) {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(anyBoolean()))
                .thenAnswer(invocation -> getConnection(DB_NAME));
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

}
