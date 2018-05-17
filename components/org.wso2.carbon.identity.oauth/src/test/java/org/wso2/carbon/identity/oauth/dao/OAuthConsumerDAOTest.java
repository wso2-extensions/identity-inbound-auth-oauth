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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.Parameters;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

/*
 * Unit tests for OAuthConsumerDAO
 */
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuthConsumerDAO.class})
public class OAuthConsumerDAOTest extends TestOAuthDAOBase {

    private static final String CLIENT_ID = "ca19a540f544777860e44e75f605d927";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String NOT_EXISTING_SECRET = "sasaddewgefnhf44777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String ACC_TOKEN = "fakeAccToken";
    private static final String ACC_TOKEN_SECRET = "fakeTokenSecret";
    private static final String REQ_TOKEN = "fakeReqToken";
    private static final String REQ_TOKEN_SECRET = "fakeReqToken";
    private static final String SCOPE = "openid";
    private static final String AUTHZ_USER = "fakeAuthzUser";
    private static final String OAUTH_VERIFIER = "fakeOauthVerifier";
    private static final String NEW_SECRET = "a459a540f544777860e44e75f605d875";
    private static final String DB_NAME = "testOAuthConsumerDAO";
    private static final String BACKCHANNELLOGOUT_URL = "http://localhost:8080/backChannelLogout";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private Parameters mockedParameters;

    @Mock
    private PlainTextPersistenceProcessor persistenceProcessor;

    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));

        int consumer_ID = createBaseOAuthApp(DB_NAME, CLIENT_ID, SECRET, USER_NAME, APP_NAME, CALLBACK, APP_STATE, BACKCHANNELLOGOUT_URL);
        createAccessTokenTable(DB_NAME, consumer_ID, ACC_TOKEN, ACC_TOKEN_SECRET, SCOPE, AUTHZ_USER);
        createReqTokenTable(DB_NAME, consumer_ID, REQ_TOKEN, REQ_TOKEN_SECRET, SCOPE, CALLBACK, OAUTH_VERIFIER,
                AUTHZ_USER);
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @Test
    public void testGetOAuthConsumerSecret() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getOAuthConsumerSecret(CLIENT_ID), SECRET);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthConsumerSecretWithExceptions() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            Connection connection2 = spy(connection1);
            doThrow(new SQLException()).when(connection2).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.getOAuthConsumerSecret(CLIENT_ID);
        }
    }

    @Test
    public void testUpdateSecretKey() throws Exception {

        String GET_SECRET_SQL = "SELECT CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {

            PreparedStatement statement = connection.prepareStatement(GET_SECRET_SQL);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.updateSecretKey(CLIENT_ID, NEW_SECRET);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    assertEquals(resultSet.getString(1), NEW_SECRET, "Checking whether the passed value is set to the " +
                            " CONSUMER_SECRET.");
                }
            }
        }
    }

    @Test
    public void testGetAuthenticatedUsername() throws Exception {

        mockStatic(IdentityDatabaseUtil.class);

        try (Connection connection2 = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            mockStatic(OAuthServerConfiguration.class);
            when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
            PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
            when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getAuthenticatedUsername(CLIENT_ID, SECRET), USER_NAME);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetAuthenticatedUsernameWithExceptions() throws Exception {

        mockStatic(IdentityDatabaseUtil.class);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            mockStatic(OAuthServerConfiguration.class);
            when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
            PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
            when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.getAuthenticatedUsername(CLIENT_ID, SECRET);
        }
    }

    @DataProvider(name = "provideTokens")
    public Object[][] provideTokens() throws Exception {
        return new Object[][]{
                {ACC_TOKEN, true, ACC_TOKEN_SECRET},
                {REQ_TOKEN, false, REQ_TOKEN_SECRET}
        };
    }

    @Test(dataProvider = "provideTokens")
    public void testGetOAuthTokenSecret(String token, Boolean isAccessToken, String expected) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection3 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getOAuthTokenSecret(token, isAccessToken), expected);
        }
    }

    @Test(dataProvider = "provideTokens", expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthTokenSecretWithExceptions(String token, Boolean isAccessToken, String expected) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getOAuthTokenSecret(token, isAccessToken), expected);
        }
    }

    @Test
    public void testGetRequestToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(Parameters.class).withNoArguments().thenReturn(mockedParameters);

        try (Connection connection3 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getRequestToken(REQ_TOKEN), mockedParameters);
        }
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testGetRequestTokenWithExceptions() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(Parameters.class).withNoArguments().thenReturn(mockedParameters);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getRequestToken(REQ_TOKEN), mockedParameters);
        }
    }

    @Test
    public void testCreateOAuthRequestToken_01() throws Exception {

        String GET_ID_SQL = "SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
        String REQ_ID_SQL = "SELECT REQUEST_TOKEN FROM IDN_OAUTH1A_REQUEST_TOKEN WHERE CONSUMER_KEY_ID=?";
        Integer ID = null;
        String req_Token = null;
        PreparedStatement statement1 = null;
        PreparedStatement statement2 = null;

        ResultSet resultSet1 = null;
        ResultSet resultSet2 = null;

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection3 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.createOAuthRequestToken(CLIENT_ID, ACC_TOKEN, SECRET, CALLBACK, SCOPE);

            try {
                statement1 = connection3.prepareStatement(GET_ID_SQL);
                statement1.setString(1, CLIENT_ID);
                resultSet1 = statement1.executeQuery();
                if (resultSet1.next()) {
                    ID = resultSet1.getInt(1);
                }
                statement2 = connection3.prepareStatement(REQ_ID_SQL);
                statement2.setInt(1, ID);
                resultSet2 = statement2.executeQuery();
                if (resultSet2.next()) {
                    req_Token = resultSet2.getString(1);
                }
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection3, resultSet1, statement1);
            }
            assertEquals(REQ_TOKEN, req_Token, "Checking whether the passed req_Token is set to the " +
                    "REQ_TOKEN.");
        }
    }

    @Test
    public void testCreateOAuthRequestToken_02() throws Exception {

        String callback_URL = null;
        String c_Id = "fakeClientId";
        String ac_Token = "fakeAccToken";
        String secretFake = "fakeSecret";
        String fakeScope = "fakeScope";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection3 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.createOAuthRequestToken(c_Id, ac_Token, secretFake, callback_URL, fakeScope);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testCreateOAuthRequestTokenWithExceptions() throws Exception {

        String callback_URL = null;
        String c_Id = "fakeClientId";
        String ac_Token = "fakeAccToken";
        String secretFake = "fakeSecret";
        String fakeScope = "fakeScope";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.createOAuthRequestToken(c_Id, ac_Token, secretFake, callback_URL, fakeScope);
        }
    }

    @Test
    public void testAuthorizeOAuthToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(Parameters.class).withNoArguments().thenReturn(mockedParameters);

        try (Connection connection3 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.authorizeOAuthToken(REQ_TOKEN, USER_NAME, OAUTH_VERIFIER), mockedParameters);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAuthorizeOAuthTokenWithExceptions() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(Parameters.class).withNoArguments().thenReturn(mockedParameters);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.authorizeOAuthToken(REQ_TOKEN, USER_NAME, OAUTH_VERIFIER), mockedParameters);
        }
    }

    @Test
    public void testValidateAccessToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.validateAccessToken(CLIENT_ID, ACC_TOKEN, SCOPE), AUTHZ_USER);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testValidateAccessTokenWithExceptions() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.validateAccessToken(CLIENT_ID, ACC_TOKEN, SCOPE), AUTHZ_USER);
        }
    }

    @Test
    public void testIsConsumerSecretExist() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.isConsumerSecretExist(CLIENT_ID, SECRET), true);
        }
    }

    @Test
    public void testIsConsumerSecretExistWithNotExistingConsumersecret() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.isConsumerSecretExist(CLIENT_ID, NOT_EXISTING_SECRET), false);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testIsConsumerSecretExistWithExceptions() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(persistenceProcessor);
        doThrow(new IdentityOAuth2Exception("Test")).when(persistenceProcessor).getProcessedClientId(CLIENT_ID);

        try (Connection connection1 = getConnection(DB_NAME)) {
            Connection connection2 = spy(connection1);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.isConsumerSecretExist(CLIENT_ID, SECRET);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testIsConsumerSecretExistWithException() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(persistenceProcessor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            Connection connection2 = spy(connection1);
            doThrow(new SQLException()).when(connection2).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.isConsumerSecretExist(CLIENT_ID, SECRET);
        }
    }

}
