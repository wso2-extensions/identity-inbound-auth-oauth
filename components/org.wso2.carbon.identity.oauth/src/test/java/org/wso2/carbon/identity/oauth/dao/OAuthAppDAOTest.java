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
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/*
 * Unit tests for OAuthAppDAO
 */
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuthConsumerDAO.class,
        OAuthUtil.class, OAuth2ServiceComponentHolder.class, IdentityTenantUtil.class, IdentityUtil.class})
public class OAuthAppDAOTest extends TestOAuthDAOBase {

    private static final String CLIENT_ID = "ca19a540f544777860e44e75f605d927";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String DB_NAME = "testDB";

    @Mock
    private OAuthAppDO mockedAppDo;

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private AuthenticatedUser mockedUser;

    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
        createBase(CLIENT_ID, SECRET, USER_NAME, APP_NAME, CALLBACK, APP_STATE);
    }

    @Test
    public void testAddOAuthApplication() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        when(mockedAppDo.getUser()).thenReturn(mockedUser);
        when(mockedUser.getUserName()).thenReturn(USER_NAME);
        when(mockedUser.getUserStoreDomain()).thenReturn("fakeUserStoreDomain");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("PRIMARY")).thenReturn(-12345);

        try(Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            mockStatic(IdentityUtil.class);
            when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME, -12345)).thenReturn(true);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.addOAuthApplication(mockedAppDo);

            mockStatic(OAuth2ServiceComponentHolder.class);
            when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(false);
        }
    }

    @Test
    public void testAddOAuthConsumer() throws Exception {

        String newKey = "fakeKey";
        String user = "fakeUser";
        String secret = "fakeSecret";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            mockStatic(OAuthUtil.class);
            when(OAuthUtil.getRandomNumber()).thenReturn(secret).thenReturn(newKey);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.addOAuthConsumer(user, -1234, "PRIMARY"),
                    new String[] {newKey, secret});
        }
    }

    @Test
    public void testRemoveConsumerApplication() throws Exception {

        String GET_SECRET = "SELECT CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection = getConnection(DB_NAME)) {
            PreparedStatement statement = connection.prepareStatement(GET_SECRET);

            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.removeConsumerApplication(CLIENT_ID);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if(resultSet.next()) {
                    assertNull(resultSet.getString(1), "Checking whether the CONSUMER_SECRET is successfully deleted.");
                }
            }
        }
    }

    @Test
    public void testUpdateOAuthConsumerApp() throws Exception {

        String GET_APP = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection1 = getConnection(DB_NAME);
            PreparedStatement statement = connection1.prepareStatement(GET_APP)) {

            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateOAuthConsumerApp(APP_NAME, CLIENT_ID);
            statement.setString(1, CLIENT_ID);

            try(ResultSet resultSet = statement.executeQuery()) {
                if(resultSet.next()) {
                    assertEquals(resultSet.getString(1), APP_NAME, "Checking whether the table " +
                            "is updated with the passed appName.");
                }
            }
        }
    }

    @Test
    public void testGetConsumerAppState() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.getConsumerAppState(CLIENT_ID), APP_STATE, "Checking the APP_STATE for the " +
                    "given CONSUMER_KEY.");
        }
    }

}
