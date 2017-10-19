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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.Parameters;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;

import java.sql.Connection;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

/*
 * Unit tests for OAuthConsumerDAO
 */
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuthConsumerDAO.class})
public class OAuthConsumerDAOTest extends TestOAuthDAOBase {

    private String clientId;
    private String secret;
    private String appName;
    private String username;
    private String appState;

    private String acc_Token;
    private String acc_Token_Secret;
    private String req_Token;
    private String req_Token_Secret;
    private String scope;
    private String authz_user;

    private String newSecret;

    private static final String DB_Name = "testDB";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private Parameters mockedParameters;

    @BeforeClass
    public void setUp() throws Exception {

        clientId = "ca19a540f544777860e44e75f605d927";
        secret = "87n9a540f544777860e44e75f605d435";
        appName = "myApp";
        username = "user1";
        appState = "ACTIVE";

        acc_Token = "fakeAccToken";
        acc_Token_Secret = "fakeTokenSecret";
        req_Token = "fakeReqToken";
        req_Token_Secret = "fakeReqToken";
        scope = "openid";
        authz_user = "fakeAuthzUser";

        newSecret = "a459a540f544777860e44e75f605d875";

        initiateH2Base(DB_Name, getFilePath("h2.sql"));

        int consumer_ID = createBase(clientId, secret, username, appName, appState);
        createAccTokenTable(consumer_ID, acc_Token, acc_Token_Secret, scope, authz_user);
        createReqTokenTable(consumer_ID, req_Token, req_Token_Secret, scope, authz_user);
    }

    @Test
    public void testGetOAuthConsumerSecret() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection1 = getConnection(DB_Name)) {

            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getOAuthConsumerSecret(clientId), secret);
        }
    }

    @Test
    public void testGetAuthenticatedUsername() throws Exception {

        mockStatic(IdentityDatabaseUtil.class);

        try(Connection connection2 = getConnection(DB_Name)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            mockStatic(OAuthServerConfiguration.class);
            when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);

            PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
            when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getAuthenticatedUsername(clientId, secret), username);
        }
    }

    @DataProvider(name = "provideTokens")
    public Object[][] provideTokens() throws Exception {
        return new Object[][]{
                {acc_Token, true, acc_Token_Secret},
                {req_Token, false, req_Token_Secret}
        };
    }

    @Test(dataProvider = "provideTokens")
    public void testGetOAuthTokenSecret(String token, Boolean isAccessToken, String expected) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection3 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

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

        try(Connection connection3 = getConnection(DB_Name)) {

            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getRequestToken(req_Token), mockedParameters);
        }
    }

}
