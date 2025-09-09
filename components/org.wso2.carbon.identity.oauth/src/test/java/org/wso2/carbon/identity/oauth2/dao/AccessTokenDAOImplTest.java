/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.org).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class AccessTokenDAOImplTest {

    private static final String EXPIRED_TOKEN_ID = "expired_token_id";
    private static final String TEST_TENANT_DOMAIN = "TestTenantDomain";
    private static final String TEST_USER1 = "user1";
    private static final String PRIMARY_USER_STORE = "PRIMARY";

    private AccessTokenDAOImpl accessTokenDAO;
    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    public static final String H2_SCRIPT_NAME = "identity.sql";
    public static final String H2_SCRIPT2_NAME = "insert_token_binding.sql";
    public static final String DB_NAME = "AccessTokenDB";
    Connection connection = null;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeClass
    public void initTest() throws Exception {

        try {
            DAOUtils.initializeBatchDataSource(DB_NAME, H2_SCRIPT_NAME, H2_SCRIPT2_NAME);
        } catch (Exception e) {
            throw new IdentityOAuth2Exception("Error while initializing the data source", e);
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        identityUtil = mockStatic(IdentityUtil.class);

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.isTokenCleanupEnabled()).thenReturn(true);
        oAuth2Util = mockStatic(OAuth2Util.class, InvocationOnMock::callRealMethod);

        TokenPersistenceProcessor mockTokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(mockTokenPersistenceProcessor);
        accessTokenDAO = new AccessTokenDAOImpl();
    }

    @AfterMethod
    public void closeup() throws Exception {

        if (connection != null) {
            connection.close();
        }
        identityDatabaseUtil.close();
        oAuthServerConfiguration.close();
        identityUtil.close();
        oAuth2Util.close();
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base(DB_NAME);
    }

    @Test
    public void getSessionIdentifierByTokenId() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);
        assertEquals(accessTokenDAO.getSessionIdentifierByTokenId("2sa9a678f890877856y66e75f605d456"),
                    "4503eb1561bfd6bf237b7e05c15afaff21f511d81135423015a747ee7e3f0bc0");
    }

    private static void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    @Test
    public void testGetAccessTokensByUserForOpenidScope_includeExpiredAccessTokensWithActiveRefreshToken()
            throws Exception {

        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);

        oAuth2Util.when(() -> OAuth2Util.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(1234);
        oAuth2Util.when(() -> OAuth2Util.getTokenPartitionedSqlByUserStore(
                        SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER, PRIMARY_USER_STORE))
                .thenReturn(SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER1);
        authenticatedUser.setUserStoreDomain(PRIMARY_USER_STORE);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);

        assertTrue(accessTokenDAO
                .getAccessTokensByUserForOpenidScope(authenticatedUser, true)
                .stream()
                .anyMatch(token -> EXPIRED_TOKEN_ID.equals(token.getTokenId())),
                "Expired access token with active refresh token was not returned.");

        assertFalse(accessTokenDAO
                        .getAccessTokensByUserForOpenidScope(authenticatedUser, false)
                        .stream()
                        .anyMatch(token -> EXPIRED_TOKEN_ID.equals(token.getTokenId())),
                "Expired access token with active refresh token was returned.");
    }

    @Test
    public void testRevokeAccessTokensIndividually() throws Exception {

        String[] tokens = {};
        boolean isHashedToken = false;

        Connection mockConnection = mock(Connection.class);
        DatabaseMetaData mockDatabaseMetaData = mock(DatabaseMetaData.class);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        when(mockDatabaseMetaData.getDriverName()).thenReturn("Microsoft SQL Server");
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(mockConnection);
        accessTokenDAO.revokeAccessTokensIndividually(tokens, isHashedToken);
    }

    @Test
    public void testRevokeAccessTokensInBatch() throws Exception {

        String[] tokens = {"token1", "token2"};
        boolean isHashedToken = true;

        Connection mockConnection = mock(Connection.class);
        PreparedStatement preparedStatement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
        when(mockConnection.prepareStatement(anyString())).thenReturn(preparedStatement);

        DatabaseMetaData mockDatabaseMetaData = mock(DatabaseMetaData.class);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        when(mockDatabaseMetaData.getDriverName()).thenReturn("Microsoft SQL Server");
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(mockConnection);

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.getHashAlgorithm()).thenReturn("SHA-256");

        accessTokenDAO.revokeAccessTokensInBatch(tokens, isHashedToken);
    }
}
