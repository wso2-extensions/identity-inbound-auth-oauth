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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.EmptyStackException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
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
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<OAuth2ServiceComponentHolder> oauth2ServiceComponentHolder;
    private MockedStatic<OAuth2TokenUtil> oauth2TokenUtil;
    @Mock
    private RealmService mockRealmService;
    @Mock
    private OAuthComponentServiceHolder mockOAuthComponentServiceHolder;
    @Mock
    private TenantManager mockTenantManager;
    @Mock
    private OAuth2ServiceComponentHolder mockOAuth2ServiceComponentHolder;
    @Mock
    private OrganizationManager mockOrganizationManager;

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
        
        // Set up PrivilegedCarbonContext.
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        identityUtil = mockStatic(IdentityUtil.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        oauth2ServiceComponentHolder = mockStatic(OAuth2ServiceComponentHolder.class);
        oauth2TokenUtil = mockStatic(OAuth2TokenUtil.class);

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.isTokenCleanupEnabled()).thenReturn(true);
        lenient().when(mockOAuthServerConfiguration.getHashAlgorithm()).thenReturn("SHA-256");
        oAuth2Util = mockStatic(OAuth2Util.class, InvocationOnMock::callRealMethod);
        
        // Mock tenant resolution
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(1234);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
        oAuth2Util.when(() -> OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        oAuth2Util.when(() -> OAuth2Util.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(1234);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
        oAuth2Util.when(() -> OAuth2Util.getUserStoreDomain(any(AuthenticatedUser.class)))
                .thenReturn(PRIMARY_USER_STORE);
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedIDP(any(AuthenticatedUser.class))).thenReturn("LOCAL");
        
        // Mock OAuth token issuer
        OauthTokenIssuer mockTokenIssuer = mock(OauthTokenIssuer.class);
        lenient().when(mockTokenIssuer.usePersistedAccessTokenAlias()).thenReturn(false);
        lenient().when(mockTokenIssuer.getAccessTokenType()).thenReturn("default");
        oAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString())).thenReturn(mockTokenIssuer);
        
        // Mock OAuthAppDO
        OAuthAppDO mockOAuthAppDO = mock(OAuthAppDO.class);
        lenient().when(mockOAuthAppDO.getTokenType()).thenReturn("default");
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                .thenReturn(mockOAuthAppDO);
        
        identityUtil.when(() -> IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);

        TokenPersistenceProcessor mockTokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(mockTokenPersistenceProcessor);
        accessTokenDAO = new AccessTokenDAOImpl();
    }

    @AfterMethod(alwaysRun = true)
    public void closeup() throws Exception {

        if (connection != null) {
            connection.close();
        }
        
        try {
            PrivilegedCarbonContext.endTenantFlow();
        } catch (EmptyStackException e) {
            // Ignore if tenant flow was not started.
        }
        
        closeMockSafely(identityDatabaseUtil);
        closeMockSafely(oAuthServerConfiguration);
        closeMockSafely(identityUtil);
        closeMockSafely(identityTenantUtil);
        closeMockSafely(oAuth2Util);
        closeMockSafely(oauth2ServiceComponentHolder);
        closeMockSafely(oauth2TokenUtil);
    }
    
    private void closeMockSafely(MockedStatic<?> mock) {
        if (mock != null) {
            try {
                mock.close();
            } catch (Exception e) {
                // Ignore if already resolved.
            }
        }
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

    @Test
    public void testInvalidateAndCreateNewAccessToken_Success_WithoutConsent() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.CLIENT_CREDENTIALS;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setIsConsentedToken(false);

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        lenient().when(mockResultSet.next()).thenReturn(false);

        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);

        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), anyString(), eq(tokenState), eq(false)))
                .then(invocation -> null);

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                tokenStateId, accessTokenDO, userStoreDomain, grantType);

        verify(mockConnection, atLeastOnce()).prepareStatement(anyString());
        oauth2TokenUtil.verify(() -> OAuth2TokenUtil.postRefreshAccessToken(
                eq(oldAccessTokenId), anyString(), eq(tokenState), eq(false)), times(1));
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_Success_WithConsent() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.PASSWORD;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setIsConsentedToken(false);

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        when(mockResultSet.getString(1)).thenReturn("true");
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(true);
        
        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), anyString(), eq(tokenState), eq(false)))
                .then(invocation -> null);

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                tokenStateId, accessTokenDO, userStoreDomain, grantType);

        assertTrue(accessTokenDO.isConsentedToken(), "Token should be marked as consented");
        oauth2TokenUtil.verify(() -> OAuth2TokenUtil.postRefreshAccessToken(
                eq(oldAccessTokenId), anyString(), eq(tokenState), eq(false)), times(1));
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_Success_AuthorizationCodeGrant() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.AUTHORIZATION_CODE;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setTokenId("new-token-id");

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        when(mockPrepStmt.executeUpdate()).thenReturn(1);
        lenient().when(mockResultSet.next()).thenReturn(false);
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);

        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)))
                .then(invocation -> null);

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                tokenStateId, accessTokenDO, userStoreDomain, grantType);

        oauth2TokenUtil.verify(() -> OAuth2TokenUtil.postRefreshAccessToken(
                eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)), times(1));
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_Success_ImplicitGrant() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.IMPLICIT;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setTokenId("new-token-id");

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        lenient().when(mockResultSet.next()).thenReturn(false);
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);
        
        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)))
                .then(invocation -> null);

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                tokenStateId, accessTokenDO, userStoreDomain, grantType);

        oauth2TokenUtil.verify(() -> OAuth2TokenUtil.postRefreshAccessToken(
                eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)), times(1));
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_SQLException() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.CLIENT_CREDENTIALS;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("Database error"));
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);

        assertThrows(IdentityOAuth2Exception.class, () ->
                accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                        tokenStateId, accessTokenDO, userStoreDomain, grantType)
        );
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_PostRefreshTokenException() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.CLIENT_CREDENTIALS;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setTokenId("new-token-id");

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        lenient().when(mockResultSet.next()).thenReturn(false);
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);
        
        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(false)))
                .thenAnswer(invocation -> {
                    throw new IdentityOAuth2Exception("Post refresh token event failed");
                });

        assertThrows(IdentityOAuth2Exception.class, () ->
                accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                        tokenStateId, accessTokenDO, userStoreDomain, grantType)
        );
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_WithTokenCleanup() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = OAuthConstants.GrantTypes.REFRESH_TOKEN;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setTokenId("new-token-id");

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        lenient().when(mockResultSet.next()).thenReturn(false);
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);
        
        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)))
                .then(invocation -> null);

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                tokenStateId, accessTokenDO, userStoreDomain, grantType);

        oauth2TokenUtil.verify(() -> OAuth2TokenUtil.postRefreshAccessToken(
                eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)), times(1));
    }

    @Test
    public void testInvalidateAndCreateNewAccessToken_NullGrantType() throws Exception {

        String oldAccessTokenId = "old-token-id";
        String tokenState = OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
        String consumerKey = "test-consumer-key";
        String tokenStateId = "new-token-state-id";
        String userStoreDomain = "PRIMARY";
        String grantType = null;

        AccessTokenDO accessTokenDO = createMockAccessTokenDO("new-access-token", consumerKey);
        accessTokenDO.setTokenId("new-token-id");

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);
        ResultSet mockResultSet = mock(ResultSet.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(mockConnection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(mockConnection))
                .then(invocation -> null);

        lenient().when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        lenient().when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet);
        lenient().when(mockResultSet.next()).thenReturn(false);
                
        oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(false);
        
        oauth2TokenUtil.when(() -> OAuth2TokenUtil.postRefreshAccessToken(
                        eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)))
                .then(invocation -> null);

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey,
                tokenStateId, accessTokenDO, userStoreDomain, grantType);

        oauth2TokenUtil.verify(() -> OAuth2TokenUtil.postRefreshAccessToken(
                eq(oldAccessTokenId), eq("new-token-id"), eq(tokenState), eq(true)), times(1));
    }

    /**
     * Helper method to create a mock AccessTokenDO.
     */
    private AccessTokenDO createMockAccessTokenDO(String accessToken, String consumerKey) {

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken(accessToken);
        accessTokenDO.setConsumerKey(consumerKey);
        accessTokenDO.setTokenId("token-id-" + System.currentTimeMillis());
        accessTokenDO.setIsConsentedToken(false);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        accessTokenDO.setAuthzUser(authenticatedUser);

        accessTokenDO.setScope(new String[]{"openid", "profile"});

        return accessTokenDO;
    }

    @Test
    public void testGetActiveAcessTokenDataByConsumerKey() throws Exception {

        String consumerKey = "testConsumerKey";
        String token = "testToken";
        String authzUser = "testUser";
        int tenantId = 1;
        String userDomain = "PRIMARY";
        String scope = "testScope";
        String idpName = "LOCAL";
        String organizationId = "testOrg";
        Timestamp issuedTime = new Timestamp(System.currentTimeMillis());
        long validityPeriod = 3600L;

        try (MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            oAuthComponentServiceHolder.when(OAuthComponentServiceHolder::getInstance)
                     .thenReturn(mockOAuthComponentServiceHolder);
            when(mockOAuthComponentServiceHolder.getRealmService()).thenReturn(mockRealmService);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            oauth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(mockOAuth2ServiceComponentHolder);
            when(mockOAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(mockOrganizationManager);
            identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(tenantId);
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(userDomain);

            Connection mockConnection = mock(Connection.class);
            PreparedStatement mockPs = mock(PreparedStatement.class);
            ResultSet mockRs = mock(ResultSet.class);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(mockConnection);
            when(mockConnection.prepareStatement(anyString())).thenReturn(mockPs);
            when(mockPs.executeQuery()).thenReturn(mockRs);

            when(mockRs.next()).thenReturn(true, false);
            when(mockRs.getString(1)).thenReturn(authzUser);
            when(mockRs.getString(2)).thenReturn(token);
            when(mockRs.getInt(3)).thenReturn(tenantId);
            when(mockRs.getString(4)).thenReturn(userDomain);
            when(mockRs.getString(5)).thenReturn(scope);
            when(mockRs.getString(6)).thenReturn(idpName);
            when(mockRs.getString(8)).thenReturn(organizationId);
            when(mockRs.getTimestamp(anyInt(), any(Calendar.class))).thenReturn(issuedTime);
            when(mockRs.getLong(10)).thenReturn(validityPeriod);

            Set<AccessTokenDO> result = accessTokenDAO.getActiveAcessTokenDataByConsumerKey(consumerKey);

            assertFalse(result.isEmpty());
            AccessTokenDO accessTokenDO = result.iterator().next();
            assertEquals(accessTokenDO.getAccessToken(), token);
            assertEquals(accessTokenDO.getIssuedTime(), issuedTime);
            assertEquals(accessTokenDO.getValidityPeriod(), validityPeriod);
        }
    }
}
