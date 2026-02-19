/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.EmptyStackException;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for RefreshTokenDAOImpl.
 * Uses H2 in-memory database with refreshToken.sql script for table creation.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class RefreshTokenDAOImplTest {

    private static final String DB_NAME = "RefreshTokenDB";
    private static final String H2_SCRIPT_NAME = "refreshToken.sql";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final int TEST_TENANT_ID = -1234;
    private static final String TEST_USER = "testUser";
    private static final String PRIMARY_USER_STORE = "PRIMARY";
    private static final String TEST_CONSUMER_KEY = "testConsumerKey";
    private static final String TEST_CONSUMER_SECRET = "testConsumerSecret";
    private static final String TEST_GRANT_TYPE = "authorization_code";
    private static final String[] SCOPES_WITH_OPENID = {"openid", "profile", "email"};
    private static final String[] SCOPES_WITHOUT_OPENID = {"profile", "email"};
    private static final String TEST_SUBJECT_IDENTIFIER = "testSubjectIdentifier";

    private RefreshTokenDAOImpl refreshTokenDAO;
    private Connection connection = null;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    private OAuthServerConfiguration mockOAuthServerConfiguration;
    private TokenPersistenceProcessor mockTokenPersistenceProcessor;

    @BeforeClass
    public void initTest() throws Exception {

        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath(H2_SCRIPT_NAME));
        // Insert test application data
        insertTestApplication();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);

        // Set up PrivilegedCarbonContext.
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(TEST_TENANT_DOMAIN);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(TEST_TENANT_ID);

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.isTokenCleanupEnabled()).thenReturn(false);
        lenient().when(mockOAuthServerConfiguration.getHashAlgorithm()).thenReturn("SHA-256");
        lenient().when(mockOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(300L);

        mockTokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                .thenReturn(mockTokenPersistenceProcessor);

        // Mock token persistence processor methods - return the same value (no hashing for tests)
        lenient().when(mockTokenPersistenceProcessor.getProcessedClientId(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(mockTokenPersistenceProcessor.getPreprocessedClientId(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(mockTokenPersistenceProcessor.getProcessedRefreshToken(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(mockTokenPersistenceProcessor.getPreprocessedRefreshToken(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(mockTokenPersistenceProcessor.getProcessedAccessTokenIdentifier(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Now mock other static classes
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        identityUtil = mockStatic(IdentityUtil.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        oAuth2Util = mockStatic(OAuth2Util.class, InvocationOnMock::callRealMethod);

        // Mock IdentityDatabaseUtil to return our test connection
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenAnswer(inv -> DAOUtils.getConnection(DB_NAME));
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenAnswer(inv -> DAOUtils.getConnection(DB_NAME));
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection)
                .thenAnswer(inv -> DAOUtils.getConnection(DB_NAME));
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(any(Connection.class)))
                .then(invocation -> {
                    Connection conn = invocation.getArgument(0);
                    if (conn != null && !conn.isClosed() && !conn.getAutoCommit()) {
                        conn.commit();
                    }
                    return null;
                });
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(any(Connection.class)))
                .then(invocation -> {
                    Connection conn = invocation.getArgument(0);
                    if (conn != null && !conn.isClosed()) {
                        conn.rollback();
                    }
                    return null;
                });

        // Mock tenant resolution
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TEST_TENANT_ID))
                .thenReturn(TEST_TENANT_DOMAIN);

        oAuth2Util.when(() -> OAuth2Util.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomain(TEST_TENANT_ID)).thenReturn(TEST_TENANT_DOMAIN);
        oAuth2Util.when(() -> OAuth2Util.getUserStoreDomain(any(AuthenticatedUser.class)))
                .thenReturn(PRIMARY_USER_STORE);
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedIDP(any(AuthenticatedUser.class))).thenReturn("LOCAL");
        oAuth2Util.when(() -> OAuth2Util.getSanitizedUserStoreDomain(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Mock isAccessTokenPersistenceEnabled to return false so RefreshTokenDAOImpl is enabled
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);
        oAuth2Util.when(OAuth2Util::isRefreshTokenPersistenceEnabled).thenReturn(true);

        identityUtil.when(() -> IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
        identityUtil.when(() -> IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);

        refreshTokenDAO = new RefreshTokenDAOImpl();
    }

    @AfterMethod(alwaysRun = true)
    public void closeup() throws Exception {

        // Cleanup tokens after each test
        cleanupRefreshTokens();

        if (connection != null && !connection.isClosed()) {
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
    }

    private void closeMockSafely(MockedStatic<?> mock) {

        if (mock != null) {
            try {
                mock.close();
            } catch (Exception e) {
                // Ignore if already closed.
            }
        }
    }

    @AfterClass
    public void tearDown() throws Exception {

        DAOUtils.closeDataSource(DB_NAME);
    }

    // ======================== Helper Methods ========================

    private void insertTestApplication() throws Exception {

        try (Connection conn = DAOUtils.getConnection(DB_NAME)) {
            String sql = "INSERT INTO IDN_OAUTH_CONSUMER_APPS (CONSUMER_KEY, CONSUMER_SECRET, USERNAME, " +
                    "TENANT_ID, USER_DOMAIN, APP_NAME, OAUTH_VERSION) VALUES (?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, TEST_CONSUMER_KEY);
                ps.setString(2, TEST_CONSUMER_SECRET);
                ps.setString(3, TEST_USER);
                ps.setInt(4, TEST_TENANT_ID);
                ps.setString(5, PRIMARY_USER_STORE);
                ps.setString(6, "TestApp");
                ps.setString(7, "OAuth-2.0");
                ps.executeUpdate();
            }
        }
    }

    private AccessTokenDO createTestAccessTokenDO(String refreshToken, String[] scopes) {

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setTokenId(UUID.randomUUID().toString());
        accessTokenDO.setConsumerKey(TEST_CONSUMER_KEY);
        accessTokenDO.setRefreshToken(refreshToken);
        accessTokenDO.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis()));
        accessTokenDO.setRefreshTokenValidityPeriodInMillis(3600000L);
        accessTokenDO.setScope(scopes);
        accessTokenDO.setGrantType(TEST_GRANT_TYPE);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(PRIMARY_USER_STORE);
        authenticatedUser.setAuthenticatedSubjectIdentifier(TEST_SUBJECT_IDENTIFIER);
        accessTokenDO.setAuthzUser(authenticatedUser);

        return accessTokenDO;
    }

    private AuthenticatedUser createTestAuthenticatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(PRIMARY_USER_STORE);
        authenticatedUser.setAuthenticatedSubjectIdentifier(TEST_SUBJECT_IDENTIFIER);
        return authenticatedUser;
    }

    private void insertRefreshTokenDirectly(String tokenId, String refreshToken, String[] scopes, String state)
            throws SQLException {

        try (Connection conn = DAOUtils.getConnection(DB_NAME)) {
            String sql = "INSERT INTO IDN_OAUTH2_REFRESH_TOKEN (REFRESH_TOKEN_ID, REFRESH_TOKEN, CONSUMER_KEY_ID, " +
                    "AUTHZ_USER, TENANT_ID, USER_DOMAIN, GRANT_TYPE, REFRESH_TOKEN_TIME_CREATED, " +
                    "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, TOKEN_STATE, SUBJECT_IDENTIFIER, " +
                    "REFRESH_TOKEN_HASH, IDP_ID, CONSENTED_TOKEN, AUTHORIZED_ORGANIZATION) " +
                    "SELECT ?, ?, ID, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, " +
                    "(SELECT ID FROM IDP WHERE NAME = 'LOCAL' AND TENANT_ID = ?), ?, ? " +
                    "FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, tokenId);
                ps.setString(2, refreshToken);
                ps.setString(3, TEST_USER);
                ps.setInt(4, TEST_TENANT_ID);
                ps.setString(5, PRIMARY_USER_STORE);
                ps.setString(6, TEST_GRANT_TYPE);
                ps.setLong(7, 3600000L);
                ps.setString(8, OAuth2Util.hashScopes(scopes));
                ps.setString(9, state);
                ps.setString(10, TEST_SUBJECT_IDENTIFIER);
                ps.setString(11, refreshToken); // Set hash same as token for test queries
                ps.setInt(12, TEST_TENANT_ID);
                ps.setString(13, "false");
                ps.setString(14, "NONE");
                ps.setString(15, TEST_CONSUMER_KEY);
                ps.executeUpdate();
            }

            // Insert scopes
            for (String scope : scopes) {
                insertRefreshTokenScope(conn, tokenId, scope);
            }
        }
    }

    private void insertRefreshTokenScope(Connection conn, String tokenId, String scope) throws SQLException {

        String sql = "INSERT INTO IDN_OAUTH2_REFRESH_TOKEN_SCOPE (REFRESH_TOKEN_ID, TOKEN_SCOPE, TENANT_ID) " +
                "VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, tokenId);
            ps.setString(2, scope);
            ps.setInt(3, TEST_TENANT_ID);
            ps.executeUpdate();
        }
    }

    private void cleanupRefreshTokens() {

        try (Connection conn = DAOUtils.getConnection(DB_NAME)) {
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM IDN_OAUTH2_REFRESH_TOKEN_SCOPE")) {
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM IDN_OAUTH2_REFRESH_TOKEN")) {
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            // Ignore cleanup errors
        }
    }

    private String getTokenStateFromDB(String tokenId) throws SQLException {

        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT TOKEN_STATE FROM IDN_OAUTH2_REFRESH_TOKEN WHERE REFRESH_TOKEN_ID = ?")) {
            ps.setString(1, tokenId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("TOKEN_STATE");
                }
            }
        }
        return null;
    }

    private int countRefreshTokensInDB() throws SQLException {

        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM IDN_OAUTH2_REFRESH_TOKEN");
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        }
        return 0;
    }

    // ======================== Test: Database Table Creation ========================

    @Test
    public void testDatabaseTablesCreated() throws Exception {

        // Verify that the refreshToken.sql script created the required tables
        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'IDN_OAUTH2_REFRESH_TOKEN'");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next() && rs.getInt(1) > 0,
                    "IDN_OAUTH2_REFRESH_TOKEN table should exist");
        }

        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME =" +
                             " 'IDN_OAUTH2_REFRESH_TOKEN_SCOPE'");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next() && rs.getInt(1) > 0,
                    "IDN_OAUTH2_REFRESH_TOKEN_SCOPE table should exist");
        }
    }

    // ======================== Test: Revoke Token and Assert State ========================

    @Test
    public void testRevokeTokensForApp_VerifyAllTokensRevoked() throws Exception {

        // Insert multiple tokens for the same app
        String tokenId1 = UUID.randomUUID().toString();
        String refreshToken1 = "app-token-1-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId1, refreshToken1, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        String tokenId2 = UUID.randomUUID().toString();
        String refreshToken2 = "app-token-2-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId2, refreshToken2, SCOPES_WITHOUT_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Verify initial states
        assertEquals(getTokenStateFromDB(tokenId1), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token 1 initial state should be ACTIVE");
        assertEquals(getTokenStateFromDB(tokenId2), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token 2 initial state should be ACTIVE");

        // Revoke all tokens for the app
        refreshTokenDAO.revokeTokensForApp(TEST_CONSUMER_KEY);

        // Verify all tokens are REVOKED
        assertEquals(getTokenStateFromDB(tokenId1), OAuthConstants.TokenStates.TOKEN_STATE_REVOKED,
                "Token 1 should be REVOKED after app revocation");
        assertEquals(getTokenStateFromDB(tokenId2), OAuthConstants.TokenStates.TOKEN_STATE_REVOKED,
                "Token 2 should be REVOKED after app revocation");
    }

    @Test
    public void testRevokeTokensByUser_VerifyAllUserTokensRevoked() throws Exception {

        // Insert multiple tokens for the same user
        String tokenId1 = UUID.randomUUID().toString();
        String refreshToken1 = "user-token-1-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId1, refreshToken1, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        String tokenId2 = UUID.randomUUID().toString();
        String refreshToken2 = "user-token-2-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId2, refreshToken2, SCOPES_WITHOUT_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Verify initial states
        assertEquals(getTokenStateFromDB(tokenId1), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token 1 initial state should be ACTIVE");
        assertEquals(getTokenStateFromDB(tokenId2), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token 2 initial state should be ACTIVE");

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        // Revoke all tokens for the user
        refreshTokenDAO.revokeTokensByUser(authenticatedUser, TEST_TENANT_ID, PRIMARY_USER_STORE);

        // Verify all tokens are REVOKED
        assertEquals(getTokenStateFromDB(tokenId1), OAuthConstants.TokenStates.TOKEN_STATE_REVOKED,
                "Token 1 should be REVOKED after user revocation");
        assertEquals(getTokenStateFromDB(tokenId2), OAuthConstants.TokenStates.TOKEN_STATE_REVOKED,
                "Token 2 should be REVOKED after user revocation");
    }

    // ======================== Test: GetRefreshTokensByUserForOpenidScope ========================

    @Test
    public void testGetRefreshTokensByUserForOpenidScope_WithOpenidScope() throws Exception {

        // Insert a token WITH openid scope
        String tokenId1 = UUID.randomUUID().toString();
        String refreshToken1 = "openid-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId1, refreshToken1, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        Set<AccessTokenDO> result = refreshTokenDAO.getRefreshTokensByUserForOpenidScope(authenticatedUser);

        assertNotNull(result, "Result should not be null");
        assertFalse(result.isEmpty(), "Should return tokens with openid scope");
        assertEquals(result.size(), 1, "Should return exactly one token");
    }

    @Test
    public void testGetRefreshTokensByUserForOpenidScope_WithoutOpenidScope() throws Exception {

        // Insert a token WITHOUT openid scope
        String tokenId = UUID.randomUUID().toString();
        String refreshToken = "no-openid-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId, refreshToken, SCOPES_WITHOUT_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        Set<AccessTokenDO> result = refreshTokenDAO.getRefreshTokensByUserForOpenidScope(authenticatedUser);

        assertNotNull(result, "Result should not be null");
        assertTrue(result.isEmpty(), "Should NOT return tokens without openid scope");
    }

    @Test
    public void testGetRefreshTokensByUserForOpenidScope_MixedScopes() throws Exception {

        // Insert a token WITH openid scope
        String tokenId1 = UUID.randomUUID().toString();
        String refreshToken1 = "with-openid-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId1, refreshToken1, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Insert a token WITHOUT openid scope
        String tokenId2 = UUID.randomUUID().toString();
        String refreshToken2 = "without-openid-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId2, refreshToken2, SCOPES_WITHOUT_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        Set<AccessTokenDO> result = refreshTokenDAO.getRefreshTokensByUserForOpenidScope(authenticatedUser);

        assertNotNull(result, "Result should not be null");
        assertEquals(result.size(), 1, "Should return only one token (with openid scope)");
    }

    // ======================== Test: Disabled Scenarios ========================

    @Test
    public void testInsertRefreshToken_WhenDisabled() throws Exception {

        // Mock isEnabled to return false (access token persistence enabled)
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        AccessTokenDO accessTokenDO = createTestAccessTokenDO("disabled-test-token", SCOPES_WITH_OPENID);

        // Should not throw exception, just return without doing anything
        refreshTokenDAO.insertRefreshToken("accessToken", TEST_CONSUMER_KEY, accessTokenDO,
                PRIMARY_USER_STORE);

        // Verify no token was inserted
        assertEquals(countRefreshTokensInDB(), 0, "No token should be inserted when DAO is disabled");
    }

    @Test
    public void testRevokeToken_WhenDisabled() throws Exception {

        // First insert a token
        String tokenId = UUID.randomUUID().toString();
        String refreshToken = "disabled-revoke-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId, refreshToken, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        // Should not throw exception, just return without doing anything
        refreshTokenDAO.revokeToken(refreshToken);

        // Verify token state is still ACTIVE (not revoked because DAO was disabled)
        assertEquals(getTokenStateFromDB(tokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token should still be ACTIVE when DAO is disabled");
    }

    @Test
    public void testRevokeTokensForApp_WhenDisabled() throws Exception {

        // Insert a token
        String tokenId = UUID.randomUUID().toString();
        String refreshToken = "disabled-app-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId, refreshToken, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        // Should not throw exception
        refreshTokenDAO.revokeTokensForApp(TEST_CONSUMER_KEY);

        // Verify token state is still ACTIVE
        assertEquals(getTokenStateFromDB(tokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token should still be ACTIVE when DAO is disabled");
    }

    @Test
    public void testRevokeTokensByUser_WhenDisabled() throws Exception {

        // Insert a token
        String tokenId = UUID.randomUUID().toString();
        String refreshToken = "disabled-user-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId, refreshToken, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        // Should not throw exception
        refreshTokenDAO.revokeTokensByUser(authenticatedUser, TEST_TENANT_ID, PRIMARY_USER_STORE);

        // Verify token state is still ACTIVE
        assertEquals(getTokenStateFromDB(tokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Token should still be ACTIVE when DAO is disabled");
    }

    @Test
    public void testGetRefreshTokensByUserForOpenidScope_WhenDisabled() throws Exception {

        // Insert a token
        String tokenId = UUID.randomUUID().toString();
        String refreshToken = "disabled-openid-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(tokenId, refreshToken, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        Set<AccessTokenDO> result = refreshTokenDAO.getRefreshTokensByUserForOpenidScope(authenticatedUser);

        assertNull(result, "Should return null when DAO is disabled");
    }

    @Test
    public void testGetActiveRefreshToken_WhenDisabled() throws Exception {

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        AuthenticatedUser authzUser = createTestAuthenticatedUser();

        AccessTokenDO result = refreshTokenDAO.getActiveRefreshToken(TEST_CONSUMER_KEY, authzUser,
                PRIMARY_USER_STORE, "openid profile");

        assertNull(result, "Should return null when DAO is disabled");
    }

    @Test
    public void testValidateRefreshToken_WhenDisabled() throws Exception {

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        RefreshTokenValidationDataDO result = refreshTokenDAO.validateRefreshToken(TEST_CONSUMER_KEY,
                "some-token");

        assertNull(result, "Should return null when DAO is disabled");
    }

    @Test
    public void testGetRefreshToken_WhenDisabled() throws Exception {

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        AccessTokenDO result = refreshTokenDAO.getRefreshToken("some-token");

        assertNull(result, "Should return null when DAO is disabled");
    }

    @Test
    public void testInvalidateAndCreateNewRefreshToken_WhenDisabled() throws Exception {

        // Mock isEnabled to return false
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        AccessTokenDO accessTokenDO = createTestAccessTokenDO("new-token", SCOPES_WITH_OPENID);

        // Should not throw exception
        refreshTokenDAO.invalidateAndCreateNewRefreshToken("old-token-id",
                OAuthConstants.TokenStates.TOKEN_STATE_REVOKED, TEST_CONSUMER_KEY,
                accessTokenDO, PRIMARY_USER_STORE);

        // Verify no token was inserted
        assertEquals(countRefreshTokensInDB(), 0, "No token should be inserted when DAO is disabled");
    }

    // ======================== Test: Exception Handling ========================

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateRefreshToken_NullToken() throws Exception {

        refreshTokenDAO.validateRefreshToken(TEST_CONSUMER_KEY, null);
    }

    // ======================== Test: No Tokens Scenario ========================

    @Test
    public void testGetRefreshTokensByUserForOpenidScope_NoTokens() throws Exception {

        AuthenticatedUser authenticatedUser = createTestAuthenticatedUser();

        Set<AccessTokenDO> result = refreshTokenDAO.getRefreshTokensByUserForOpenidScope(authenticatedUser);

        assertNotNull(result, "Result should not be null even when no tokens exist");
        assertTrue(result.isEmpty(), "Result should be empty when no tokens exist");
    }

    @Test
    public void testGetActiveRefreshToken_NoTokens() throws Exception {

        AuthenticatedUser authzUser = createTestAuthenticatedUser();
        String scopeString = String.join(" ", SCOPES_WITH_OPENID);

        AccessTokenDO result = refreshTokenDAO.getActiveRefreshToken(TEST_CONSUMER_KEY, authzUser,
                PRIMARY_USER_STORE, scopeString);

        assertNull(result, "Should return null when no tokens exist");
    }

    // ======================== Test: Insert Refresh Token via DAO ========================

    @Test
    public void testInsertRefreshToken_VerifyDataInsertedInDB() throws Exception {

        // Create a refresh token
        String refreshToken = "dao-insert-test-token-" + UUID.randomUUID();
        String tokenId = UUID.randomUUID().toString();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setConsumerKey(TEST_CONSUMER_KEY);
        accessTokenDO.setRefreshToken(refreshToken);
        accessTokenDO.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis()));
        accessTokenDO.setRefreshTokenValidityPeriodInMillis(3600000L);
        accessTokenDO.setScope(SCOPES_WITH_OPENID);
        accessTokenDO.setGrantType(TEST_GRANT_TYPE);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(PRIMARY_USER_STORE);
        authenticatedUser.setAuthenticatedSubjectIdentifier(TEST_SUBJECT_IDENTIFIER);
        accessTokenDO.setAuthzUser(authenticatedUser);

        // Verify no tokens exist before insert
        assertEquals(countRefreshTokensInDB(), 0, "No tokens should exist before insert");

        // Call the DAO method to insert the refresh token
        refreshTokenDAO.insertRefreshToken("accessToken", TEST_CONSUMER_KEY, accessTokenDO, PRIMARY_USER_STORE);

        // Verify token was inserted in DB
        assertEquals(countRefreshTokensInDB(), 1, "One token should be inserted in DB");

        // Verify token details in DB
        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT REFRESH_TOKEN_ID, REFRESH_TOKEN, TOKEN_STATE, GRANT_TYPE, AUTHZ_USER, " +
                     "SUBJECT_IDENTIFIER FROM IDN_OAUTH2_REFRESH_TOKEN WHERE REFRESH_TOKEN_ID = ?")) {
            ps.setString(1, tokenId);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "Token should exist in database");
                assertEquals(rs.getString("REFRESH_TOKEN_ID"), tokenId, "Token ID should match");
                assertEquals(rs.getString("TOKEN_STATE"), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                        "Token state should be ACTIVE");
                assertEquals(rs.getString("GRANT_TYPE"), TEST_GRANT_TYPE, "Grant type should match");
                assertEquals(rs.getString("AUTHZ_USER"), TEST_USER, "Authorized user should match");
                assertEquals(rs.getString("SUBJECT_IDENTIFIER"), TEST_SUBJECT_IDENTIFIER,
                        "Subject identifier should match");
            }
        }
    }

    @Test
    public void testInsertRefreshToken_WithExistingToken_VerifyDataInsertedInDB() throws Exception {

        // Create first refresh token
        String refreshToken1 = "existing-token-" + UUID.randomUUID();
        String tokenId1 = UUID.randomUUID().toString();
        AccessTokenDO existingAccessTokenDO = createTestAccessTokenDO(refreshToken1, SCOPES_WITH_OPENID);
        existingAccessTokenDO.setTokenId(tokenId1);

        // Create new refresh token
        String refreshToken2 = "new-token-" + UUID.randomUUID();
        String tokenId2 = UUID.randomUUID().toString();
        AccessTokenDO newAccessTokenDO = createTestAccessTokenDO(refreshToken2, SCOPES_WITH_OPENID);
        newAccessTokenDO.setTokenId(tokenId2);

        // Verify no tokens exist before insert
        assertEquals(countRefreshTokensInDB(), 0, "No tokens should exist before insert");

        // Call the DAO method to insert the new refresh token (with existing token context)
        boolean result = refreshTokenDAO.insertRefreshToken("accessToken", TEST_CONSUMER_KEY,
                newAccessTokenDO, existingAccessTokenDO, PRIMARY_USER_STORE);

        // Verify the method returns true
        assertTrue(result, "insertRefreshToken should return true on successful insert");

        // Verify token was inserted in DB
        assertEquals(countRefreshTokensInDB(), 1, "One token should be inserted in DB");

        // Verify the inserted token is the new one
        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT REFRESH_TOKEN_ID, TOKEN_STATE FROM IDN_OAUTH2_REFRESH_TOKEN WHERE REFRESH_TOKEN_ID = ?")) {
            ps.setString(1, tokenId2);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "New token should exist in database");
                assertEquals(rs.getString("REFRESH_TOKEN_ID"), tokenId2, "Token ID should match new token");
                assertEquals(rs.getString("TOKEN_STATE"), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                        "Token state should be ACTIVE");
            }
        }
    }

    // ======================== Test: Invalidate And Create New Refresh Token ========================

    @Test
    public void testInvalidateAndCreateNewRefreshToken_VerifyOldTokenInvalidatedAndNewTokenInserted() throws Exception {

        // Step 1: Insert an existing token directly to DB
        String oldTokenId = UUID.randomUUID().toString();
        String oldRefreshToken = "old-refresh-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(oldTokenId, oldRefreshToken, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Verify old token exists and is ACTIVE
        assertEquals(countRefreshTokensInDB(), 1, "One token should exist before invalidation");
        assertEquals(getTokenStateFromDB(oldTokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Old token should be ACTIVE initially");

        // Step 2: Create new token to replace the old one
        String newTokenId = UUID.randomUUID().toString();
        String newRefreshToken = "new-refresh-token-" + UUID.randomUUID();

        AccessTokenDO newAccessTokenDO = new AccessTokenDO();
        newAccessTokenDO.setTokenId(newTokenId);
        newAccessTokenDO.setConsumerKey(TEST_CONSUMER_KEY);
        newAccessTokenDO.setRefreshToken(newRefreshToken);
        newAccessTokenDO.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis()));
        newAccessTokenDO.setRefreshTokenValidityPeriodInMillis(3600000L);
        newAccessTokenDO.setScope(SCOPES_WITH_OPENID);
        newAccessTokenDO.setGrantType(TEST_GRANT_TYPE);
        newAccessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(PRIMARY_USER_STORE);
        authenticatedUser.setAuthenticatedSubjectIdentifier(TEST_SUBJECT_IDENTIFIER);
        newAccessTokenDO.setAuthzUser(authenticatedUser);

        // Step 3: Call invalidateAndCreateNewRefreshToken
        refreshTokenDAO.invalidateAndCreateNewRefreshToken(
                oldTokenId,
                OAuthConstants.TokenStates.TOKEN_STATE_REVOKED,
                TEST_CONSUMER_KEY,
                newAccessTokenDO,
                PRIMARY_USER_STORE);

        // Step 4: Verify old token is now REVOKED
        assertEquals(getTokenStateFromDB(oldTokenId), OAuthConstants.TokenStates.TOKEN_STATE_REVOKED,
                "Old token should be REVOKED after invalidation");

        // Step 5: Verify new token exists and is ACTIVE
        assertEquals(countRefreshTokensInDB(), 2, "Two tokens should exist after invalidation and insert");
        assertEquals(getTokenStateFromDB(newTokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "New token should be ACTIVE");

        // Step 6: Verify new token details in DB
        try (Connection conn = DAOUtils.getConnection(DB_NAME);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT REFRESH_TOKEN_ID, REFRESH_TOKEN, TOKEN_STATE, GRANT_TYPE, AUTHZ_USER, " +
                     "SUBJECT_IDENTIFIER FROM IDN_OAUTH2_REFRESH_TOKEN WHERE REFRESH_TOKEN_ID = ?")) {
            ps.setString(1, newTokenId);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "New token should exist in database");
                assertEquals(rs.getString("REFRESH_TOKEN_ID"), newTokenId, "New token ID should match");
                assertEquals(rs.getString("TOKEN_STATE"), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                        "New token state should be ACTIVE");
                assertEquals(rs.getString("GRANT_TYPE"), TEST_GRANT_TYPE, "Grant type should match");
                assertEquals(rs.getString("AUTHZ_USER"), TEST_USER, "Authorized user should match");
                assertEquals(rs.getString("SUBJECT_IDENTIFIER"), TEST_SUBJECT_IDENTIFIER,
                        "Subject identifier should match");
            }
        }
    }

    @Test
    public void testInvalidateAndCreateNewRefreshToken_WithExpiredState() throws Exception {

        // Insert an existing token directly to DB
        String oldTokenId = UUID.randomUUID().toString();
        String oldRefreshToken = "expired-old-token-" + UUID.randomUUID();
        insertRefreshTokenDirectly(oldTokenId, oldRefreshToken, SCOPES_WITH_OPENID,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        // Verify old token is ACTIVE
        assertEquals(getTokenStateFromDB(oldTokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "Old token should be ACTIVE initially");

        // Create new token
        String newTokenId = UUID.randomUUID().toString();
        String newRefreshToken = "new-after-expired-" + UUID.randomUUID();
        AccessTokenDO newAccessTokenDO = createTestAccessTokenDO(newRefreshToken, SCOPES_WITH_OPENID);
        newAccessTokenDO.setTokenId(newTokenId);

        // Call invalidateAndCreateNewRefreshToken with EXPIRED state
        refreshTokenDAO.invalidateAndCreateNewRefreshToken(
                oldTokenId,
                OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED,
                TEST_CONSUMER_KEY,
                newAccessTokenDO,
                PRIMARY_USER_STORE);

        // Verify old token is now EXPIRED
        assertEquals(getTokenStateFromDB(oldTokenId), OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED,
                "Old token should be EXPIRED after invalidation");

        // Verify new token is ACTIVE
        assertEquals(getTokenStateFromDB(newTokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "New token should be ACTIVE");

        // Verify total count
        assertEquals(countRefreshTokensInDB(), 2, "Two tokens should exist in DB");
    }

}
