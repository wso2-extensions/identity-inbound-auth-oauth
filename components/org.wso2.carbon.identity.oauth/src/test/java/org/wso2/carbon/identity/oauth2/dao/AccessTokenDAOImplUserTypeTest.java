/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Tests for the user type (APPLICATION / APPLICATION_USER) handling of {@link AccessTokenDAOImpl}. A user can hold an
 * active token of each user type for the same client and scope, as the user type is part of the 'CON_APP_KEY'
 * constraint.
 */
@WithCarbonHome
public class AccessTokenDAOImplUserTypeTest {

    private static final String DB_NAME = "AccessTokenUserTypeDB";
    private static final String CONSUMER_KEY = "user-type-test-client-id";
    private static final String USER = "admin";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private static final int SUPER_TENANT_ID = -1234;
    private static final String PRIMARY_USER_STORE = "PRIMARY";
    private static final String LOCAL_IDP = "LOCAL";
    private static final String SCOPE = "default";
    private static final String APPLICATION_USER_TOKEN_ID = "application-user-token-id";
    private static final String APPLICATION_TOKEN_ID = "application-token-id";

    private int consumerKeyId;
    private int localIdpId;
    private long accessTokenExpireMillis;
    private AccessTokenDAOImpl accessTokenDAO;
    private ApplicationManagementService applicationMgtService;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    @BeforeClass
    public void initTest() throws Exception {

        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("identity.sql"));
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES (ID INTEGER " +
                    "AUTO_INCREMENT, TOKEN_ID VARCHAR(255), TOKEN_ATTR_NAME VARCHAR(255), TOKEN_ATTR_VALUE " +
                    "VARCHAR(255), PRIMARY KEY (ID))");
            statement.executeUpdate("INSERT INTO IDN_OAUTH_CONSUMER_APPS (CONSUMER_KEY, CONSUMER_SECRET, USERNAME, " +
                    "TENANT_ID, USER_DOMAIN, APP_NAME, OAUTH_VERSION, GRANT_TYPES) VALUES ('" + CONSUMER_KEY +
                    "', 'secret', '" + USER + "', " + SUPER_TENANT_ID + ", '" + PRIMARY_USER_STORE + "', " +
                    "'userTypeApp', 'OAuth-2.0', 'password client_credentials')");
            statement.executeUpdate("INSERT INTO IDP (TENANT_ID, NAME, UUID) VALUES (" + SUPER_TENANT_ID + ", '" +
                    LOCAL_IDP + "', '" + UUID.randomUUID() + "')");
            consumerKeyId = getId(statement, "SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = '" +
                    CONSUMER_KEY + "'");
            localIdpId = getId(statement, "SELECT ID FROM IDP WHERE NAME = '" + LOCAL_IDP + "' AND TENANT_ID = " +
                    SUPER_TENANT_ID);
        }
    }

    @AfterClass
    public void tearDown() throws Exception {

        DAOUtils.closeDataSource(DB_NAME);
    }

    @BeforeMethod
    public void setUp() throws Exception {

        accessTokenExpireMillis = 0L;

        // Every DAO call gets a new connection with auto commit disabled and real commits and rollbacks, as the
        // 'CON_APP_KEY' recovery depends on the rollback behaviour.
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeAllConnections(any(Connection.class),
                any(ResultSet.class), any(PreparedStatement.class))).thenCallRealMethod();
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeConnection(any(Connection.class)))
                .thenCallRealMethod();
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeStatement(any(PreparedStatement.class)))
                .thenCallRealMethod();
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.closeResultSet(any(ResultSet.class)))
                .thenCallRealMethod();
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenAnswer(invocation -> newConnection());
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(anyBoolean()))
                .thenAnswer(invocation -> newConnection());
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(any(Connection.class)))
                .thenAnswer(invocation -> {
                    invocation.getArgument(0, Connection.class).rollback();
                    return null;
                });
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(any(Connection.class)))
                .thenAnswer(invocation -> {
                    invocation.getArgument(0, Connection.class).commit();
                    return null;
                });

        applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        ApplicationManagementService mockApplicationMgtService = mock(ApplicationManagementService.class);
        lenient().when(mockApplicationMgtService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        OAuth2ServiceComponentHolder.setApplicationMgtService(mockApplicationMgtService);

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                .thenReturn(new PlainTextPersistenceProcessor());
        lenient().when(mockOAuthServerConfiguration.getHashAlgorithm()).thenReturn("SHA-256");
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

        identityUtil = mockStatic(IdentityUtil.class);
        identityUtil.when(() -> IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);

        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(SUPER_TENANT_ID))
                .thenReturn(SUPER_TENANT_DOMAIN);

        OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuer.class);
        oAuth2Util = mockStatic(OAuth2Util.class, InvocationOnMock::callRealMethod);
        oAuth2Util.when(() -> OAuth2Util.getAppTenantId(anyString())).thenReturn(SUPER_TENANT_ID);
        oAuth2Util.when(() -> OAuth2Util.getTenantId(anyString())).thenReturn(SUPER_TENANT_ID);
        oAuth2Util.when(() -> OAuth2Util.getUserStoreDomain(any(AuthenticatedUser.class)))
                .thenReturn(PRIMARY_USER_STORE);
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedIDP(any(AuthenticatedUser.class))).thenReturn(LOCAL_IDP);
        oAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString())).thenReturn(oauthTokenIssuer);
        oAuth2Util.when(() -> OAuth2Util.getAccessTokenExpireMillis(any(AccessTokenDO.class)))
                .thenAnswer(invocation -> accessTokenExpireMillis);

        accessTokenDAO = new AccessTokenDAOImpl();
        seedActiveTokensOfBothUserTypes(OAuth2Util.hashScopes(SCOPE));
    }

    @AfterMethod(alwaysRun = true)
    public void closeMocks() {

        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);

        identityDatabaseUtil.close();
        oAuthServerConfiguration.close();
        oAuth2Util.close();
        identityUtil.close();
        identityTenantUtil.close();
    }

    @Test
    public void testGetLatestAccessTokenConsidersUserType() throws Exception {

        AccessTokenDO anyUserType = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(), PRIMARY_USER_STORE,
                SCOPE, OAuthConstants.TokenBindings.NONE, false);
        assertNotNull(anyUserType);
        assertEquals(anyUserType.getTokenId(), APPLICATION_TOKEN_ID,
                "Without a user type, the latest token of any user type should be returned.");

        AccessTokenDO withoutUserType = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(),
                PRIMARY_USER_STORE, SCOPE, OAuthConstants.TokenBindings.NONE, false, null);
        assertNotNull(withoutUserType);
        assertEquals(withoutUserType.getTokenId(), APPLICATION_TOKEN_ID,
                "A null user type should behave the same as not giving a user type.");

        AccessTokenDO applicationUserToken = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(),
                PRIMARY_USER_STORE, SCOPE, OAuthConstants.TokenBindings.NONE, false,
                OAuthConstants.UserType.APPLICATION_USER);
        assertNotNull(applicationUserToken);
        assertEquals(applicationUserToken.getTokenId(), APPLICATION_USER_TOKEN_ID);
        assertEquals(applicationUserToken.getTokenType(), OAuthConstants.UserType.APPLICATION_USER);

        AccessTokenDO applicationToken = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, SUPER_TENANT_DOMAIN,
                getUser(), PRIMARY_USER_STORE, SCOPE, OAuthConstants.TokenBindings.NONE, true,
                OAuthConstants.UserType.APPLICATION);
        assertNotNull(applicationToken);
        assertEquals(applicationToken.getTokenId(), APPLICATION_TOKEN_ID);
        assertEquals(applicationToken.getTokenType(), OAuthConstants.UserType.APPLICATION);
    }

    @Test
    public void testGetLatestAccessTokenOfUserTypeWhenLatestTokenOfUserTypeIsRevoked() throws Exception {

        updateTokenState(APPLICATION_TOKEN_ID, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);

        assertNull(accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(), PRIMARY_USER_STORE, SCOPE,
                OAuthConstants.TokenBindings.NONE, true, OAuthConstants.UserType.APPLICATION),
                "A revoked token should not be returned.");
        AccessTokenDO applicationUserToken = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(),
                PRIMARY_USER_STORE, SCOPE, OAuthConstants.TokenBindings.NONE, true,
                OAuthConstants.UserType.APPLICATION_USER);
        assertNotNull(applicationUserToken, "The token of the other user type should still be returned.");
        assertEquals(applicationUserToken.getTokenId(), APPLICATION_USER_TOKEN_ID);
    }

    @Test
    public void testGetLatestAccessTokenOfUserTypeWithNullScope() throws Exception {

        // Without a scope, the scope hash filter becomes TOKEN_SCOPE_HASH IS NULL and the user type parameter takes
        // the place of the scope hash parameter.
        seedActiveTokensOfBothUserTypes(null);

        AccessTokenDO applicationUserToken = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(),
                PRIMARY_USER_STORE, null, OAuthConstants.TokenBindings.NONE, false,
                OAuthConstants.UserType.APPLICATION_USER);
        assertNotNull(applicationUserToken);
        assertEquals(applicationUserToken.getTokenId(), APPLICATION_USER_TOKEN_ID);

        AccessTokenDO applicationToken = accessTokenDAO.getLatestAccessToken(CONSUMER_KEY, getUser(),
                PRIMARY_USER_STORE, null, OAuthConstants.TokenBindings.NONE, false,
                OAuthConstants.UserType.APPLICATION);
        assertNotNull(applicationToken);
        assertEquals(applicationToken.getTokenId(), APPLICATION_TOKEN_ID);
    }

    @Test
    public void testGetLatestAccessTokenByStateConsidersUserType() throws Exception {

        Method getLatestAccessTokenByState = AccessTokenDAOImpl.class.getDeclaredMethod(
                "getLatestAccessTokenByState", Connection.class, String.class, AuthenticatedUser.class,
                String.class, String.class, String.class, boolean.class);
        getLatestAccessTokenByState.setAccessible(true);
        try (Connection connection = newConnection()) {
            AccessTokenDO applicationUserToken = (AccessTokenDO) getLatestAccessTokenByState.invoke(accessTokenDAO,
                    connection, CONSUMER_KEY, getUser(), PRIMARY_USER_STORE, SCOPE,
                    OAuthConstants.UserType.APPLICATION_USER, true);
            assertNotNull(applicationUserToken);
            assertEquals(applicationUserToken.getTokenId(), APPLICATION_USER_TOKEN_ID);

            AccessTokenDO applicationToken = (AccessTokenDO) getLatestAccessTokenByState.invoke(accessTokenDAO,
                    connection, CONSUMER_KEY, getUser(), PRIMARY_USER_STORE, SCOPE,
                    OAuthConstants.UserType.APPLICATION, true);
            assertNotNull(applicationToken);
            assertEquals(applicationToken.getTokenId(), APPLICATION_TOKEN_ID);

            assertNull(getLatestAccessTokenByState.invoke(accessTokenDAO, connection, CONSUMER_KEY, getUser(),
                    PRIMARY_USER_STORE, SCOPE, OAuthConstants.UserType.APPLICATION_USER, false),
                    "No non active token should be returned.");
        }
    }

    @Test
    public void testConAppKeyRecoveryInactivatesExpiredTokenOfSameUserType() throws Exception {

        // Both seeded tokens are expired. The latest ACTIVE token is the APPLICATION token, while the token blocking
        // the insert is the older APPLICATION_USER token.
        String newTokenId = UUID.randomUUID().toString();
        accessTokenDAO.insertAccessToken(UUID.randomUUID().toString(), CONSUMER_KEY,
                buildAccessTokenDO(newTokenId, OAuthConstants.UserType.APPLICATION_USER), PRIMARY_USER_STORE);

        assertEquals(getTokenState(newTokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "The new token should be persisted.");
        assertEquals(getTokenState(APPLICATION_USER_TOKEN_ID), OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE,
                "The blocking token of the same user type should be inactivated.");
        assertEquals(getTokenState(APPLICATION_TOKEN_ID), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "The token of the other user type should not be touched.");
    }

    @Test
    public void testConAppKeyRecoveryWhenExistingTokenOfOtherUserTypeIsExpired() throws Exception {

        // The flow of the issue: the token issuance marks the latest token, of the other user type, as expired and
        // inserts a new token, which collides with the older active token of the same user type.
        String newTokenId = UUID.randomUUID().toString();
        AccessTokenDO existingToken = buildAccessTokenDO(APPLICATION_TOKEN_ID, OAuthConstants.UserType.APPLICATION);
        accessTokenDAO.insertAccessToken(UUID.randomUUID().toString(), CONSUMER_KEY,
                buildAccessTokenDO(newTokenId, OAuthConstants.UserType.APPLICATION_USER), existingToken,
                PRIMARY_USER_STORE);

        assertEquals(getTokenState(newTokenId), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "The new token should be persisted.");
        assertEquals(getTokenState(APPLICATION_USER_TOKEN_ID), OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE,
                "The blocking token of the same user type should be inactivated.");
    }

    @Test
    public void testConAppKeyRecoveryReusesActiveTokenOfSameUserType() throws Exception {

        // Both seeded tokens are still valid. The recovery should reuse the APPLICATION_USER token blocking the
        // insert, not the newer APPLICATION token.
        accessTokenExpireMillis = 3600000L;

        String newTokenId = UUID.randomUUID().toString();
        AccessTokenDO newAccessTokenDO = buildAccessTokenDO(newTokenId, OAuthConstants.UserType.APPLICATION_USER);
        accessTokenDAO.insertAccessToken(UUID.randomUUID().toString(), CONSUMER_KEY, newAccessTokenDO,
                PRIMARY_USER_STORE);

        assertEquals(newAccessTokenDO.getTokenId(), APPLICATION_USER_TOKEN_ID,
                "The existing token of the same user type should be reused.");
        assertEquals(newAccessTokenDO.getAccessToken(), getSeededAccessToken(APPLICATION_USER_TOKEN_ID));
        assertEquals(newAccessTokenDO.getTokenType(), OAuthConstants.UserType.APPLICATION_USER);
        assertNull(getTokenState(newTokenId), "A new token should not be persisted.");
        assertEquals(getTokenState(APPLICATION_USER_TOKEN_ID), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        assertEquals(getTokenState(APPLICATION_TOKEN_ID), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
    }

    private void seedActiveTokensOfBothUserTypes(String scopeHash) throws Exception {

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            connection.setAutoCommit(false);
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE CONSUMER_KEY_ID = ?")) {
                delete.setInt(1, consumerKeyId);
                delete.executeUpdate();
            }
            long now = System.currentTimeMillis();
            insertToken(connection, APPLICATION_USER_TOKEN_ID, OAuthConstants.UserType.APPLICATION_USER, "password",
                    new Timestamp(now - 120000), scopeHash);
            insertToken(connection, APPLICATION_TOKEN_ID, OAuthConstants.UserType.APPLICATION, "client_credentials",
                    new Timestamp(now - 60000), scopeHash);
            connection.commit();
        }
    }

    private void insertToken(Connection connection, String tokenId, String userType, String grantType,
                             Timestamp timeCreated, String scopeHash) throws Exception {

        String sql = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (TOKEN_ID, ACCESS_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER, " +
                "TENANT_ID, USER_DOMAIN, USER_TYPE, GRANT_TYPE, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, " +
                "VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, TOKEN_STATE, TOKEN_STATE_ID, " +
                "SUBJECT_IDENTIFIER, IDP_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 3600000, 3600000, ?, 'ACTIVE', " +
                "'NONE', ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tokenId);
            statement.setString(2, getSeededAccessToken(tokenId));
            statement.setInt(3, consumerKeyId);
            statement.setString(4, USER);
            statement.setInt(5, SUPER_TENANT_ID);
            statement.setString(6, PRIMARY_USER_STORE);
            statement.setString(7, userType);
            statement.setString(8, grantType);
            statement.setTimestamp(9, timeCreated);
            statement.setTimestamp(10, timeCreated);
            statement.setString(11, scopeHash);
            statement.setString(12, USER);
            statement.setInt(13, localIdpId);
            statement.executeUpdate();
        }
    }

    private void updateTokenState(String tokenId, String tokenState) throws Exception {

        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET TOKEN_STATE = ?, TOKEN_STATE_ID = ? WHERE TOKEN_ID = ?")) {
            statement.setString(1, tokenState);
            statement.setString(2, UUID.randomUUID().toString());
            statement.setString(3, tokenId);
            statement.executeUpdate();
        }
    }

    private String getSeededAccessToken(String tokenId) {

        return tokenId + "-access-token";
    }

    private AccessTokenDO buildAccessTokenDO(String tokenId, String userType) {

        Timestamp now = new Timestamp(System.currentTimeMillis());
        AccessTokenDO accessTokenDO = new AccessTokenDO(CONSUMER_KEY, getUser(), new String[]{SCOPE}, now, now,
                3600000L, 3600000L, userType);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setGrantType(OAuthConstants.UserType.APPLICATION.equals(userType) ? "client_credentials" :
                "password");
        return accessTokenDO;
    }

    private String getTokenState(String tokenId) throws Exception {

        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT TOKEN_STATE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE TOKEN_ID = ?")) {
            statement.setString(1, tokenId);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? resultSet.getString(1) : null;
            }
        }
    }

    private AuthenticatedUser getUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(USER);
        user.setTenantDomain(SUPER_TENANT_DOMAIN);
        user.setUserStoreDomain(PRIMARY_USER_STORE);
        user.setAuthenticatedSubjectIdentifier(USER);
        user.setUserId(USER);
        return user;
    }

    private Connection newConnection() throws Exception {

        Connection connection = DAOUtils.getConnection(DB_NAME);
        connection.setAutoCommit(false);
        return connection;
    }

    private static int getId(Statement statement, String query) throws Exception {

        try (ResultSet resultSet = statement.executeQuery(query)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }
}
