/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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

import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuth2Util.class, IdentityUtil.class,
        IdentityTenantUtil.class, OAuth2ServiceComponentHolder.class, OAuth2TokenUtil.class,
        OAuthComponentServiceHolder.class})
public class AccessTokenDAOImplTest extends PowerMockTestCase {
    public static final String H2_SCRIPT_NAME = "identity.sql";
    public static final String H2_SCRIPT2_NAME = "insert_token_binding.sql";
    public static final String DB_NAME = "AccessTokenDB";
    private static final String EXPIRED_TOKEN_ID = "expired_token_id";
    private static final String TEST_TENANT_DOMAIN = "TestTenantDomain";
    private static final String TEST_USER1 = "user1";
    private static final String PRIMARY_USER_STORE = "PRIMARY";
    Connection connection = null;
    private AccessTokenDAOImpl accessTokenDAO;
    @Mock
    private RealmService mockRealmService;
    @Mock private OAuthComponentServiceHolder mockOAuthComponentServiceHolder;
    @Mock private TenantManager mockTenantManager;
    @Mock private OAuth2ServiceComponentHolder mockOAuth2ServiceComponentHolder;

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

        PowerMockito.mockStatic(IdentityDatabaseUtil.class);
        PowerMockito.mockStatic(OAuthServerConfiguration.class);

        OAuthServerConfiguration mockConfig = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockConfig);
        when(mockConfig.isTokenCleanupEnabled()).thenReturn(true);
        when(mockConfig.getHashAlgorithm()).thenReturn("SHA-256");

        TokenPersistenceProcessor mockTokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        when(mockConfig.getPersistenceProcessor()).thenReturn(mockTokenPersistenceProcessor);

        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.mockStatic(IdentityUtil.class);
        PowerMockito.mockStatic(IdentityTenantUtil.class);
        PowerMockito.mockStatic(OAuth2ServiceComponentHolder.class);
        PowerMockito.mockStatic(OAuth2TokenUtil.class);
        PowerMockito.mockStatic(OAuthComponentServiceHolder.class);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);

        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1234);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("carbon.super");

        when(OAuth2Util.getTenantId(anyString())).thenReturn(1234);
        when(OAuth2Util.getTenantDomain(anyInt())).thenReturn("carbon.super");

        when(IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);

        accessTokenDAO = new AccessTokenDAOImpl();
    }


    @Test
    public void testGetActiveAccessTokenDataByConsumerKey() throws Exception {

        String consumerKey = "testConsumerKey";
        String token = "testToken";
        String authzUser = "testUser";
        int tenantId = 1;
        String userDomain = "PRIMARY";
        String scope = "testScope";
        String idpName = "LOCAL";
        Timestamp issuedTime = new Timestamp(System.currentTimeMillis());
        long validityPeriod = 3600L;

        connection = mock(Connection.class);

        PowerMockito.mockStatic(OAuthComponentServiceHolder.class);
        PowerMockito.mockStatic(OAuth2ServiceComponentHolder.class);
        PowerMockito.mockStatic(IdentityTenantUtil.class);
        PowerMockito.mockStatic(IdentityUtil.class);

        when(OAuthComponentServiceHolder.getInstance())
                .thenReturn(mockOAuthComponentServiceHolder);
        when(mockOAuthComponentServiceHolder.getRealmService())
                .thenReturn(mockRealmService);
        when(mockRealmService.getTenantManager())
                .thenReturn(mockTenantManager);

        when(OAuth2ServiceComponentHolder.getInstance())
                .thenReturn(mockOAuth2ServiceComponentHolder);
        when(OAuth2Util.getTokenPartitionedSqlByUserStore(anyString(), anyString()))
                .thenReturn("SELECT * FROM TEST");
        when(IdentityUtil.getPrimaryDomainName())
                .thenReturn(userDomain);

        PreparedStatement mockPs = mock(PreparedStatement.class);
        ResultSet mockRs = mock(ResultSet.class);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);

        when(connection.prepareStatement(anyString())).thenReturn(mockPs);
        when(mockPs.executeQuery()).thenReturn(mockRs);

        when(mockRs.next()).thenReturn(true, false);
        when(mockRs.getString(1)).thenReturn(authzUser);
        when(mockRs.getString(2)).thenReturn(token);
        when(mockRs.getInt(3)).thenReturn(tenantId);
        when(mockRs.getString(4)).thenReturn(userDomain);
        when(mockRs.getString(5)).thenReturn(scope);
        when(mockRs.getString(6)).thenReturn(idpName);
        when(mockRs.getTimestamp(anyInt(), any(Calendar.class))).thenReturn(issuedTime);
        when(mockRs.getLong(8)).thenReturn(validityPeriod);

        Set<AccessTokenDO> result =
                accessTokenDAO.getActiveAcessTokenDataByConsumerKey(consumerKey);

        assertFalse(result.isEmpty());
        AccessTokenDO accessTokenDO = result.iterator().next();
        assertEquals(accessTokenDO.getAccessToken(), token);
        assertEquals(accessTokenDO.getIssuedTime(), issuedTime);
        assertEquals(accessTokenDO.getValidityPeriod(), validityPeriod);
    }

    @Test
    public void testGetAccessTokensByUserForOpenidScope_includeExpiredAccessTokensWithActiveRefreshToken()
            throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        when(OAuth2Util.getTenantId(anyString())).thenReturn(1234);
        when(OAuth2Util.getTokenPartitionedSqlByUserStore(
                SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER, PRIMARY_USER_STORE))
                .thenReturn(SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER);
        // Simulate that the access token is expired.
        when(OAuth2Util.getTimeToExpire(1704103200000L, 3600000L)).thenReturn(-1000L);

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

    @AfterMethod
    public void tearDown() throws SQLException {
        if (connection != null) {
            connection.close();
        }
        PrivilegedCarbonContext.endTenantFlow();
    }
}