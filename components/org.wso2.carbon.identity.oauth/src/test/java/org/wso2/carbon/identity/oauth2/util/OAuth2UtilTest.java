/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest({OAuthServerConfiguration.class, OAuthCache.class, IdentityUtil.class, OAuthConsumerDAO.class,
        OAuth2Util.class, OAuthComponentServiceHolder.class})
public class OAuth2UtilTest extends PowerMockIdentityBaseTest {

    private String[] scopeArraySorted = new String[]{"scope1", "scope2", "scope3"};
    private String[] scopeArrayUnSorted = new String[]{"scope2", "scope3", "scope1"};
    private String[] scopeArray = new String[]{"openid", "scope1", "scope2"};
    private String scopeString = "scope1 scope2 scope3";
    private String clientId = "dummyClientId";
    private String clientSecret = "dummyClientSecret";
    private String authorizationCode = "testAuthorizationCode";
    private String tokenType = "testTokenType";
    private AuthenticatedUser authzUser;
    private Integer clientTenatId = 1;
    private Timestamp issuedTime;
    private Timestamp refreshTokenIssuedTime;
    private long validityPeriodInMillis;
    private long refreshTokenValidityPeriodInMillis;

    @Mock
    private OAuthServerConfiguration oauthServerConfigurationMock;

    @Mock
    private OAuthAuthzReqMessageContext authAuthzReqMessageContextMock;

    @Mock
    private OAuthTokenReqMessageContext oAuthTokenReqMessageContextMock;

    @Mock
    private OAuthCache oAuthCacheMock;

    @Mock
    private CacheEntry cacheEntryMock;

    @Mock
    private TokenPersistenceProcessor tokenPersistenceProcessorMock;

    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolderMock;

    @Mock
    private RealmService realmServiceMock;

    @Mock
    private TenantManager tenantManagerMock;

    @BeforeMethod
    public void setUp() throws Exception {
        authzUser = new AuthenticatedUser();
        issuedTime = new Timestamp(System.currentTimeMillis());
        refreshTokenIssuedTime = new Timestamp(System.currentTimeMillis());
        validityPeriodInMillis = 3600000L;
        refreshTokenValidityPeriodInMillis = 3600000L;
        long timestampSkew = 3600L;
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(timestampSkew);
        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolderMock);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testAuthenticateClientCacheHit() throws Exception {
        OAuthCache mockOAuthCache = mock(OAuthCache.class);
        ClientCredentialDO mockCacheEntry = mock(ClientCredentialDO.class);
        when(mockCacheEntry.getClientSecret()).thenReturn(clientSecret);
        when(mockOAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(mockCacheEntry);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(mockOAuthCache);

        assertTrue(OAuth2Util.authenticateClient(clientId, clientSecret));
    }

    @Test
    public void testGetAuthzRequestContext() throws Exception {
        OAuth2Util.setAuthzRequestContext(authAuthzReqMessageContextMock);
        assertEquals(OAuth2Util.getAuthzRequestContext(), authAuthzReqMessageContextMock);
    }

    @Test
    public void testSetAuthzRequestContext() throws Exception {
        OAuth2Util.setAuthzRequestContext(authAuthzReqMessageContextMock);
        assertEquals(OAuth2Util.getAuthzRequestContext(), authAuthzReqMessageContextMock);
    }

    @Test
    public void testClearAuthzRequestContext() throws Exception {
        OAuth2Util.setAuthzRequestContext(authAuthzReqMessageContextMock);
        assertEquals(OAuth2Util.getAuthzRequestContext(), authAuthzReqMessageContextMock);
        OAuth2Util.clearAuthzRequestContext();
        assertNull(OAuth2Util.getAuthzRequestContext());
    }

    @Test
    public void testGetTokenRequestContext() throws Exception {
        OAuth2Util.setTokenRequestContext(oAuthTokenReqMessageContextMock);
        assertEquals(OAuth2Util.getTokenRequestContext(), oAuthTokenReqMessageContextMock);
    }

    @Test
    public void testSetTokenRequestContext() throws Exception {
        OAuth2Util.setTokenRequestContext(oAuthTokenReqMessageContextMock);
        assertEquals(OAuth2Util.getTokenRequestContext(), oAuthTokenReqMessageContextMock);
    }

    @Test
    public void testClearTokenRequestContext() throws Exception {
        OAuth2Util.setTokenRequestContext(oAuthTokenReqMessageContextMock);
        assertEquals(OAuth2Util.getTokenRequestContext(), oAuthTokenReqMessageContextMock);
        OAuth2Util.clearTokenRequestContext();
        assertNull(OAuth2Util.getTokenRequestContext());
    }

    @Test
    public void testGetClientTenatId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenatId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenatId.intValue());
    }

    @Test
    public void testSetClientTenatId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenatId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenatId.intValue());
    }

    @Test
    public void testClearClientTenantId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenatId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenatId.intValue());
        OAuth2Util.clearClientTenantId();
        assertEquals(OAuth2Util.getClientTenatId(), -1);
    }

    @DataProvider(name = "BuildScopeString")
    public Object[][] buildScopeString() {
        return new Object[][]{
                // scope array
                // scope string
                {scopeArraySorted, scopeString},
                {scopeArrayUnSorted, scopeString},
                {null, null},
                {new String[0], ""}
        };
    }

    @Test(dataProvider = "BuildScopeString")
    public void testBuildScopeString(String[] scopeArray, String scopeString) throws Exception {
        assertEquals(OAuth2Util.buildScopeString(scopeArray), scopeString);
    }

    @DataProvider(name = "BuildScopeArray")
    public Object[][] buildScopeArray() {
        return new Object[][]{
                // scopes
                // response
                {scopeString, scopeArraySorted},
                {null, new String[0]}
        };
    }

    @Test(dataProvider = "BuildScopeArray")
    public void testBuildScopeArray(String scopes, String[] response) throws Exception {
        assertEquals(OAuth2Util.buildScopeArray(scopes), response);
    }

    @DataProvider(name = "AuthenticateClient")
    public Object[][] authenticateClient() {
        CacheEntry cacheResult1 = null;
        CacheEntry cacheResult2 = cacheEntryMock;
        CacheEntry cacheResult3 = new ClientCredentialDO(null);
        CacheEntry cacheResult4 = new ClientCredentialDO(clientSecret);
        CacheEntry cacheResult5 = new ClientCredentialDO("7_EsdLmABh_cPdmmYxCTwRdyDG6c");

        // cacheResult
        // dummyClientSecret
        // expectedResult
        return new Object[][]{
                {cacheResult1, null, false},
                {cacheResult1, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult1, clientSecret, true},
                {cacheResult2, null, false},
                {cacheResult2, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult2, clientSecret, true},
                {cacheResult3, null, false},
                {cacheResult3, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult3, clientSecret, true},
                {cacheResult4, null, true},
                {cacheResult4, "4_EedLmABh_cPdmmYxCTwRdyDG5b", true},
                {cacheResult4, clientSecret, true},
                {cacheResult5, null, false},
                {cacheResult5, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult5, clientSecret, false}
        };
    }

    @Test(dataProvider = "AuthenticateClient")
    public void testAuthenticateClient(Object cacheResult, String dummyClientSecret, boolean expectedResult)
            throws Exception {
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCacheMock);
        when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class))).thenReturn((CacheEntry) cacheResult);
        OAuthConsumerDAO oAuthConsumerDAO = mock(OAuthConsumerDAO.class);
        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessorMock);
        whenNew(OAuthConsumerDAO.class).withNoArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(dummyClientSecret);

        assertEquals(OAuth2Util.authenticateClient(clientId, clientSecret), expectedResult);
    }

    @DataProvider(name = "AuthenticateUsername")
    public Object[][] authenticateUsername() {
        CacheEntry cacheResult1 = new ClientCredentialDO(null);
        CacheEntry cacheResult2 = cacheEntryMock;

        // isUsernameCaseSensitive
        // cacheResult
        // dummyClientSecret
        // dummyUserName
        // expectedResult
        return new Object[][]{
                {false, cacheResult1, "4_EedLmABh_cPdmmYxCTwRdyDG5b", "testUser", null},
                {false, cacheResult1, clientSecret, "testUser", "testUser"},
                {false, cacheResult1, "4_EedLmABh_cPdmmYxCTwRdyDG5b", null, null},
                {false, cacheResult1, clientSecret, null, null},
                {true, cacheResult2, "4_EedLmABh_cPdmmYxCTwRdyDG5b", "testUser", null},
                {true, cacheResult2, clientSecret, "testUser", "testUser"},
                {true, cacheResult2, "4_EedLmABh_cPdmmYxCTwRdyDG5b", null, null},
                {true, cacheResult2, clientSecret, null, null}
        };
    }

    @Test(dataProvider = "AuthenticateUsername")
    public void testGetAuthenticatedUsername(boolean isUsernameCaseSensitive, Object cacheResult, String
            dummyClientSecret, String dummyUserName, String expectedResult) throws Exception {
        mockStatic(OAuthCache.class);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(isUsernameCaseSensitive);

        when(OAuthCache.getInstance()).thenReturn(oAuthCacheMock);
        when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class))).thenReturn((CacheEntry) cacheResult);
        OAuthConsumerDAO oAuthConsumerDAO = mock(OAuthConsumerDAO.class);
        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessorMock);
        whenNew(OAuthConsumerDAO.class).withNoArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(dummyClientSecret);
        when(oAuthConsumerDAO.getAuthenticatedUsername(anyString(), anyString())).thenReturn(dummyUserName);

        assertEquals(OAuth2Util.getAuthenticatedUsername(clientId, clientSecret), expectedResult);
    }

    @Test
    public void testBuildCacheKeyStringForAuthzCode() throws Exception {

        String authzCode = "testAuthzCode";
        String testAuthzCode = clientId + ":" + authzCode;
        assertEquals(OAuth2Util.buildCacheKeyStringForAuthzCode(clientId, authzCode), testAuthzCode);
    }

    @Test
    public void testValidateAccessTokenDO() throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertEquals(OAuth2Util.validateAccessTokenDO(accessTokenDO), accessTokenDO);
    }

    @DataProvider(name = "booleanData")
    public Object[][] booleanData() {
        return new Object[][]{
                {false, false},
                {true, true}
        };
    }

    @Test(dataProvider = "booleanData")
    public void testCheckAccessTokenPartitioningEnabled(boolean value, boolean expectedResult) throws Exception {
        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled()).thenReturn(value);
        assertEquals(OAuth2Util.checkAccessTokenPartitioningEnabled(), expectedResult);
    }

    @Test(dataProvider = "booleanData")
    public void testCheckUserNameAssertionEnabled(boolean value, boolean expectedResult) throws Exception {
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(value);
        assertEquals(OAuth2Util.checkUserNameAssertionEnabled(), expectedResult);
    }

    @Test
    public void testGetAccessTokenPartitioningDomains() throws Exception {
        String accessTokenPartitioningDomains = "A:foo.com , B:bar.com";
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn(accessTokenPartitioningDomains);
        assertEquals(OAuth2Util.getAccessTokenPartitioningDomains(), accessTokenPartitioningDomains);
    }

    @DataProvider(name = "accessTokenPartitioningDomainsData")
    public Object[][] accessTokenPartitioningDomainsData() {
        return new Object[][]{
                // accessTokenPartitioningDomains
                // expectedResult
                {"A:foo.com , B:bar.com", 2},
                {null, 0}
        };
    }

    @Test(dataProvider = "accessTokenPartitioningDomainsData")
    public void testGetAvailableUserStoreDomainMappings(String accessTokenPartitioningDomains, int expectedResult)
            throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn(accessTokenPartitioningDomains);
        Map<String, String> userStoreDomainMap = OAuth2Util.getAvailableUserStoreDomainMappings();
        assertEquals(userStoreDomainMap.size(), expectedResult);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAvailableUserStoreDomainMappings1() throws Exception {
        String accessTokenPartitioningDomains = "A: , B:bar.com";
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn(accessTokenPartitioningDomains);
        OAuth2Util.getAvailableUserStoreDomainMappings();
    }

    @DataProvider(name = "accessMappedUserStoreDomainData")
    public Object[][] accessMappedUserStoreDomainData() {
        return new Object[][]{
                // accessTokenPartitioningDomains
                // userStoreDomain
                // expectedResult
                {"A:foo.com, B:bar.com", "foo.com", "A"},
                {"A:foo.com , B:bar.com", "bar.com", "B"},
                {"A:foo.com , B:bar.com", null, null},
                {"A:foo.com , B:bar.com", "test.com", "test.com"}
        };
    }

    @Test(dataProvider = "accessMappedUserStoreDomainData")
    public void testGetMappedUserStoreDomain(String accessTokenPartitioningDomains, String userStoreDomain,
                                             String expectedResult) throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn(accessTokenPartitioningDomains);
        assertEquals(OAuth2Util.getMappedUserStoreDomain(userStoreDomain), expectedResult);
    }

    @DataProvider(name = "TestGetPartitionedTableByUserStoreDataProvider")
    public Object[][] getPartitionedTableByUserStoreData() {
        return new Object[][]{
                // tableName
                // userstoreDomain
                // partionedTableName
                {"IDN_OAUTH2_ACCESS_TOKEN", "H2", "IDN_OAUTH2_ACCESS_TOKEN_A"},
                {"IDN_OAUTH2_ACCESS_TOKEN", "AD", "IDN_OAUTH2_ACCESS_TOKEN_B"},
                {"IDN_OAUTH2_ACCESS_TOKEN", "PRIMARY", "IDN_OAUTH2_ACCESS_TOKEN"},
                {"IDN_OAUTH2_ACCESS_TOKEN", "LDAP", "IDN_OAUTH2_ACCESS_TOKEN_LDAP"},
                {"IDN_OAUTH2_ACCESS_TOKEN_SCOPE", "H2", "IDN_OAUTH2_ACCESS_TOKEN_SCOPE_A"},
                {null, "H2", null},
                {"IDN_OAUTH2_ACCESS_TOKEN", null, "IDN_OAUTH2_ACCESS_TOKEN"}
        };
    }

    @Test(dataProvider = "TestGetPartitionedTableByUserStoreDataProvider")
    public void testGetPartitionedTableByUserStore(String tableName, String userstoreDomain, String partionedTableName)
            throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        assertEquals(OAuth2Util.getPartitionedTableByUserStore(tableName, userstoreDomain), partionedTableName);
    }

    @DataProvider(name = "TokenPartitionedSqlByUserStoreData")
    public Object[][] tokenPartitionedSqlByUserStoreData() {
        String sql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE ACCESS_TOKEN = ?";
        String partitionedSql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN_A WHERE ACCESS_TOKEN = ?";
        return new Object[][]{
                // accessTokenPartitioningEnabled
                // assertionsUserNameEnabled
                // sql
                // partitionedSql
                {false, false, sql, sql},
                {true, false, sql, sql},
                {false, true, sql, sql},
                {true, true, sql, partitionedSql}
        };
    }

    @Test(dataProvider = "TokenPartitionedSqlByUserStoreData")
    public void testGetTokenPartitionedSqlByUserStore(boolean accessTokenPartitioningEnabled,
                                                      boolean assertionsUserNameEnabled, String sql,
                                                      String partitionedSql) throws Exception {
        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled()).thenReturn(accessTokenPartitioningEnabled);
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(assertionsUserNameEnabled);
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        assertEquals(OAuth2Util.getTokenPartitionedSqlByUserStore(sql, "H2"), partitionedSql);
    }

    @DataProvider(name = "TokenPartitionedSqlByUserIdData")
    public Object[][] tokenPartitionedSqlByUserIdData() {
        String sql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE ACCESS_TOKEN = ?";
        String partitionedSql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN_A WHERE ACCESS_TOKEN = ?";
        return new Object[][]{
                // accessTokenPartitioningEnabled
                // assertionsUserNameEnabled
                // sql
                // username
                // partitionedSql
                {false, false, sql, null, sql},
                {true, false, sql, "H2/testUser", sql},
                {false, true, sql, null, sql},
                {true, true, sql, "H2/testUser", partitionedSql},
                {true, true, sql, null, sql},

        };
    }

    @Test(dataProvider = "TokenPartitionedSqlByUserIdData")
    public void testGetTokenPartitionedSqlByUserId(boolean accessTokenPartitioningEnabled,
                                                   boolean assertionsUserNameEnabled, String sql,
                                                   String username, String partitionedSql) throws Exception {
        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled()).thenReturn(accessTokenPartitioningEnabled);
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(assertionsUserNameEnabled);
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        assertEquals(OAuth2Util.getTokenPartitionedSqlByUserId(sql, username), partitionedSql);
    }

    @DataProvider(name = "TokenPartitionedSqlByTokenData")
    public Object[][] tokenPartitionedSqlByTokenData() {
        String sql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE ACCESS_TOKEN = ?";
        String partitionedSql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN_A WHERE ACCESS_TOKEN = ?";
        String apiKey = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OkgyL2FkbWlu";

        return new Object[][]{
                // accessTokenPartitioningEnabled
                // assertionsUserNameEnabled
                // isTokenLoggable
                // sql
                // apiKey
                // partitionedSql
                {false, false, true, sql, null, sql},
                {true, false, false, sql, apiKey, sql},
                {false, true, true, sql, null, sql},
                {true, true, false, sql, apiKey, partitionedSql},
                {true, true, true, sql, apiKey, partitionedSql},
        };
    }

    @Test(dataProvider = "TokenPartitionedSqlByTokenData")
    public void testGetTokenPartitionedSqlByToken(boolean accessTokenPartitioningEnabled,
                                                  boolean assertionsUserNameEnabled, boolean isTokenLoggable, String
                                                          sql,
                                                  String apiKey, String partitionedSql) throws Exception {
        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled()).thenReturn(accessTokenPartitioningEnabled);
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(assertionsUserNameEnabled);
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        when(IdentityUtil.isTokenLoggable(anyString())).thenReturn(isTokenLoggable);
        assertEquals(OAuth2Util.getTokenPartitionedSqlByToken(sql, apiKey), partitionedSql);
    }

    @DataProvider(name = "UserStoreDomainFromUserIdData")
    public Object[][] userStoreDomainFromUserIdData() {
        return new Object[][]{
                // userId
                // userStoreDomain
                {"H2/admin", "A"},
                {"admin", null}
        };
    }

    @Test(dataProvider = "UserStoreDomainFromUserIdData")
    public void testGetUserStoreDomainFromUserId(String userId, String userStoreDomain) throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        assertEquals(OAuth2Util.getUserStoreDomainFromUserId(userId), userStoreDomain);
    }

    @DataProvider(name = "UserStoreDomainFromAccessTokenData")
    public Object[][] userStoreDomainFromAccessTokenData() {
        String apiKey1 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OkgyL2FkbWlu";
        String apiKey2 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OmFkbWlu";

        return new Object[][]{
                // apiKey
                // userStoreDomain
                {apiKey1, "H2"},
                {apiKey2, null}
        };
    }

    @Test(dataProvider = "UserStoreDomainFromAccessTokenData")
    public void testGetUserStoreDomainFromAccessToken(String apiKey, String userStoreDomain) throws Exception {
        assertEquals(OAuth2Util.getUserStoreDomainFromAccessToken(apiKey), userStoreDomain);
    }

    @DataProvider(name = "AccessTokenStoreTableFromUserIdData")
    public Object[][] accessTokenStoreTableFromUserIdData() {
        return new Object[][]{
                // userId
                // accessTokenStoreTable
                {"H2/admin", "IDN_OAUTH2_ACCESS_TOKEN_A"},
                {"admin", "IDN_OAUTH2_ACCESS_TOKEN"},
                {null, "IDN_OAUTH2_ACCESS_TOKEN"}
        };
    }

    @Test(dataProvider = "AccessTokenStoreTableFromUserIdData")
    public void testGetAccessTokenStoreTableFromUserId(String userId, String accessTokenStoreTable) throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        assertEquals(OAuth2Util.getAccessTokenStoreTableFromUserId(userId), accessTokenStoreTable);
    }

    @Test
    public void testGetAccessTokenStoreTableFromAccessToken() throws Exception {
        String apiKey = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OmFkbWlu";
        String accessTokenStoreTable = "IDN_OAUTH2_ACCESS_TOKEN";
        assertEquals(OAuth2Util.getAccessTokenStoreTableFromAccessToken(apiKey), accessTokenStoreTable);
    }

    @DataProvider(name = "UserIdFromAccessTokenData")
    public Object[][] userIdFromAccessTokenData() {
        String apiKey1 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OmFkbWlu";
        String apiKey2 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2";

        return new Object[][]{
                // apiKey
                // userId
                {apiKey1, "admin"},
                {apiKey2, null}
        };
    }

    @Test(dataProvider = "UserIdFromAccessTokenData")
    public void testGetUserIdFromAccessToken(String apiKey, String userId) throws Exception {
        assertEquals(OAuth2Util.getUserIdFromAccessToken(apiKey), userId);
    }

    @Test
    public void testGetTokenExpireTimeMillis() throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertTrue(OAuth2Util.getTokenExpireTimeMillis(accessTokenDO) > 1000);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetTokenExpireTimeMillis2() throws Exception {
        OAuth2Util.getTokenExpireTimeMillis(null);
    }

    @Test
    public void testGetRefreshTokenExpireTimeMillis() throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertTrue(OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO) > 1000);
    }

    @Test
    public void testGetRefreshTokenExpireTimeMillis2() throws Exception {
        refreshTokenValidityPeriodInMillis = -100;
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertEquals(OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO), -1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetRefreshTokenExpireTimeMillis3() throws Exception {
        OAuth2Util.getRefreshTokenExpireTimeMillis(null);
    }

    @Test
    public void testGetAccessTokenExpireMillis() throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertTrue(OAuth2Util.getAccessTokenExpireMillis(accessTokenDO) > 1000);
    }

    @DataProvider(name = "BooleanData2")
    public Object[][] booleanData2() {
        return new Object[][]{
                // isTokenLoggable
                {true},
                {false}
        };
    }

    @Test(dataProvider = "BooleanData2")
    public void testGetAccessTokenExpireMillis2(boolean isTokenLoggable) throws Exception {
        validityPeriodInMillis = -100;
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        String accessToken = "dummyAccessToken";
        accessTokenDO.setAccessToken(accessToken);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        when(IdentityUtil.isTokenLoggable(anyString())).thenReturn(isTokenLoggable);
        assertEquals(OAuth2Util.getAccessTokenExpireMillis(accessTokenDO), -1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetAccessTokenExpireMillis3() throws Exception {
        OAuth2Util.getAccessTokenExpireMillis(null);
    }

    @Test
    public void testCalculateValidityInMillis() throws Exception {
        long issuedTimeInMillis = System.currentTimeMillis() - 5000;
        long validityPeriodMillis = 100000;
        assertTrue(OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodMillis) > 0);
    }

    @Test
    public void testGetTenantId() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        assertEquals(OAuth2Util.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                MultitenantConstants.SUPER_TENANT_ID);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTenantId1() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenThrow(new UserStoreException());

        OAuth2Util.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Test
    public void testGetTenantDomain() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        assertEquals(OAuth2Util.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID),
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTenantDomain1() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getDomain(anyInt())).thenThrow(new UserStoreException());

        OAuth2Util.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID);
    }

    @Test
    public void testGetTenantIdFromUserName() throws Exception {
        String userName = "admin" + CarbonConstants.ROLE_TENANT_DOMAIN_SEPARATOR + MultitenantConstants
                .SUPER_TENANT_DOMAIN_NAME;
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        assertEquals(OAuth2Util.getTenantIdFromUserName(userName), MultitenantConstants.SUPER_TENANT_ID);
    }

    @Test
    public void testHashScopes() throws Exception {
        String hashScopes = DigestUtils.md5Hex(scopeString);
        assertEquals(OAuth2Util.hashScopes(scopeArraySorted), hashScopes);
    }

    @DataProvider(name = "ScopesData")
    public Object[][] scopesData() {
        String scope = "testScope";
        String hashScope = DigestUtils.md5Hex(scope);

        return new Object[][]{
                // scope
                // hashScope
                {scope, hashScope},
                {null, null}
        };
    }

    @Test(dataProvider = "ScopesData")
    public void testHashScopes1(String scope, String hashScope) throws Exception {
        assertEquals(OAuth2Util.hashScopes(scope), hashScope);
    }

    @Test
    public void testGetUserFromUserName() throws Exception {
        AuthenticatedUser user = OAuth2Util.getUserFromUserName("H2/testUser");
        assertNotNull(user, "User should be not null.");
        assertEquals(user.getUserName(), "testUser");
        assertEquals(user.getTenantDomain(), MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(user.getUserStoreDomain(), "H2");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetUserFromUserName1() throws Exception {
        OAuth2Util.getUserFromUserName("");
    }

    @DataProvider(name = "IDTokenIssuerData")
    public Object[][] idTokenIssuerData() {
        return new Object[][]{
                // oidcIDTokenIssuer
                // oauth2TokenEPUrl
                // issuer
                {"testIssuer", "", "testIssuer"},
                {"", "testIssuer", "testIssuer"},
                {"", "", "https://localhost:9443/oauth2/token"}
        };
    }

    @Test(dataProvider = "IDTokenIssuerData")
    public void testGetIDTokenIssuer(String oidcIDTokenIssuer, String oauth2TokenEPUrl, String issuer) throws Exception {
        when(oauthServerConfigurationMock.getOpenIDConnectIDTokenIssuerIdentifier()).thenReturn(oidcIDTokenIssuer);
        when(oauthServerConfigurationMock.getOAuth2TokenEPUrl()).thenReturn(oauth2TokenEPUrl);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).
                thenReturn("https://localhost:9443/oauth2/token");

        assertEquals(OAuth2Util.getIDTokenIssuer(), issuer);
    }

    @DataProvider(name = "OAuthURLData")
    public Object[][] oauthURLData() {
        return new Object[][]{
                // configUrl
                // serverUrl
                // oauthUrl
                {"/testUrl", "https://localhost:9443/testUrl", "/testUrl"},
                {"", "https://localhost:9443/testUrl", "https://localhost:9443/testUrl"}
        };
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1RequestTokenUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth1RequestTokenUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth1RequestTokenUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1AuthorizeUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth1AuthorizeUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth1AuthorizeUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1AccessTokenUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth1AccessTokenUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth1AccessTokenUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2AuthzEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth2AuthzEPUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2AuthzEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2TokenEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth2TokenEPUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2TokenEPUrl(), oauthUrl);
    }

    @DataProvider(name = "OAuthURLData2")
    public Object[][] oauthURLData2() {
        return new Object[][]{
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {"/testUrl", "https://localhost:9443/testUrl", "testDomain", "/t/testDomain/testUrl"},
                {"/testUrl", "https://localhost:9443/testUrl", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        "/testUrl"},
                {"", "https://localhost:9443/testUrl", "testDomain", "https://localhost:9443/t/testDomain/testUrl"}
        };
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOAuth2DCREPUrl(String configUrl, String serverUrl, String tenantDomain, String oauthUrl)
            throws Exception {
        when(oauthServerConfigurationMock.getOAuth2DCREPUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2DCREPUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOAuth2JWKSPageUrl(String configUrl, String serverUrl, String tenantDomain, String oauthUrl)
            throws Exception {
        when(oauthServerConfigurationMock.getOAuth2JWKSPageUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOidcWebFingerEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOidcWebFingerEPUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOidcWebFingerEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOidcDiscoveryEPUrl(String configUrl, String serverUrl, String tenantDomain, String oauthUrl)
            throws Exception {
        when(oauthServerConfigurationMock.getOidcDiscoveryUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOidcDiscoveryEPUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2UserInfoEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOauth2UserInfoEPUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2UserInfoEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOIDCConsentPageUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOIDCConsentPageUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOIDCConsentPageUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2ConsentPageUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOauth2ConsentPageUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2ConsentPageUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2ErrorPageUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOauth2ErrorPageUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl(), oauthUrl);
    }

    private void getOAuthURL(String serverUrl) {
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(serverUrl);
    }

    @DataProvider(name = "ScopesSet")
    public Object[][] scopesSet() {
        Set<String> scopesSet1 = new HashSet<>((Arrays.asList(scopeArray)));
        Set<String> scopesSet2 = new HashSet<>((Arrays.asList(scopeArraySorted)));

        return new Object[][]{
                // scopes
                // expected result
                {scopesSet1, true},
                {scopesSet2, false}
        };
    }

    @Test(dataProvider = "ScopesSet")
    public void testIsOIDCAuthzRequest(Set<String> scopes, boolean expectedResult) throws Exception {
        assertEquals(OAuth2Util.isOIDCAuthzRequest(scopes), expectedResult);
    }

    @DataProvider(name = "ScopesArray")
    public Object[][] scopesArray() {
        return new Object[][]{
                // scopes
                // expected result
                {scopeArray, true},
                {scopeArraySorted, false}
        };
    }

    @Test(dataProvider = "ScopesArray")
    public void testIsOIDCAuthzRequest1(String[] scopes, boolean expectedResult) throws Exception {
        assertEquals(OAuth2Util.isOIDCAuthzRequest(scopes), expectedResult);
    }

    @DataProvider(name = "PKCEData")
    public Object[][] pkceData() {
        return new Object[][]{
                // codeVerifierLength
                // expected result
                {42, false},
                {129, false},
                {77, true}
        };
    }

    @Test(dataProvider = "PKCEData")
    public void testValidatePKCECodeVerifier(int codeVerifierLength, boolean expectedResult) throws Exception {
        String codeVerifier = generateCodeVerifier(codeVerifierLength);
        assertEquals(OAuth2Util.validatePKCECodeVerifier(codeVerifier), expectedResult);
    }

    @DataProvider(name = "PKCECodeChallengeData")
    public Object[][] pkceCodeChallengeData() {
        return new Object[][]{
                // codeVerifierLength
                // codeChallengeMethod
                // expected result
                {42, null, false},
                {129, null, false},
                {77, null, true},
                {42, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false},
                {129, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false},
                {77, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, true},
                {77, "testCodeChallengeMethod", false},
                {43, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, true},
                {40, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, false}
        };
    }

    @Test(dataProvider = "PKCECodeChallengeData")
    public void testValidatePKCECodeChallenge(int codeVerifierLength, String codeChallengeMethod,
                                              boolean expectedResult) throws Exception {
        String codeChallenge = generateCodeVerifier(codeVerifierLength);
        assertEquals(OAuth2Util.validatePKCECodeChallenge(codeChallenge, codeChallengeMethod), expectedResult);
    }

    @Test
    public void testIsPKCESupportEnabled() throws Exception {
        assertFalse(OAuth2Util.isPKCESupportEnabled());
    }

    @DataProvider(name = "ImplicitResponseTypeData")
    public Object[][] implicitResponseTypeData() {
        return new Object[][]{
                // responseType
                // expected result
                {"", false},
                {"testResponseType", false},
                {"token", true},
                {"id_token", true}
        };
    }

    @Test(dataProvider = "ImplicitResponseTypeData")
    public void testIsImplicitResponseType(String responseType, boolean expectedResult) throws Exception {
        assertEquals(OAuth2Util.isImplicitResponseType(responseType), expectedResult);
    }

    private String generateCodeVerifier(int codeVerifierLength) {
        StringBuilder codeVerifier = new StringBuilder();
        Random r = new Random();
        String subset = "0123456789abcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < codeVerifierLength; i++) {
            int index = r.nextInt(subset.length());
            char c = subset.charAt(index);
            codeVerifier.append(c);
        }

        return codeVerifier.toString();
    }

    @DataProvider(name="authzUserProvider")
    public Object[][] providerAuthzUser() {
        AuthenticatedUser federatedDomainUser = new AuthenticatedUser();
        federatedDomainUser.setUserStoreDomain("FEDERATED");

        AuthenticatedUser localUser = new AuthenticatedUser();
        localUser.setFederatedUser(false);

        return new Object[][] {
                // Authenticated User, isMapFederatedUserToLocal, expectedIsFederatedValue
                {AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier("DUMMY"), false, true},
                {AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier("DUMMY"), true, false},
                {federatedDomainUser, false, true},
                {federatedDomainUser, true, false},
                {localUser, false, false},
                {localUser, true, false}
        };
    }

    @Test(dataProvider = "authzUserProvider")
    public void testGetAuthenticatedUser(Object authenticatedUser,
                                         boolean mapFederatedUserToLocal,
                                         boolean expectedIsFederatedValue) throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAuthzUser((AuthenticatedUser) authenticatedUser);

        when(oauthServerConfigurationMock.isMapFederatedUsersToLocal()).thenReturn(mapFederatedUserToLocal);

        AuthenticatedUser authzUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);
        assertEquals(authzUser.isFederatedUser(), expectedIsFederatedValue);
    }
}
