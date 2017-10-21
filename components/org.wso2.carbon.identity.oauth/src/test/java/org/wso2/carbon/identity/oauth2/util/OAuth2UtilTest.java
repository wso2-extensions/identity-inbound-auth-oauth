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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.sql.Timestamp;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest({OAuthServerConfiguration.class, OAuthCache.class, IdentityUtil.class, OAuthConsumerDAO.class,
        OAuth2Util.class})
public class OAuth2UtilTest extends PowerMockIdentityBaseTest {

    private String scopeArr[] = new String[]{"scope1", "scope2", "scope3"};
    private String scopeStr = "scope1 scope2 scope3";
    private String clientId = "dummyClientId";
    private String clientSecret = "dummyClientSecret";
    private AuthenticatedUser authzUser = new AuthenticatedUser();
    private Timestamp issuedTime = new Timestamp(System.currentTimeMillis());
    private Timestamp refreshTokenIssuedTime = new Timestamp(System.currentTimeMillis());
    private Integer clientTenantId = 1;

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

    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        long timestampSkew = 3600L;
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(timestampSkew);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @DataProvider(name = "TestGetPartitionedTableByUserStoreDataProvider")
    public Object[][] getPartitionedTableByUserStoreData() {
        return new Object[][]{
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
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2,B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        assertEquals(OAuth2Util.getPartitionedTableByUserStore(tableName, userstoreDomain), partionedTableName);
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
    public void testGetClientTenantId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenantId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenantId.intValue());
    }

    @Test
    public void testSetClientTenantId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenantId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenantId.intValue());
    }

    @Test
    public void testClearClientTenantId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenantId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenantId.intValue());
        OAuth2Util.clearClientTenantId();
        assertEquals(OAuth2Util.getClientTenatId(), -1);
    }

    @DataProvider(name = "BuildScopeString")
    public Object[][] buildScopeString() {
        return new Object[][]{
                {scopeArr, scopeStr},
                {null, null},
                {new String[0], ""}
        };
    }

    @Test(dataProvider = "BuildScopeString")
    public void testBuildScopeString(String arr[], String response) throws Exception {
        assertEquals(OAuth2Util.buildScopeString(arr), response);
    }

    @DataProvider(name = "BuildScopeArray")
    public Object[][] buildScopeArray() {
        return new Object[][]{
                {scopeStr, scopeArr},
                {null, new String[0]}
        };
    }

    @Test(dataProvider = "BuildScopeArray")
    public void testBuildScopeArray(String scopes, String response[]) throws Exception {
        assertEquals(OAuth2Util.buildScopeArray(scopes), response);
    }

    @DataProvider(name = "AuthenticateClient")
    public Object[][] authenticateClient() {
        CacheEntry cacheResult1 = cacheEntryMock;
        CacheEntry cacheResult2 = new ClientCredentialDO(null);
        CacheEntry cacheResult3 = new ClientCredentialDO(clientSecret);
        CacheEntry cacheResult4 = new ClientCredentialDO("7_EsdLmABh_cPdmmYxCTwRdyDG6c");

        return new Object[][]{
                {null, null, false},
                {null, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {null, clientSecret, true},
                {cacheResult1, null, false},
                {cacheResult1, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult1, clientSecret, true},
                {cacheResult2, null, false},
                {cacheResult2, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult2, clientSecret, true},
                {cacheResult3, null, true},
                {cacheResult3, "4_EedLmABh_cPdmmYxCTwRdyDG5b", true},
                {cacheResult3, clientSecret, true},
                {cacheResult4, null, false},
                {cacheResult4, "4_EedLmABh_cPdmmYxCTwRdyDG5b", false},
                {cacheResult4, clientSecret, false}
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

        String tokenType = "testTokenType";
        long validityPeriodInMillis = 3600000L;
        long refreshTokenValidityPeriodInMillis = 3600000L;
        String authorizationCode = "dummyCode";
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArr, issuedTime,
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
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn
                ("testAccessTokenPartitioningDomains");
        assertEquals(OAuth2Util.getAccessTokenPartitioningDomains(), "testAccessTokenPartitioningDomains");
    }
}
