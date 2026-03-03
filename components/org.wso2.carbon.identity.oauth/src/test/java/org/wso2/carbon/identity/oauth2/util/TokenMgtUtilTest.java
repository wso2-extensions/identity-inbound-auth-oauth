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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RevokedTokenPersistenceDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for TokenMgtUtil static methods.
 */
@WithCarbonHome
public class TokenMgtUtilTest {

    private static final String TEST_CONSUMER_KEY = "test_consumer_key";
    private static final String TEST_JTI = "test-jti-12345";
    private static final String TEST_TOKEN_ID = "test-token-id-67890";
    private static final String TEST_ENTITY_ID = "test-entity-id";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";

    private AutoCloseable closeable;

    @Mock
    private OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory;

    @Mock
    private RevokedTokenPersistenceDAO mockRevokedTokenPersistenceDAO;

    private MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactoryMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        closeMockSafely(oAuthTokenPersistenceFactoryMockedStatic);
        if (closeable != null) {
            closeable.close();
        }
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

    // ======================== isHybridPersistedToken ========================

    @DataProvider(name = "hybridPersistedTokenData")
    public Object[][] hybridPersistedTokenData() {

        return new Object[][]{
                {"npr_abc123", true},
                {"npr_", true},
                {"regular_token", false},
                {"", false},
                {null, false},
                {"   ", false},
                {"NPR_uppercase", false},
        };
    }

    @Test(dataProvider = "hybridPersistedTokenData")
    public void testIsHybridPersistedToken(String refreshToken, boolean expected) {

        assertEquals(TokenMgtUtil.isHybridPersistedToken(refreshToken), expected);
    }

    // ======================== getTokenIdentifier ========================

    @Test
    public void testGetTokenIdentifier_WithValidJTI() throws IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .build();

        String result = TokenMgtUtil.getTokenIdentifier(claimsSet);
        assertEquals(result, TEST_JTI);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "JTI could not be retrieved from the JWT token.")
    public void testGetTokenIdentifier_WithNullJTI_ShouldThrow() throws IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        TokenMgtUtil.getTokenIdentifier(claimsSet);
    }

    // ======================== getTokenJWTClaims ========================

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Error while parsing token.")
    public void testParseJWT_WithInvalidToken_ShouldThrow() throws IdentityOAuth2Exception {

        TokenMgtUtil.parseJWT("not-a-jwt-token");
    }

    // ======================== getScopes ========================

    @Test
    public void testGetScopes() {

        String[] result = TokenMgtUtil.getScopes("openid profile email");
        assertEquals(result.length, 3);
        assertEquals(result[0], "openid");
        assertEquals(result[1], "profile");
        assertEquals(result[2], "email");

        result = TokenMgtUtil.getScopes("openid");
        assertEquals(result.length, 1);
        assertEquals(result[0], "openid");

        result = TokenMgtUtil.getScopes(Integer.valueOf(123));
        assertEquals(result.length, 0);

        result = TokenMgtUtil.getScopes(null);
        assertEquals(result.length, 0);
    }

    // ======================== getTenantDomain ========================

    @Test
    public void testGetTenantDomain_WithTenantDomainInContext() {

        try (MockedStatic<PrivilegedCarbonContext> carbonContextMockedStatic =
                     mockStatic(PrivilegedCarbonContext.class)) {
            PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
            carbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(mockCarbonContext);
            when(mockCarbonContext.getTenantDomain()).thenReturn("wso2.com");

            String result = TokenMgtUtil.getTenantDomain();
            assertEquals(result, "wso2.com");
        }
    }

    @Test
    public void testGetTenantDomain_WithEmptyTenantDomain_ShouldReturnSuperTenant() {

        try (MockedStatic<PrivilegedCarbonContext> carbonContextMockedStatic =
                     mockStatic(PrivilegedCarbonContext.class)) {
            PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
            carbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(mockCarbonContext);
            when(mockCarbonContext.getTenantDomain()).thenReturn("");

            String result = TokenMgtUtil.getTenantDomain();
            assertEquals(result, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
    }

    @Test
    public void testGetTenantDomain_WithNullTenantDomain_ShouldReturnSuperTenant() {

        try (MockedStatic<PrivilegedCarbonContext> carbonContextMockedStatic =
                     mockStatic(PrivilegedCarbonContext.class)) {
            PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
            carbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(mockCarbonContext);
            when(mockCarbonContext.getTenantDomain()).thenReturn(null);

            String result = TokenMgtUtil.getTenantDomain();
            assertEquals(result, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
    }

    // ======================== getTokenId ========================

    @Test
    public void testGetTokenId_WithValidTokenId() throws IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        String result = TokenMgtUtil.getTokenId(claimsSet);
        assertEquals(result, TEST_TOKEN_ID);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "TokenId could not be retrieved from the JWT token.")
    public void testGetTokenId_WithNullTokenId_ShouldThrow() throws IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        TokenMgtUtil.getTokenId(claimsSet);
    }

    // ======================== isTokenRevokedDirectly ========================

    @Test
    public void testIsTokenRevokedDirectly_WhenTokenIsRevoked() throws IdentityOAuth2Exception {

        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);
        when(mockRevokedTokenPersistenceDAO.isRevokedToken("token123", TEST_CONSUMER_KEY)).thenReturn(true);

        boolean result = TokenMgtUtil.isTokenRevokedDirectly("token123", TEST_CONSUMER_KEY);
        assertTrue(result);
        verify(mockRevokedTokenPersistenceDAO).isRevokedToken("token123", TEST_CONSUMER_KEY);
    }

    @Test
    public void testIsTokenRevokedDirectly_WhenTokenIsNotRevoked() throws IdentityOAuth2Exception {

        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);
        when(mockRevokedTokenPersistenceDAO.isRevokedToken("token123", TEST_CONSUMER_KEY)).thenReturn(false);

        boolean result = TokenMgtUtil.isTokenRevokedDirectly("token123", TEST_CONSUMER_KEY);
        assertFalse(result);
    }

    // ======================== isTokenRevokedIndirectly ========================

    @Test
    public void testIsTokenRevokedIndirectly_WhenConsumerKeyIsRevoked() throws IdentityOAuth2Exception {

        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);

        Date issuedTime = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .issueTime(issuedTime)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.SCOPE, "openid profile")
                .build();

        when(mockRevokedTokenPersistenceDAO.isTokenRevokedForSubjectEntity(eq(TEST_CONSUMER_KEY), any(Date.class)))
                .thenReturn(true);

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class);
             MockedStatic<OAuthUtil> oAuthUtilMockedStatic = mockStatic(OAuthUtil.class);
             MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class)) {

            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.buildScopeString(any(String[].class)))
                    .thenReturn("openid profile");

            boolean result = TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, null);
            assertTrue(result);
        }
    }

    @Test
    public void testIsTokenRevokedIndirectly_WhenEntityIdIsRevoked() throws IdentityOAuth2Exception {

        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);

        Date issuedTime = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .issueTime(issuedTime)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.SCOPE, "openid")
                .build();

        // Consumer key check returns false, entity id check returns true.
        when(mockRevokedTokenPersistenceDAO.isTokenRevokedForSubjectEntity(eq(TEST_CONSUMER_KEY), any(Date.class)))
                .thenReturn(false);
        when(mockRevokedTokenPersistenceDAO.isTokenRevokedForSubjectEntity(eq(TEST_ENTITY_ID), any(Date.class)))
                .thenReturn(true);

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class);
             MockedStatic<OAuthUtil> oAuthUtilMockedStatic = mockStatic(OAuthUtil.class);
             MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class)) {

            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.buildScopeString(any(String[].class)))
                    .thenReturn("openid");

            boolean result = TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, null);
            assertTrue(result);

            // Verify both checks were made.
            verify(mockRevokedTokenPersistenceDAO)
                    .isTokenRevokedForSubjectEntity(eq(TEST_CONSUMER_KEY), any(Date.class));
            verify(mockRevokedTokenPersistenceDAO)
                    .isTokenRevokedForSubjectEntity(eq(TEST_ENTITY_ID), any(Date.class));
        }
    }

    @Test
    public void testIsTokenRevokedIndirectly_WhenNotRevoked() throws IdentityOAuth2Exception {

        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);

        Date issuedTime = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .issueTime(issuedTime)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .build();

        when(mockRevokedTokenPersistenceDAO.isTokenRevokedForSubjectEntity(anyString(), any(Date.class)))
                .thenReturn(false);

        boolean result = TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, null);
        assertFalse(result);
    }

    @Test
    public void testIsTokenRevokedIndirectly_WhenConsumerKeyEqualsEntityId_ShouldCheckOnce()
            throws IdentityOAuth2Exception {

        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);

        // When consumerKey == entityId, only one check should be made.
        Date issuedTime = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .issueTime(issuedTime)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .build();

        when(mockRevokedTokenPersistenceDAO.isTokenRevokedForSubjectEntity(eq(TEST_CONSUMER_KEY), any(Date.class)))
                .thenReturn(false);

        boolean result = TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, null);
        assertFalse(result);

        // Should only be called once since consumerKey equals entityId.
        verify(mockRevokedTokenPersistenceDAO)
                .isTokenRevokedForSubjectEntity(eq(TEST_CONSUMER_KEY), any(Date.class));
    }

    // ======================== getTokenDOFromCache ========================

    @Test
    public void testGetTokenDOFromCache_WhenCacheHit() {

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class)) {
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            when(mockOAuthCache.isEnabled()).thenReturn(true);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken("cached-token");
            when(mockOAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);

            assertTrue(TokenMgtUtil.getTokenDOFromCache("test-id").isPresent());
            assertEquals(TokenMgtUtil.getTokenDOFromCache("test-id").get().getAccessToken(), "cached-token");
        }
    }

    @Test
    public void testGetTokenDOFromCache_WhenCacheMiss() {

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class)) {
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            when(mockOAuthCache.isEnabled()).thenReturn(true);
            when(mockOAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(null);

            assertFalse(TokenMgtUtil.getTokenDOFromCache("test-id").isPresent());
        }
    }

    @Test
    public void testGetTokenDOFromCache_WhenCacheDisabled() {

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class)) {
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            when(mockOAuthCache.isEnabled()).thenReturn(false);

            assertFalse(TokenMgtUtil.getTokenDOFromCache("test-id").isPresent());
            verify(mockOAuthCache, never()).getValueFromCache(any(OAuthCacheKey.class));
        }
    }

    // ======================== addTokenToCache ========================

    @Test
    public void testAddTokenToCache_WhenCacheEnabled() {

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class)) {
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            when(mockOAuthCache.isEnabled()).thenReturn(true);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            TokenMgtUtil.addTokenToCache("test-id", accessTokenDO);

            verify(mockOAuthCache).addToCache(any(OAuthCacheKey.class), eq(accessTokenDO));
        }
    }

    @Test
    public void testAddTokenToCache_WhenCacheDisabled() {

        try (MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class)) {
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);
            when(mockOAuthCache.isEnabled()).thenReturn(false);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            TokenMgtUtil.addTokenToCache("test-id", accessTokenDO);

            verify(mockOAuthCache, never()).addToCache(any(OAuthCacheKey.class), any(AccessTokenDO.class));
        }
    }

    @Test
    public void testIsNonPersistenceAccessToken_WithNonJWTToken() {

        assertFalse(TokenMgtUtil.isNonPersistenceAccessToken("plain-opaque-token"));
        assertFalse(TokenMgtUtil.isNonPersistenceAccessToken(null));
    }
}
