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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.TokenMgtUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.util.Date;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit tests for HybridPersistenceTokenProvider.
 */
@WithCarbonHome
public class HybridPersistenceTokenProviderTest {

    private static final String TEST_CONSUMER_KEY = "test_consumer_key";
    private static final String TEST_JTI = "test-jti-12345";
    private static final String TEST_TOKEN_ID = "test-token-id-67890";
    private static final String TEST_ENTITY_ID = "test-entity-id";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_SUBJECT = "testUser";
    private static final int TEST_TENANT_ID = -1234;

    private HybridPersistenceTokenProvider hybridPersistenceTokenProvider;
    private AutoCloseable closeable;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private TenantManager mockTenantManager;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
        hybridPersistenceTokenProvider = new HybridPersistenceTokenProvider();
    }

    @AfterMethod
    public void tearDown() throws Exception {

        if (closeable != null) {
            closeable.close();
        }
    }

    @Test
    public void testGetVerifiedAccessToken_WhenCheckIndirectRevocationTrue_ShouldCallIsTokenRevokedDirectly()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(NonPersistenceConstants.SCOPE, "openid profile")
                .claim(OAuthConstants.AUTHORIZED_USER_TYPE, "APPLICATION_USER")
                .claim(NonPersistenceConstants.GRANT_TYPE, "authorization_code")
                .claim(OAuth2Constants.IS_CONSENTED, "true")
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        mockAuthenticatedUser.setUserStoreDomain("PRIMARY");

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class);
             MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class);
             MockedStatic<OAuthComponentServiceHolder> serviceHolderMockedStatic =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            // Mock JWTUtils.isJWT to return true.
            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            // checkNotBeforeTime is a void method, so we use doNothing()
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            // Mock TokenMgtUtil static methods.
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString())).thenReturn(false);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedIndirectly(any(JWTClaimsSet.class), any(AuthenticatedUser.class)))
                    .thenReturn(false);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenDOFromCache(anyString()))
                    .thenReturn(Optional.empty());
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getScopes(any()))
                    .thenReturn(new String[]{"openid", "profile"});
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenId(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_TOKEN_ID);

            // Mock OAuthComponentServiceHolder for tenant ID resolution.
            OAuthComponentServiceHolder mockServiceHolder =
                    org.mockito.Mockito.mock(OAuthComponentServiceHolder.class);
            serviceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance).thenReturn(mockServiceHolder);
            when(mockServiceHolder.getRealmService()).thenReturn(mockRealmService);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);

            // Mock OAuthCache.
            OAuthCache mockOAuthCache = org.mockito.Mockito.mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            AccessTokenDO result = hybridPersistenceTokenProvider.getVerifiedAccessToken(
                    "dummy.jwt.token", false, true);

            assertNotNull(result);
            assertEquals(result.getAccessToken(), TEST_JTI);
            assertEquals(result.getConsumerKey(), TEST_CONSUMER_KEY);
            assertEquals(result.getTokenState(), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

            // Verify isTokenRevokedDirectly was called since checkIndirectRevocation is true.
            tokenMgtUtilMockedStatic.verify(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(eq(TEST_JTI), eq(TEST_CONSUMER_KEY)));
            tokenMgtUtilMockedStatic.verify(() ->
                    TokenMgtUtil.isTokenRevokedIndirectly(any(JWTClaimsSet.class), any(AuthenticatedUser.class)));
        }
    }

    @Test
    public void testGetVerifiedAccessToken_WhenCheckIndirectRevocationFalse_ShouldNotCallIsTokenRevokedDirectly()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(NonPersistenceConstants.SCOPE, "openid profile")
                .claim(OAuthConstants.AUTHORIZED_USER_TYPE, "APPLICATION_USER")
                .claim(NonPersistenceConstants.GRANT_TYPE, "authorization_code")
                .claim(OAuth2Constants.IS_CONSENTED, "true")
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        mockAuthenticatedUser.setUserStoreDomain("PRIMARY");

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class);
             MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class);
             MockedStatic<OAuthComponentServiceHolder> serviceHolderMockedStatic =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenDOFromCache(anyString()))
                    .thenReturn(Optional.empty());
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getScopes(any()))
                    .thenReturn(new String[]{"openid", "profile"});
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenId(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_TOKEN_ID);

            OAuthComponentServiceHolder mockServiceHolder =
                    org.mockito.Mockito.mock(OAuthComponentServiceHolder.class);
            serviceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance).thenReturn(mockServiceHolder);
            when(mockServiceHolder.getRealmService()).thenReturn(mockRealmService);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);

            OAuthCache mockOAuthCache = org.mockito.Mockito.mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            AccessTokenDO result = hybridPersistenceTokenProvider.getVerifiedAccessToken(
                    "dummy.jwt.token", false, false);

            assertNotNull(result);
            assertEquals(result.getAccessToken(), TEST_JTI);

            // Verify isTokenRevokedDirectly was NOT called since checkIndirectRevocation is false.
            tokenMgtUtilMockedStatic.verify(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString()), never());
            tokenMgtUtilMockedStatic.verify(() ->
                    TokenMgtUtil.isTokenRevokedIndirectly(any(JWTClaimsSet.class), any(AuthenticatedUser.class)),
                    never());
        }
    }

    @Test
    public void testGetVerifiedAccessToken_WhenTokenRevokedDirectly_AndIncludeExpiredTrue_ShouldReturnNull()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class)) {

            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            // Token is directly revoked.
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString())).thenReturn(true);

            AccessTokenDO result = hybridPersistenceTokenProvider.getVerifiedAccessToken(
                    "dummy.jwt.token", true, true);

            // When includeExpired is true and token is revoked, should return null.
            assertNull(result);
            tokenMgtUtilMockedStatic.verify(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(eq(TEST_JTI), eq(TEST_CONSUMER_KEY)));
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetVerifiedAccessToken_WhenTokenRevokedDirectly_AndIncludeExpiredFalse_ShouldThrow()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class)) {

            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            // Token is directly revoked.
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString())).thenReturn(true);

            // When includeExpired is false and token is revoked, should throw IllegalArgumentException.
            hybridPersistenceTokenProvider.getVerifiedAccessToken("dummy.jwt.token", false, true);
        }
    }

    @Test
    public void testGetVerifiedAccessToken_TwoArgOverload_DelegatesToThreeArgWithCheckRevocationTrue()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(NonPersistenceConstants.SCOPE, "openid")
                .claim(OAuthConstants.AUTHORIZED_USER_TYPE, "APPLICATION_USER")
                .claim(NonPersistenceConstants.GRANT_TYPE, "authorization_code")
                .claim(OAuth2Constants.IS_CONSENTED, "true")
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        mockAuthenticatedUser.setUserStoreDomain("PRIMARY");

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class);
             MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class);
             MockedStatic<OAuthComponentServiceHolder> serviceHolderMockedStatic =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString())).thenReturn(false);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedIndirectly(any(JWTClaimsSet.class), any(AuthenticatedUser.class)))
                    .thenReturn(false);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenDOFromCache(anyString()))
                    .thenReturn(Optional.empty());
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getScopes(any()))
                    .thenReturn(new String[]{"openid"});
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenId(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_TOKEN_ID);

            OAuthComponentServiceHolder mockServiceHolder =
                    org.mockito.Mockito.mock(OAuthComponentServiceHolder.class);
            serviceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance).thenReturn(mockServiceHolder);
            when(mockServiceHolder.getRealmService()).thenReturn(mockRealmService);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);

            OAuthCache mockOAuthCache = org.mockito.Mockito.mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            // Two-arg overload should delegate with checkIndirectRevocation=true.
            AccessTokenDO result = hybridPersistenceTokenProvider.getVerifiedAccessToken(
                    "dummy.jwt.token", false);

            assertNotNull(result);

            // Verify revocation checks were called (proving checkIndirectRevocation=true was passed).
            tokenMgtUtilMockedStatic.verify(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(eq(TEST_JTI), eq(TEST_CONSUMER_KEY)));
        }
    }

    @Test
    public void testGetVerifiedAccessToken_WhenTokenExpired_AndIncludeExpiredTrue_ShouldReturnWithExpiredState()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(NonPersistenceConstants.SCOPE, "openid")
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        mockAuthenticatedUser.setUserStoreDomain("PRIMARY");

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class);
             MockedStatic<OAuthCache> oAuthCacheMockedStatic = mockStatic(OAuthCache.class);
             MockedStatic<OAuthComponentServiceHolder> serviceHolderMockedStatic =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            // Token is expired.
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(false);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString())).thenReturn(false);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedIndirectly(any(JWTClaimsSet.class), any(AuthenticatedUser.class)))
                    .thenReturn(false);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenDOFromCache(anyString()))
                    .thenReturn(Optional.empty());
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getScopes(any()))
                    .thenReturn(new String[]{"openid"});
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenId(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_TOKEN_ID);

            OAuthComponentServiceHolder mockServiceHolder =
                    org.mockito.Mockito.mock(OAuthComponentServiceHolder.class);
            serviceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance).thenReturn(mockServiceHolder);
            when(mockServiceHolder.getRealmService()).thenReturn(mockRealmService);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);

            OAuthCache mockOAuthCache = org.mockito.Mockito.mock(OAuthCache.class);
            oAuthCacheMockedStatic.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            AccessTokenDO result = hybridPersistenceTokenProvider.getVerifiedAccessToken(
                    "dummy.jwt.token", true, true);

            assertNotNull(result);
            assertEquals(result.getTokenState(), OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        }
    }

    @Test
    public void testGetVerifiedAccessToken_WhenCacheHit_ShouldReturnCachedToken()
            throws Exception {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(TEST_JTI)
                .subject(TEST_SUBJECT)
                .issueTime(now)
                .expirationTime(expiry)
                .notBeforeTime(now)
                .claim(NonPersistenceConstants.AUTHORIZATION_PARTY, TEST_CONSUMER_KEY)
                .claim(NonPersistenceConstants.ENTITY_ID, TEST_ENTITY_ID)
                .claim(NonPersistenceConstants.ENTITY_TYPE, NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME)
                .claim(OAuth2Constants.TOKEN_ID, TEST_TOKEN_ID)
                .build();

        SignedJWT mockSignedJWT = org.mockito.Mockito.mock(SignedJWT.class);
        AuthenticatedUser mockAuthenticatedUser = new AuthenticatedUser();
        mockAuthenticatedUser.setUserName("testUser");
        mockAuthenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);

        AccessTokenDO cachedToken = new AccessTokenDO();
        cachedToken.setAccessToken(TEST_JTI);
        cachedToken.setConsumerKey(TEST_CONSUMER_KEY);
        cachedToken.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        try (MockedStatic<JWTUtils> jwtUtilsMockedStatic = mockStatic(JWTUtils.class);
             MockedStatic<TokenMgtUtil> tokenMgtUtilMockedStatic = mockStatic(TokenMgtUtil.class)) {

            jwtUtilsMockedStatic.when(() -> JWTUtils.isJWT(anyString())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            jwtUtilsMockedStatic.when(() -> JWTUtils.checkNotBeforeTime(any())).then(invocation -> null);

            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.parseJWT(anyString())).thenReturn(mockSignedJWT);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenJWTClaims(any(SignedJWT.class)))
                    .thenReturn(claimsSet);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenIdentifier(any(JWTClaimsSet.class)))
                    .thenReturn(TEST_JTI);
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getAuthenticatedUser(any(JWTClaimsSet.class)))
                    .thenReturn(mockAuthenticatedUser);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.validateJWTSignature(any(SignedJWT.class), any(JWTClaimsSet.class),
                            any(AuthenticatedUser.class))).thenAnswer(invocation -> null);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedDirectly(anyString(), anyString())).thenReturn(false);
            tokenMgtUtilMockedStatic.when(() ->
                    TokenMgtUtil.isTokenRevokedIndirectly(any(JWTClaimsSet.class), any(AuthenticatedUser.class)))
                    .thenReturn(false);
            // Cache hit.
            tokenMgtUtilMockedStatic.when(() -> TokenMgtUtil.getTokenDOFromCache(anyString()))
                    .thenReturn(Optional.of(cachedToken));

            AccessTokenDO result = hybridPersistenceTokenProvider.getVerifiedAccessToken(
                    "dummy.jwt.token", false, true);

            assertNotNull(result);
            assertEquals(result.getAccessToken(), TEST_JTI);
            assertEquals(result.getConsumerKey(), TEST_CONSUMER_KEY);
        }
    }
}
