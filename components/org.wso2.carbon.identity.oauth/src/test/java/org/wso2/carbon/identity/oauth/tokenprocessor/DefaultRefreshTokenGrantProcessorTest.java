/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
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

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.RefreshTokenCache;
import org.wso2.carbon.identity.oauth.cache.RefreshTokenCacheEntry;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.GracefulRefreshTokenRotation;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Unit tests for {@link DefaultRefreshTokenGrantProcessor}, focused on the graceful
 * refresh token rotation paths introduced in the feature branch.
 */
@WithCarbonHome
public class DefaultRefreshTokenGrantProcessorTest {

    private static final String CLIENT_ID = "test_client_id";
    private static final String REFRESH_TOKEN = "test_refresh_token";
    private static final String OLD_TOKEN_ID = "old_token_id";
    private static final String OLD_ACCESS_TOKEN = "old_access_token";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String USER_STORE_DOMAIN = "PRIMARY";

    private DefaultRefreshTokenGrantProcessor processor;
    private AutoCloseable closeable;

    @Mock private OAuthAppDO mockOAuthAppDO;
    @Mock private OAuthTokenPersistenceFactory mockPersistenceFactory;
    @Mock private AccessTokenDAO mockAccessTokenDAO;
    @Mock private TokenManagementDAO mockTokenManagementDAO;
    @Mock private RefreshTokenCache mockReuseCountCache;
    @Mock private AuthorizationGrantCache mockAuthGrantCache;
    @Mock private AuthorizationGrantCacheEntry mockGrantCacheEntry;
    @Mock private OAuthServerConfiguration mockServerConfig;
    @Mock private AuthenticatedUser mockAuthzUser;

    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<OAuthTokenPersistenceFactory> persistenceFactoryMockedStatic;
    private MockedStatic<OAuthServerConfiguration> serverConfigMockedStatic;
    private MockedStatic<OIDCClaimUtil> oidcClaimUtilMockedStatic;
    private MockedStatic<RefreshTokenCache> reuseCountCacheMockedStatic;
    private MockedStatic<AuthorizationGrantCache> authGrantCacheMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<IdentityUtil> identityUtilMockedStatic;
    private MockedStatic<OAuth2ServiceComponentHolder> serviceComponentHolderMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);

        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        persistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        serverConfigMockedStatic = mockStatic(OAuthServerConfiguration.class);
        oidcClaimUtilMockedStatic = mockStatic(OIDCClaimUtil.class);
        reuseCountCacheMockedStatic = mockStatic(RefreshTokenCache.class);
        authGrantCacheMockedStatic = mockStatic(AuthorizationGrantCache.class);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityUtilMockedStatic = mockStatic(IdentityUtil.class);
        serviceComponentHolderMockedStatic = mockStatic(OAuth2ServiceComponentHolder.class);

        persistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockPersistenceFactory);
        when(mockPersistenceFactory.getAccessTokenDAOImpl(anyString())).thenReturn(mockAccessTokenDAO);
        when(mockPersistenceFactory.getTokenManagementDAO()).thenReturn(mockTokenManagementDAO);

        serverConfigMockedStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
        lenient().when(mockServerConfig.isRefreshTokenRenewalEnabled()).thenReturn(true);

        reuseCountCacheMockedStatic.when(RefreshTokenCache::getInstance)
                .thenReturn(mockReuseCountCache);
        authGrantCacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockAuthGrantCache);

        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(TENANT_ID);
        identityUtilMockedStatic.when(() -> IdentityUtil.isTokenLoggable(anyString())).thenReturn(false);

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.buildScopeString(any())).thenReturn("openid profile");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                .thenReturn(mockOAuthAppDO);

        serviceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::isConsentedTokenColumnEnabled)
                .thenReturn(true);
        serviceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::isTokenExtendedTableExist)
                .thenReturn(true);

        processor = new DefaultRefreshTokenGrantProcessor();
    }

    @AfterMethod
    public void tearDown() throws Exception {

        oAuth2UtilMockedStatic.close();
        persistenceFactoryMockedStatic.close();
        serverConfigMockedStatic.close();
        oidcClaimUtilMockedStatic.close();
        reuseCountCacheMockedStatic.close();
        authGrantCacheMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        identityUtilMockedStatic.close();
        serviceComponentHolderMockedStatic.close();
        closeable.close();
    }

    // -----------------------------------------------------------------------
    // validateRefreshToken / validateReuseRefreshToken
    // -----------------------------------------------------------------------

    @Test
    public void testValidateRefreshToken_gracefulDisabled_noStateFlipNoException() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(false);

        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, null,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN);
        RefreshTokenValidationDataDO result = processor.validateRefreshToken(ctx);

        assertEquals(result.getRefreshTokenState(),
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED,
                "State should remain GRACEFULLY_ROTATED when graceful rotation is disabled");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateRefreshToken_invalidOAuthClientExceptionIsWrapped() throws Exception {

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                .thenThrow(new InvalidOAuthClientException("not found"));

        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, null,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
    }

    @Test
    public void testValidateRefreshToken_gracefulRotated_stateFlippedToActive() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);

        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, null,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));

        assertEquals(validationBean.getRefreshTokenState(),
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                "GRACEFULLY_ROTATED state should be flipped to ACTIVE in-memory");
    }

    @Test
    public void testValidateRefreshToken_alreadyActive_stateUnchanged() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);

        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, null,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));

        assertEquals(validationBean.getRefreshTokenState(), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*grace period has expired.*")
    public void testValidateRefreshToken_unparseableGraceValidity_rejectsRequest() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS, "not-a-number");
        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, attrs,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*grace period has expired.*")
    public void testValidateRefreshToken_graceWindowExpired_rejectsRequest() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS, "30000");
        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, attrs,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        // Returning a negative TTL simulates expiry.
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getTimeToExpire(anyLong(), anyLong(), eq(true)))
                .thenReturn(-1L);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
    }

    @Test
    public void testValidateRefreshToken_graceWindowStillOpen_passes() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS, "60000");
        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, attrs,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getTimeToExpire(anyLong(), anyLong(), eq(true)))
                .thenReturn(30000L);

        // Should not throw.
        RefreshTokenValidationDataDO result =
                processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
        assertNotNull(result);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*graceful reuse limit.*")
    public void testValidateRefreshToken_reuseCountAtLimit_rejectsRequest() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(2);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "2");
        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, attrs,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
    }

    @Test
    public void testValidateRefreshToken_reuseCountBelowLimit_passes() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "1");
        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, attrs,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        RefreshTokenValidationDataDO result =
                processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
        assertNotNull(result);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*grace period has expired.*")
    public void testValidateRefreshToken_unparseableReuseCount_rejectsRequest() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(1);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "abc");
        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, attrs,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));
    }

    @Test
    public void testValidateRefreshToken_nullExtendedAttrs_stateFlipOnlyNoException() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);

        RefreshTokenValidationDataDO validationBean = refreshTokenBean(
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED, null,
                new Timestamp(System.currentTimeMillis()));
        validationBean.setAccessToken(OLD_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(CLIENT_ID, REFRESH_TOKEN)).thenReturn(validationBean);

        processor.validateRefreshToken(buildTokenReqContext(CLIENT_ID, REFRESH_TOKEN, TENANT_DOMAIN));

        assertEquals(validationBean.getRefreshTokenState(), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
    }

    // -----------------------------------------------------------------------
    // persistNewToken
    // -----------------------------------------------------------------------

    @Test
    public void testPersistNewToken_nonGracefulPath_callsInvalidateAndCreate() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(false);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        verify(mockAccessTokenDAO).invalidateAndCreateNewAccessToken(
                eq(OLD_TOKEN_ID),
                eq(OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE),
                eq(CLIENT_ID),
                anyString(),
                eq(newToken),
                eq(USER_STORE_DOMAIN),
                anyString());
        verify(mockAccessTokenDAO, never()).gracefullyRotateAndCreateNewAccessToken(
                anyString(), any(), anyString(), anyString(), anyString(), any(), anyString(), anyString(), any());
    }

    @Test
    public void testPersistNewToken_gracefulFirstRotation_stampsGraceDeadlineAndNewState() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(3);
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        // Cache miss → DB also returns null (first-ever rotation).
        when(mockReuseCountCache.getValueFromCache(any(), anyInt())).thenReturn(null);
        when(mockAccessTokenDAO.getAccessTokenExtendedAttributeValue(anyString(), anyString(), anyString()))
                .thenReturn(null);

        // No predecessor in the attributes table (fresh first rotation).
        when(mockAccessTokenDAO.getActiveTokenByExtendedAttribute(anyString(), anyString(), anyString()))
                .thenReturn(null);

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> mapCaptor = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<String> newStateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> newStateIdCaptor = ArgumentCaptor.forClass(String.class);

        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                eq(OLD_TOKEN_ID),
                any(Timestamp.class),
                newStateIdCaptor.capture(),
                newStateCaptor.capture(),
                eq(CLIENT_ID),
                eq(newToken),
                eq(USER_STORE_DOMAIN),
                anyString(),
                mapCaptor.capture());

        Map<String, String> updates = mapCaptor.getValue();
        assertTrue(updates.containsKey(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS),
                "First rotation must stamp grace deadline");
        assertTrue(!updates.containsKey(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT),
                "First rotation must NOT stamp reuse count");
        assertEquals(newStateCaptor.getValue(),
                OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED);
        assertNotNull(newStateIdCaptor.getValue());
    }

    @Test
    public void testPersistNewToken_gracefulSubsequentReuse_incrementsCountSkipsStateStamp() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        // Cache hit: persisted reuse count is 1.
        when(mockReuseCountCache.getValueFromCache(any(), anyInt()))
                .thenReturn(new RefreshTokenCacheEntry(1));

        // Old token has a successorTokenId → this is a reuse (Case A).
        String successorId = "successor_token_id";
        Map<String, String> reuseAttrs = new HashMap<>();
        reuseAttrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "1");
        reuseAttrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID, successorId);
        when(mockAccessTokenDAO.getAccessTokenByTokenId(eq(successorId)))
                .thenReturn("successor_access_token");

        RefreshTokenValidationDataDO oldToken = oldTokenDO(reuseAttrs);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> mapCaptor = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<String> newStateCaptor = ArgumentCaptor.forClass(String.class);

        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                eq(OLD_TOKEN_ID),
                any(Timestamp.class),
                any(),
                newStateCaptor.capture(),
                eq(CLIENT_ID),
                eq(newToken),
                eq(USER_STORE_DOMAIN),
                anyString(),
                mapCaptor.capture());

        Map<String, String> updates = mapCaptor.getValue();
        assertEquals(updates.get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT), "2",
                "Reuse count should be incremented to 2 (was 1, isRefreshTokenReuse=true)");
        assertTrue(!updates.containsKey(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS),
                "Subsequent reuse must NOT re-stamp grace deadline");
        assertNull(newStateCaptor.getValue(),
                "State stamp should be null for subsequent reuses");
    }

    @Test
    public void testPersistNewToken_cachedCountAtLimit_rejectsBeforeDbCall() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(3);

        when(mockReuseCountCache.getValueFromCache(any(), anyInt()))
                .thenReturn(new RefreshTokenCacheEntry(3));

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        try {
            processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);
            fail("Expected IdentityOAuth2Exception to be thrown");
        } catch (IdentityOAuth2Exception ex) {
            assertTrue(ex.getMessage().matches(".*graceful reuse limit.*"),
                    "Exception message must mention 'graceful reuse limit'");
        }
        verify(mockAccessTokenDAO, never()).gracefullyRotateAndCreateNewAccessToken(
                anyString(), any(), anyString(), anyString(), anyString(), any(), anyString(), anyString(), any());
    }

    @Test
    public void testPersistNewToken_cacheMissFallsBackToDbAndPrimesCache() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        // Cache miss, DB returns "1".
        when(mockReuseCountCache.getValueFromCache(any(), anyInt())).thenReturn(null);
        when(mockAccessTokenDAO.getAccessTokenExtendedAttributeValue(
                eq(OLD_TOKEN_ID),
                eq(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT),
                anyString()))
                .thenReturn("1");

        when(mockAccessTokenDAO.getActiveTokenByExtendedAttribute(anyString(), anyString(), anyString()))
                .thenReturn(null);

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        // DB read must prime the cache.
        verify(mockReuseCountCache).addToCacheOnRead(any(), any(), eq(TENANT_ID));
        // Write-through after successful rotation.
        verify(mockReuseCountCache).addToCache(any(), any(), eq(TENANT_ID));
    }

    @Test
    public void testPersistNewToken_caseB_predecessorRevoked() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        when(mockReuseCountCache.getValueFromCache(any(), anyInt())).thenReturn(null);
        when(mockAccessTokenDAO.getAccessTokenExtendedAttributeValue(anyString(), anyString(), anyString()))
                .thenReturn(null);

        // No successorTokenId on old token (Case B: fresh); predecessor found via JOIN.
        AccessTokenDO predecessor = buildSibling("predecessor_id", "predecessor_access_token");
        when(mockAccessTokenDAO.getActiveTokenByExtendedAttribute(
                eq(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID),
                eq(OLD_TOKEN_ID), anyString()))
                .thenReturn(predecessor);

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        ArgumentCaptor<String[]> revokeCaptor = ArgumentCaptor.forClass(String[].class);
        verify(mockAccessTokenDAO).revokeAccessTokens(revokeCaptor.capture());
        String[] revoked = revokeCaptor.getValue();
        assertEquals(revoked.length, 1);
        assertEquals(revoked[0], "predecessor_access_token");

        verify(mockAuthGrantCache).clearCacheEntryByTokenId(
                any(AuthorizationGrantCacheKey.class), eq("predecessor_id"));
    }

    @Test
    public void testPersistNewToken_caseA_successorAlreadyInactive() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        // Cache hit with count 1.
        when(mockReuseCountCache.getValueFromCache(any(), anyInt()))
                .thenReturn(new RefreshTokenCacheEntry(1));

        // Old token has successorTokenId but the successor row is gone.
        String successorId = "gone_successor_id";
        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "1");
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID, successorId);
        when(mockAccessTokenDAO.getAccessTokenByTokenId(eq(successorId))).thenReturn(null);

        RefreshTokenValidationDataDO oldToken = oldTokenDO(attrs);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        // No revoke call since successor token has no access token row.
        verify(mockAccessTokenDAO, never()).revokeAccessTokens(any());
        verify(mockAuthGrantCache, never()).clearCacheEntryByTokenId(any(), anyString());

        // Reuse path should still persist with incremented count (2).
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                eq(OLD_TOKEN_ID), any(Timestamp.class), any(), any(), eq(CLIENT_ID),
                eq(newToken), eq(USER_STORE_DOMAIN), anyString(), mapCaptor.capture());
        assertEquals(mapCaptor.getValue().get(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT), "2");
    }

    @Test
    public void testPersistNewToken_caseB_noPredecessor() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenReuseLimit()).thenReturn(5);
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        when(mockReuseCountCache.getValueFromCache(any(), anyInt())).thenReturn(null);
        when(mockAccessTokenDAO.getAccessTokenExtendedAttributeValue(anyString(), anyString(), anyString()))
                .thenReturn(null);

        // No successorTokenId, no predecessor found.
        when(mockAccessTokenDAO.getActiveTokenByExtendedAttribute(anyString(), anyString(), anyString()))
                .thenReturn(null);

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        AccessTokenDO newToken = newAccessTokenDO();
        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);

        processor.persistNewToken(ctx, newToken, USER_STORE_DOMAIN, CLIENT_ID);

        verify(mockAccessTokenDAO, never()).revokeAccessTokens(any());
        verify(mockAuthGrantCache, never()).clearCacheEntryByTokenId(any(), anyString());

        // Fresh path: grace deadline is stamped, reuse count is absent, state = GRACEFULLY_ROTATED.
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> mapCaptor = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                eq(OLD_TOKEN_ID), any(Timestamp.class), any(), stateCaptor.capture(),
                eq(CLIENT_ID), eq(newToken), eq(USER_STORE_DOMAIN), anyString(), mapCaptor.capture());
        assertTrue(mapCaptor.getValue().containsKey(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS));
        assertFalse(mapCaptor.getValue().containsKey(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT));
        assertEquals(stateCaptor.getValue(), OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED);
    }

    // -----------------------------------------------------------------------
    // createAccessTokenBean
    // -----------------------------------------------------------------------

    @Test
    public void testCreateAccessTokenBean_gracefulKeysStrippedFromExtendedAttrs() throws Exception {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(CLIENT_ID);
        tokenReq.setRefreshToken(REFRESH_TOKEN);
        tokenReq.setTenantDomain(TENANT_DOMAIN);
        tokenReq.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        Map<String, String> params = new HashMap<>();
        params.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "2");
        params.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS, "60000");
        params.put("custom_attr", "custom_value");
        tokenReq.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(params));

        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(tokenReq);
        ctx.setAuthorizedUser(mockAuthzUser);
        ctx.setScope(new String[]{"openid"});

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        AccessTokenDO result = processor.createAccessTokenBean(ctx, tokenReq, validationBean, "Bearer");

        assertNotNull(result.getAccessTokenExtendedAttributes());
        Map<String, String> resultParams = result.getAccessTokenExtendedAttributes().getParameters();
        assertTrue(resultParams.containsKey("custom_attr"), "Unrelated attribute must survive");
        assertTrue(!resultParams.containsKey(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT),
                "Reuse count must be stripped");
        assertTrue(!resultParams.containsKey(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS),
                "Grace validity must be stripped");
    }

    @Test
    public void testCreateAccessTokenBean_onlyGracefulKeys_noExtendedAttrsOnNewToken() throws Exception {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(CLIENT_ID);
        tokenReq.setRefreshToken(REFRESH_TOKEN);
        tokenReq.setTenantDomain(TENANT_DOMAIN);
        tokenReq.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        Map<String, String> params = new HashMap<>();
        params.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "1");
        params.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS, "30000");
        tokenReq.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(params));

        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(tokenReq);
        ctx.setAuthorizedUser(mockAuthzUser);
        ctx.setScope(new String[]{"openid"});

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        AccessTokenDO result = processor.createAccessTokenBean(ctx, tokenReq, validationBean, "Bearer");

        assertNull(result.getAccessTokenExtendedAttributes(),
                "No extended attributes should be set when only graceful keys are present");
    }

    @Test
    public void testCreateAccessTokenBean_consentedColumnEnabled_refreshTokenGrant_propagatesConsentedFlag()
            throws Exception {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(CLIENT_ID);
        tokenReq.setRefreshToken(REFRESH_TOKEN);
        tokenReq.setTenantDomain(TENANT_DOMAIN);
        tokenReq.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(tokenReq);
        ctx.setAuthorizedUser(mockAuthzUser);
        ctx.setScope(new String[]{"openid"});

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        validationBean.setConsented(true);

        AccessTokenDO result = processor.createAccessTokenBean(ctx, tokenReq, validationBean, "Bearer");

        assertTrue(result.isConsentedToken(),
                "isConsentedToken must be true when validationBean.isConsented() is true");
        assertTrue(ctx.isConsentedToken(),
                "OAuthTokenReqMessageContext.consentedToken must be set to true");
    }

    @Test
    public void testCreateAccessTokenBean_consentedColumnEnabled_nonRefreshGrantWithConsentFiltering_setsConsentedTrue()
            throws Exception {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(CLIENT_ID);
        tokenReq.setRefreshToken(REFRESH_TOKEN);
        tokenReq.setTenantDomain(TENANT_DOMAIN);
        tokenReq.setGrantType(OAuthConstants.GrantTypes.AUTHORIZATION_CODE);

        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(tokenReq);
        ctx.setAuthorizedUser(mockAuthzUser);
        ctx.setScope(new String[]{"openid"});

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.AUTHORIZATION_CODE);

        oidcClaimUtilMockedStatic.when(
                () -> OIDCClaimUtil.isConsentBasedClaimFilteringApplicable
                        (OAuthConstants.GrantTypes.AUTHORIZATION_CODE))
                .thenReturn(true);

        AccessTokenDO result = processor.createAccessTokenBean(ctx, tokenReq, validationBean, "Bearer");

        assertTrue(result.isConsentedToken(),
                "isConsentedToken must be true when isConsentBasedClaimFilteringApplicable returns true");
        assertTrue(ctx.isConsentedToken(),
                "OAuthTokenReqMessageContext.consentedToken must be set to true");
    }

    @Test
    public void testCreateAccessTokenBean_consentedColumnEnabled_refreshTokenGrant_nonConsented_doesNotFlipContext()
            throws Exception {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(CLIENT_ID);
        tokenReq.setRefreshToken(REFRESH_TOKEN);
        tokenReq.setTenantDomain(TENANT_DOMAIN);
        tokenReq.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(tokenReq);
        ctx.setAuthorizedUser(mockAuthzUser);
        ctx.setScope(new String[]{"openid"});

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        // isConsented() defaults to false — not calling setConsented(true)

        AccessTokenDO result = processor.createAccessTokenBean(ctx, tokenReq, validationBean, "Bearer");

        assertFalse(result.isConsentedToken(),
                "isConsentedToken must remain false when validationBean.isConsented() is false");
        assertFalse(ctx.isConsentedToken(),
                "OAuthTokenReqMessageContext.consentedToken must remain false");
    }

    // -----------------------------------------------------------------------
    // addUserAttributesToCache
    // -----------------------------------------------------------------------

    @Test
    public void testAddUserAttributesToCache_firstGracefulRotation_reAddsOldEntryWithGraceTTL()
            throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        Timestamp issuedNow = new Timestamp(System.currentTimeMillis());
        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        oldToken.setIssuedTime(issuedNow);

        AccessTokenDO newToken = newAccessTokenDO();
        newToken.setRefreshTokenValidityPeriodInMillis(3600_000L);

        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);
        ctx.setAuthorizedUser(mockAuthzUser);

        when(mockAuthGrantCache.getValueFromCacheByTokenId(any(), anyString()))
                .thenReturn(mockGrantCacheEntry);

        processor.addUserAttributesToCache(newToken, ctx);

        // The old cache entry should be re-added under the old access-token key.
        ArgumentCaptor<AuthorizationGrantCacheKey> keyCaptor =
                ArgumentCaptor.forClass(AuthorizationGrantCacheKey.class);
        verify(mockAuthGrantCache, atLeastOnce()).addToCacheByToken(keyCaptor.capture(), any());

        List<AuthorizationGrantCacheKey> capturedKeys = keyCaptor.getAllValues();
        boolean oldKeyFound = capturedKeys.stream()
                .anyMatch(k -> OLD_ACCESS_TOKEN.equals(k.getUserAttributesId()));
        assertTrue(oldKeyFound, "Old access-token cache entry must be re-added for graceful rotation");
    }

    @Test
    public void testAddUserAttributesToCache_reuseCase_doesNotReAddOldEntry() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(true);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");
        when(mockOAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod()).thenReturn(30);

        // Non-zero reuse count means this is already a reuse, not the first rotation.
        Map<String, String> attrs = new HashMap<>();
        attrs.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT, "1");
        RefreshTokenValidationDataDO oldToken = oldTokenDO(attrs);
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis()));

        AccessTokenDO newToken = newAccessTokenDO();
        newToken.setRefreshTokenValidityPeriodInMillis(3600_000L);

        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);
        ctx.setAuthorizedUser(mockAuthzUser);

        when(mockAuthGrantCache.getValueFromCacheByTokenId(any(), anyString()))
                .thenReturn(mockGrantCacheEntry);

        processor.addUserAttributesToCache(newToken, ctx);

        ArgumentCaptor<AuthorizationGrantCacheKey> keyCaptor =
                ArgumentCaptor.forClass(AuthorizationGrantCacheKey.class);
        verify(mockAuthGrantCache, atLeastOnce()).addToCacheByToken(keyCaptor.capture(), any());

        boolean oldKeyFound = keyCaptor.getAllValues().stream()
                .anyMatch(k -> OLD_ACCESS_TOKEN.equals(k.getUserAttributesId()));
        assertTrue(!oldKeyFound, "Old entry must NOT be re-added for a reuse (non-first rotation)");
    }

    @Test
    public void testAddUserAttributesToCache_nonGraceful_doesNotReAddOldEntry() throws Exception {

        when(mockOAuthAppDO.isGracefulRefreshTokenRotationEnabled()).thenReturn(false);
        when(mockOAuthAppDO.getRenewRefreshTokenEnabled()).thenReturn("true");

        RefreshTokenValidationDataDO oldToken = oldTokenDO(null);
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis()));

        AccessTokenDO newToken = newAccessTokenDO();
        newToken.setRefreshTokenValidityPeriodInMillis(3600_000L);

        OAuthTokenReqMessageContext ctx = persistContext(oldToken, mockOAuthAppDO);
        ctx.setAuthorizedUser(mockAuthzUser);

        when(mockAuthGrantCache.getValueFromCacheByTokenId(any(), anyString()))
                .thenReturn(mockGrantCacheEntry);

        processor.addUserAttributesToCache(newToken, ctx);

        ArgumentCaptor<AuthorizationGrantCacheKey> keyCaptor =
                ArgumentCaptor.forClass(AuthorizationGrantCacheKey.class);
        verify(mockAuthGrantCache, atLeastOnce()).addToCacheByToken(keyCaptor.capture(), any());

        boolean oldKeyFound = keyCaptor.getAllValues().stream()
                .anyMatch(k -> OLD_ACCESS_TOKEN.equals(k.getUserAttributesId()));
        assertTrue(!oldKeyFound, "Old entry must NOT be re-added when graceful rotation is disabled");
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    private OAuthTokenReqMessageContext buildTokenReqContext(String clientId, String refreshToken,
                                                             String tenantDomain) {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(clientId);
        tokenReq.setRefreshToken(refreshToken);
        tokenReq.setTenantDomain(tenantDomain);
        return new OAuthTokenReqMessageContext(tokenReq);
    }

    private RefreshTokenValidationDataDO refreshTokenBean(String state, Map<String, String> attrMap,
                                                          Timestamp issuedTime) {

        RefreshTokenValidationDataDO bean = new RefreshTokenValidationDataDO();
        bean.setRefreshTokenState(state);
        bean.setIssuedTime(issuedTime);
        bean.setTokenId(OLD_TOKEN_ID);
        bean.setAuthorizedUser(mockAuthzUser);
        bean.setScope(new String[]{"openid"});
        bean.setTokenBindingReference("NONE");
        if (attrMap != null) {
            bean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(attrMap));
        }
        return bean;
    }

    private RefreshTokenValidationDataDO oldTokenDO(Map<String, String> attrMap) {

        RefreshTokenValidationDataDO bean = new RefreshTokenValidationDataDO();
        bean.setTokenId(OLD_TOKEN_ID);
        bean.setAccessToken(OLD_ACCESS_TOKEN);
        bean.setIssuedTime(new Timestamp(System.currentTimeMillis() - 1000));
        bean.setAuthorizedUser(mockAuthzUser);
        bean.setScope(new String[]{"openid"});
        bean.setTokenBindingReference("NONE");
        bean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        if (attrMap != null) {
            bean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(attrMap));
        }
        return bean;
    }

    private AccessTokenDO newAccessTokenDO() {

        AccessTokenDO tokenDO = new AccessTokenDO();
        tokenDO.setTokenId("new_token_id");
        tokenDO.setAccessToken("new_access_token");
        tokenDO.setRefreshToken(REFRESH_TOKEN);
        tokenDO.setAuthzUser(mockAuthzUser);
        tokenDO.setConsumerKey(CLIENT_ID);
        tokenDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        tokenDO.setRefreshTokenValidityPeriodInMillis(3600_000L);
        return tokenDO;
    }

    private OAuthTokenReqMessageContext persistContext(RefreshTokenValidationDataDO oldToken, OAuthAppDO appDO) {

        OAuth2AccessTokenReqDTO tokenReq = new OAuth2AccessTokenReqDTO();
        tokenReq.setClientId(CLIENT_ID);
        tokenReq.setRefreshToken(REFRESH_TOKEN);
        tokenReq.setTenantDomain(TENANT_DOMAIN);
        tokenReq.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);

        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(tokenReq);
        ctx.setAuthorizedUser(mockAuthzUser);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);
        return ctx;
    }

    private AccessTokenDO buildSibling(String tokenId, String accessToken) {

        AccessTokenDO sibling = new AccessTokenDO();
        sibling.setTokenId(tokenId);
        sibling.setAccessToken(accessToken);
        sibling.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        return sibling;
    }
}
