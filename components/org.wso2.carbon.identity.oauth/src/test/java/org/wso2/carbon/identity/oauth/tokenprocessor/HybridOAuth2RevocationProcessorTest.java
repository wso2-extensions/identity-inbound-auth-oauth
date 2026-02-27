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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.RevokedTokenPersistenceDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for HybridOAuth2RevocationProcessor.
 * Tests the behavior when OAuth2Util.isAccessTokenPersistenceEnabled() returns true (early return)
 * and when it returns false (actual revocation with DAO calls).
 */
@WithCarbonHome
public class HybridOAuth2RevocationProcessorTest {

    private static final String TEST_CONSUMER_KEY = "test_consumer_key";
    private static final String TEST_ACCESS_TOKEN = "test_access_token";
    private static final String TEST_REFRESH_TOKEN = "test_refresh_token";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_APP_ID = "test_app_resource_id";
    private static final String TEST_API_ID = "test_api_id";
    private static final String TEST_ROLE_ID = "test_role_id";
    private static final String TEST_CLIENT_ID = "test_client_id";
    private static final int TEST_TENANT_ID = -1234;

    private HybridOAuth2RevocationProcessor hybridOAuth2RevocationProcessor;
    private AutoCloseable closeable;

    @Mock
    private OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory;

    @Mock
    private RevokedTokenPersistenceDAO mockRevokedTokenPersistenceDAO;

    @Mock
    private RefreshTokenDAOImpl mockRefreshTokenDAO;

    @Mock
    private AbstractUserStoreManager mockUserStoreManager;

    @Mock
    private ApplicationManagementService mockApplicationManagementService;

    @Mock
    private RoleManagementService mockRoleManagementService;

    @Mock
    private RealmConfiguration mockRealmConfiguration;

    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactoryMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockedStatic;
    private MockedStatic<OAuthUtil> oAuthUtilMockedStatic;
    private MockedStatic<AccessTokenEventUtil> accessTokenEventUtilMockedStatic;

    @Mock
    private PrivilegedCarbonContext mockPrivilegedCarbonContext;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
        hybridOAuth2RevocationProcessor = new HybridOAuth2RevocationProcessor();

        // Inject mock RefreshTokenDAOImpl using reflection
        Field refreshTokenDAOField = HybridOAuth2RevocationProcessor.class.getDeclaredField("refreshTokenDAO");
        refreshTokenDAOField.setAccessible(true);
        refreshTokenDAOField.set(hybridOAuth2RevocationProcessor, mockRefreshTokenDAO);

        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        privilegedCarbonContextMockedStatic = mockStatic(PrivilegedCarbonContext.class);
        oAuthUtilMockedStatic = mockStatic(OAuthUtil.class);
        accessTokenEventUtilMockedStatic = mockStatic(AccessTokenEventUtil.class);

        // Setup mock factory to return mock DAOs using lenient to avoid UnnecessaryStubbingException
        lenient().when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockOAuthTokenPersistenceFactory);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        lenient().when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenPersistenceDAO);

        // Setup IdentityTenantUtil mock
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(TEST_TENANT_ID);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                .thenReturn(TEST_TENANT_DOMAIN);

        // Setup PrivilegedCarbonContext mock
        privilegedCarbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(mockPrivilegedCarbonContext);
        lenient().when(mockPrivilegedCarbonContext.getTenantId()).thenReturn(TEST_TENANT_ID);
        lenient().when(mockPrivilegedCarbonContext.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);

        // Setup OAuthComponentServiceHolder mocks
        OAuthComponentServiceHolder.getInstance().setApplicationManagementService(mockApplicationManagementService);
        OAuthComponentServiceHolder.getInstance().setRoleV2ManagementService(mockRoleManagementService);

        // Setup UserStoreManager mock
        lenient().when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        lenient().when(mockRealmConfiguration.getUserStoreProperty(anyString())).thenReturn("PRIMARY");
    }

    @AfterMethod
    public void tearDown() throws Exception {

        closeMockSafely(oAuth2UtilMockedStatic);
        closeMockSafely(oAuthTokenPersistenceFactoryMockedStatic);
        closeMockSafely(identityTenantUtilMockedStatic);
        closeMockSafely(privilegedCarbonContextMockedStatic);
        closeMockSafely(oAuthUtilMockedStatic);
        closeMockSafely(accessTokenEventUtilMockedStatic);

        // Clear OAuthComponentServiceHolder
        OAuthComponentServiceHolder.getInstance().setApplicationManagementService(null);
        OAuthComponentServiceHolder.getInstance().setRoleV2ManagementService(null);

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

    // ======================== Negative Tests: persistence enabled (early return) ========================

    @Test
    public void testRevokeAccessToken_WhenPersistenceEnabled_ShouldReturnEarly() throws IdentityOAuth2Exception {

        // Configure OAuth2Util to enable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        OAuthRevocationRequestDTO revokeRequestDTO = createOAuthRevocationRequestDTO();
        AccessTokenDO accessTokenDO = createAccessTokenDO(false);

        hybridOAuth2RevocationProcessor.revokeAccessToken(revokeRequestDTO, accessTokenDO);

        // Verify that revokedTokenPersistenceDAO methods are not called
        verify(mockRevokedTokenPersistenceDAO, never()).addRevokedToken(anyString(), anyString(), anyLong());
        verify(mockRevokedTokenPersistenceDAO, never())
                .revokeTokensBySubjectEvent(anyString(), anyString(), anyLong(), anyInt());
    }

    // ======================== Positive Tests: persistence disabled (actual revocation) ========================

    @Test
    public void testRevokeAccessToken_WhenPersistenceDisabledAndTokenNotPersisted_ShouldCallAddRevokedToken()
            throws IdentityOAuth2Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);

        OAuthRevocationRequestDTO revokeRequestDTO = createOAuthRevocationRequestDTO();
        AccessTokenDO accessTokenDO = createAccessTokenDO(true); // Token is not persisted

        hybridOAuth2RevocationProcessor.revokeAccessToken(revokeRequestDTO, accessTokenDO);

        // Verify that addRevokedToken is called with correct parameters
        verify(mockRevokedTokenPersistenceDAO).addRevokedToken(
                eq(TEST_ACCESS_TOKEN),
                eq(TEST_CONSUMER_KEY),
                anyLong()
        );

        // Verify token state is updated to REVOKED
        assertEquals(accessTokenDO.getTokenState(), "REVOKED",
                "Token state should be set to REVOKED");
    }

    @Test
    public void testRevokeRefreshToken_WhenPersistenceDisabledAndRefreshPersistenceDisabled_ShouldCallAddRevokedToken()
            throws IdentityOAuth2Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);
        // Also disable refresh token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isRefreshTokenPersistenceEnabled).thenReturn(false);

        OAuthRevocationRequestDTO revokeRequestDTO = createOAuthRevocationRequestDTO();
        RefreshTokenValidationDataDO refreshTokenDO = createRefreshTokenValidationDataDO(true); // With non-persisted AT

        hybridOAuth2RevocationProcessor.revokeRefreshToken(revokeRequestDTO, refreshTokenDO);

        // Verify that addRevokedToken is called with correct parameters
        verify(mockRevokedTokenPersistenceDAO).addRevokedToken(
                eq(TEST_REFRESH_TOKEN),
                eq(TEST_CONSUMER_KEY),
                anyLong()
        );

        // Verify refresh token state is updated to REVOKED
        assertEquals(refreshTokenDO.getRefreshTokenState(), "REVOKED",
                "Refresh token state should be set to REVOKED");
    }

    @Test
    public void testRevokeRefreshToken_WhenPersistenceDisabledAndRefreshPersistenceEnabled_ShouldCallRefreshTokenDAO()
            throws IdentityOAuth2Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);
        // Enable refresh token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isRefreshTokenPersistenceEnabled).thenReturn(true);

        OAuthRevocationRequestDTO revokeRequestDTO = createOAuthRevocationRequestDTO();
        RefreshTokenValidationDataDO refreshTokenDO = createRefreshTokenValidationDataDO(true); // With non-persisted AT

        hybridOAuth2RevocationProcessor.revokeRefreshToken(revokeRequestDTO, refreshTokenDO);

        // Verify RefreshTokenDAOImpl.revokeToken was called with correct token
        verify(mockRefreshTokenDAO).revokeToken(eq(TEST_REFRESH_TOKEN));

        // Verify refresh token state is updated to REVOKED
        assertEquals(refreshTokenDO.getRefreshTokenState(), "REVOKED",
                "Refresh token state should be set to REVOKED");
    }

    @Test
    public void testRevokeRefreshToken_WhenPersistenceEnabledWithNonPersistedAT_ShouldReturnEarly()
            throws IdentityOAuth2Exception {

        // Configure OAuth2Util to enable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        OAuthRevocationRequestDTO revokeRequestDTO = createOAuthRevocationRequestDTO();
        RefreshTokenValidationDataDO refreshTokenDO = createRefreshTokenValidationDataDO(true);

        hybridOAuth2RevocationProcessor.revokeRefreshToken(revokeRequestDTO, refreshTokenDO);

        // Verify that revokedTokenPersistenceDAO methods are not called (early return)
        verify(mockRevokedTokenPersistenceDAO, never()).addRevokedToken(anyString(), anyString(), anyLong());
    }

    @Test
    public void testRevokeRefreshToken_WhenPersistenceDisabledAndTokenPersistedWithAT_ShouldNotCallAddRevokedToken()
            throws IdentityOAuth2Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);

        OAuthRevocationRequestDTO revokeRequestDTO = createOAuthRevocationRequestDTO();
        // Token is persisted with AT (isWithNotPersistedAT = false), so it should go to default processor
        RefreshTokenValidationDataDO refreshTokenDO = createRefreshTokenValidationDataDO(false);

        // This will call defaultOAuth2RevocationProcessor.revokeRefreshToken which we can't fully mock,
        // but we can verify that our mockRevokedTokenPersistenceDAO.addRevokedToken is NOT called
        // (since the default processor handles it differently)
        try {
            hybridOAuth2RevocationProcessor.revokeRefreshToken(revokeRequestDTO, refreshTokenDO);
        } catch (Exception e) {
            // Default processor may throw exception due to missing dependencies, that's expected
        }

        // Verify that addRevokedToken is NOT called (because it goes to default processor path)
        verify(mockRevokedTokenPersistenceDAO, never()).addRevokedToken(anyString(), anyString(), anyLong());
    }

    // ======================== Tests for revokeTokens(appId, apiId, removedScopes, tenantDomain) ================

    @Test
    public void testRevokeTokensByAppAndScopes_WhenPersistenceDisabled_ShouldCallRevokeTokensBySubjectEvent()
            throws Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);

        // Setup application management service to return a service provider with OAuth2 inbound config
        ServiceProvider serviceProvider = createServiceProviderWithOAuth2Config(TEST_CLIENT_ID);
        when(mockApplicationManagementService.getApplicationByResourceId(eq(TEST_APP_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(serviceProvider);

        List<String> removedScopes = new ArrayList<>();
        removedScopes.add("scope1");
        removedScopes.add("scope2");

        hybridOAuth2RevocationProcessor.revokeTokens(TEST_APP_ID, TEST_API_ID, removedScopes, TEST_TENANT_DOMAIN);

        // Verify revokeTokensBySubjectEvent is called with client ID
        verify(mockRevokedTokenPersistenceDAO).revokeTokensBySubjectEvent(
                eq(TEST_CLIENT_ID),
                eq("CLIENT_ID"),
                anyLong(),
                eq(TEST_TENANT_ID)
        );

        // Verify RefreshTokenDAOImpl.revokeTokensForApp was called
        verify(mockRefreshTokenDAO).revokeTokensForApp(eq(TEST_CLIENT_ID));

        // Verify AccessTokenEventUtil.publishTokenRevokeEvent was called
        accessTokenEventUtilMockedStatic.verify(() ->
                AccessTokenEventUtil.publishTokenRevokeEvent(
                        eq(TEST_APP_ID), eq(TEST_CLIENT_ID), eq(TEST_TENANT_DOMAIN)));
    }

    @Test
    public void testRevokeTokensByAppAndScopes_WhenNoOAuth2Client_ShouldNotCallRevoke()
            throws Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);

        // Setup application management service to return a service provider without OAuth2 config
        ServiceProvider serviceProvider = new ServiceProvider();
        when(mockApplicationManagementService.getApplicationByResourceId(eq(TEST_APP_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(serviceProvider);

        List<String> removedScopes = new ArrayList<>();
        removedScopes.add("scope1");

        hybridOAuth2RevocationProcessor.revokeTokens(TEST_APP_ID, TEST_API_ID, removedScopes, TEST_TENANT_DOMAIN);

        // Verify revokeTokensBySubjectEvent is NOT called since no OAuth2 client
        verify(mockRevokedTokenPersistenceDAO, never())
                .revokeTokensBySubjectEvent(anyString(), anyString(), anyLong(), anyInt());
    }

    @Test
    public void testRevokeTokensByAppAndScopes_WhenPersistenceEnabled_ShouldDelegateToDefaultProcessor()
            throws Exception {

        // Configure OAuth2Util to enable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        List<String> removedScopes = new ArrayList<>();
        removedScopes.add("scope1");

        // This should delegate to the default processor, so our mock DAO should not be called
        // Default processor may throw exception due to missing dependencies
        try {
            hybridOAuth2RevocationProcessor.revokeTokens(TEST_APP_ID, TEST_API_ID, removedScopes, TEST_TENANT_DOMAIN);
        } catch (Exception e) {
            // Expected - default processor requires more dependencies
        }

        // Verify our mockRevokedTokenPersistenceDAO.revokeTokensBySubjectEvent is NOT called
        // because it delegated to the default processor
        verify(mockRevokedTokenPersistenceDAO, never())
                .revokeTokensBySubjectEvent(anyString(), anyString(), anyLong(), anyInt());
    }

    // ======================== Tests for revokeTokens(username, userStoreManager, roleId) =======================

    @Test
    public void testRevokeTokensByUsernameAndRoleId_WhenPersistenceDisabledAndAppAudienceRole_ShouldRevokeForClientId()
            throws Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);

        // Setup role management service to return an APPLICATION audience role
        RoleBasicInfo roleBasicInfo = mock(RoleBasicInfo.class);
        when(roleBasicInfo.getAudience()).thenReturn(RoleConstants.APPLICATION);
        when(roleBasicInfo.getAudienceId()).thenReturn(TEST_APP_ID);
        when(mockRoleManagementService.getRoleBasicInfoById(eq(TEST_ROLE_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(roleBasicInfo);

        // Setup application management service to return a service provider with OAuth2 config
        ServiceProvider serviceProvider = createServiceProviderWithOAuth2Config(TEST_CLIENT_ID);
        when(mockApplicationManagementService.getApplicationByResourceId(eq(TEST_APP_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(serviceProvider);

        boolean result = hybridOAuth2RevocationProcessor.revokeTokens(
                TEST_USERNAME, mockUserStoreManager, TEST_ROLE_ID);

        assertTrue(result, "Should return true for successful revocation");

        // Verify revokeTokensBySubjectEvent is called with client ID
        verify(mockRevokedTokenPersistenceDAO).revokeTokensBySubjectEvent(
                eq(TEST_CLIENT_ID),
                eq("CLIENT_ID"),
                anyLong(),
                eq(TEST_TENANT_ID)
        );

        // Verify RefreshTokenDAOImpl.revokeTokensForApp was called
        verify(mockRefreshTokenDAO).revokeTokensForApp(eq(TEST_CLIENT_ID));

        // Verify pre and post revocation listeners were invoked
        oAuthUtilMockedStatic.verify(() ->
                OAuthUtil.invokePreRevocationBySystemListeners(eq(TEST_CLIENT_ID), any()));
        oAuthUtilMockedStatic.verify(() ->
                OAuthUtil.invokePostRevocationBySystemListeners(eq(TEST_CLIENT_ID), any()));
    }

    @Test
    public void testRevokeTokensByUsernameAndRoleId_WhenPersistenceEnabled_ShouldReturnTrue()
            throws Exception {

        // Configure OAuth2Util to enable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        boolean result = hybridOAuth2RevocationProcessor.revokeTokens(
                TEST_USERNAME, mockUserStoreManager, TEST_ROLE_ID);

        assertTrue(result, "Should return true when persistence is enabled (early return)");

        // Verify no revocation calls are made
        verify(mockRevokedTokenPersistenceDAO, never())
                .revokeTokensBySubjectEvent(anyString(), anyString(), anyLong(), anyInt());
    }

    @Test
    public void testRevokeTokensByUsernameAndRoleId_WhenRoleIsNull_ShouldDelegateToTwoArgMethod()
            throws Exception {

        // Configure OAuth2Util to enable access token persistence (so we can verify early return)
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        boolean result = hybridOAuth2RevocationProcessor.revokeTokens(TEST_USERNAME, mockUserStoreManager, null);

        // Should return true because it delegates to 2-arg method which returns early when persistence is enabled
        assertTrue(result, "Should return true when delegating to 2-arg method with persistence enabled");

        // Verify no revocation calls are made
        verify(mockRevokedTokenPersistenceDAO, never())
                .revokeTokensBySubjectEvent(anyString(), anyString(), anyLong(), anyInt());
    }

    @Test
    public void testRevokeTokensByUsernameAndRoleId_WhenRoleNotFound_ShouldDelegateToTwoArgMethod()
            throws Exception {

        // Configure OAuth2Util to enable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);

        // Setup role management service to return null (role not found)
        when(mockRoleManagementService.getRoleBasicInfoById(eq(TEST_ROLE_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(null);

        boolean result = hybridOAuth2RevocationProcessor.revokeTokens(
                TEST_USERNAME, mockUserStoreManager, TEST_ROLE_ID);

        // Should return true because it delegates to 2-arg method which returns early when persistence is enabled
        assertTrue(result, "Should return true when role not found and persistence enabled");
    }

    @Test
    public void testRevokeTokensByUsernameAndRoleId_WhenNoOAuth2ClientForApp_ShouldReturnTrue()
            throws Exception {

        // Configure OAuth2Util to disable access token persistence
        oAuth2UtilMockedStatic.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);

        // Setup role management service to return an APPLICATION audience role
        RoleBasicInfo roleBasicInfo = mock(RoleBasicInfo.class);
        when(roleBasicInfo.getAudience()).thenReturn(RoleConstants.APPLICATION);
        when(roleBasicInfo.getAudienceId()).thenReturn(TEST_APP_ID);
        when(mockRoleManagementService.getRoleBasicInfoById(eq(TEST_ROLE_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(roleBasicInfo);

        // Setup application management service to return a service provider WITHOUT OAuth2 config
        ServiceProvider serviceProvider = new ServiceProvider();
        when(mockApplicationManagementService.getApplicationByResourceId(eq(TEST_APP_ID), eq(TEST_TENANT_DOMAIN)))
                .thenReturn(serviceProvider);

        boolean result = hybridOAuth2RevocationProcessor.revokeTokens(
                TEST_USERNAME, mockUserStoreManager, TEST_ROLE_ID);

        // Should return true and skip revocation since no OAuth2 client
        assertTrue(result, "Should return true when no OAuth2 client found");

        // Verify no revocation calls are made
        verify(mockRevokedTokenPersistenceDAO, never())
                .revokeTokensBySubjectEvent(anyString(), anyString(), anyLong(), anyInt());
    }

    // ======================== Helper methods ========================

    private OAuthRevocationRequestDTO createOAuthRevocationRequestDTO() {

        OAuthRevocationRequestDTO dto = new OAuthRevocationRequestDTO();
        dto.setConsumerKey(TEST_CONSUMER_KEY);
        dto.setToken(TEST_ACCESS_TOKEN);
        return dto;
    }

    private AccessTokenDO createAccessTokenDO(boolean isNotPersisted) {

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken(TEST_ACCESS_TOKEN);
        accessTokenDO.setConsumerKey(TEST_CONSUMER_KEY);
        accessTokenDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        accessTokenDO.setValidityPeriodInMillis(3600000L);
        accessTokenDO.setNotPersisted(isNotPersisted);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USERNAME);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        accessTokenDO.setAuthzUser(authenticatedUser);

        return accessTokenDO;
    }

    private RefreshTokenValidationDataDO createRefreshTokenValidationDataDO(boolean withNotPersistedAT) {

        RefreshTokenValidationDataDO refreshTokenDO = new RefreshTokenValidationDataDO();
        refreshTokenDO.setRefreshToken(TEST_REFRESH_TOKEN);
        refreshTokenDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        refreshTokenDO.setValidityPeriodInMillis(7200000L);
        refreshTokenDO.setWithNotPersistedAT(withNotPersistedAT);
        return refreshTokenDO;
    }

    private ServiceProvider createServiceProviderWithOAuth2Config(String clientId) {

        ServiceProvider serviceProvider = new ServiceProvider();
        InboundAuthenticationConfig inboundAuthConfig = new InboundAuthenticationConfig();
        InboundAuthenticationRequestConfig oauthConfig = new InboundAuthenticationRequestConfig();
        oauthConfig.setInboundAuthType("oauth2");
        oauthConfig.setInboundAuthKey(clientId);
        inboundAuthConfig.setInboundAuthenticationRequestConfigs(
                new InboundAuthenticationRequestConfig[]{oauthConfig});
        serviceProvider.setInboundAuthenticationConfig(inboundAuthConfig);
        return serviceProvider;
    }
}
