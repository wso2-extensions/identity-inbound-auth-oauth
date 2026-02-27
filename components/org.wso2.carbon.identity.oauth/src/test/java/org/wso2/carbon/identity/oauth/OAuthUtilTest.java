/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAO;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.TestConstants.CARBON_TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.TestConstants.LOCAL_IDP;
import static org.wso2.carbon.identity.oauth2.TestConstants.MANAGED_ORG_CLAIM_URI;
import static org.wso2.carbon.identity.oauth2.TestConstants.SAMPLE_ID;

/**
 * Unit tests for OAuthUtil class.
 */
@WithCarbonHome
@WithRealmService
@Listeners(MockitoTestNGListener.class)
public class OAuthUtilTest {

    @Mock
    private OrganizationManager organizationManager;

    @Mock
    private OrganizationUserSharingService organizationUserSharingService;

    @Mock
    private TokenManagementDAO tokenManagementDAO;

    @Mock
    private IdpManager idpManager;

    @Mock
    private RealmService realmService;

    @Mock
    RoleManagementService roleManagementService;

    @Mock
    ApplicationManagementService applicationManagementService;

    @Mock
    private IdentityEventService identityEventService;

    private AutoCloseable closeable;
    private MockedStatic<OrganizationManagementUtil> organizationManagementUtil;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<AuthorizationGrantCache> authorizationGrantCache;
    private MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactory;
    private MockedStatic<IdPManagementUtil> idpManagementUtil;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
        organizationManagementUtil = mockStatic(OrganizationManagementUtil.class);
        OAuthComponentServiceHolder.getInstance().setOrganizationUserSharingService(organizationUserSharingService);
        OAuthComponentServiceHolder.getInstance().setRoleV2ManagementService(roleManagementService);
        OAuthComponentServiceHolder.getInstance().setApplicationManagementService(applicationManagementService);
        OAuthComponentServiceHolder.getInstance().setIdpManager(idpManager);
        OAuthComponentServiceHolder.getInstance().setOrganizationManager(organizationManager);
        OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
        oAuth2Util = mockStatic(OAuth2Util.class);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        oAuthTokenPersistenceFactory = mockStatic(OAuthTokenPersistenceFactory.class);
        authorizationGrantCache = mockStatic(AuthorizationGrantCache.class);
        idpManagementUtil = mockStatic(IdPManagementUtil.class);
        OpenIDConnectServiceComponentHolder.setIdentityEventService(identityEventService);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        organizationManagementUtil.close();
        oAuth2Util.close();
        identityDatabaseUtil.close();
        oAuthTokenPersistenceFactory.close();
        authorizationGrantCache.close();
        idpManagementUtil.close();
        reset(organizationUserSharingService);
        reset(roleManagementService);
        reset(applicationManagementService);
        reset(realmService);
        reset(idpManager);
        reset(organizationManager);
        closeable.close();
    }
    
    @DataProvider(name = "testGetAuthenticatedUser")
    public Object[][] fullQualifiedUserName() {
        return new Object[][] { { "JDBC/siripala@is.com", "siripala" }, { "JDBC/siripala", "siripala" },
                { "siripala@is.com", "siripala" }, { "siripala", "siripala" } };
    }

    @DataProvider(name = "testClearOAuthCache")
    public Object[][] isUserStoreCaseSensitive() {
        return new Object[][] { { true }, { false } };
    }

    @Test
    public void testGetRandomNumber() throws Exception {
        assertTrue(StringUtils.isNotBlank(OAuthUtil.getRandomNumber()), "Generated random string should not be blank.");
    }

    @Test
    public void testClearOAuthCache() throws Exception {

        String cacheKey = "some-cache-key";
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKey);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(cacheKey);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear(-1234);
    }

    @Test(dataProvider = "testClearOAuthCache")
    public void testClearOAuthCacheKeyUser(boolean isUserStoreCaseSensitive) throws Exception {

        String consumerKey = "consumer-key";
        String authorizedUser = "authorized-user";
        String cacheKey = consumerKey + ":" + authorizedUser + ":" + LOCAL_IDP;
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKey);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(cacheKey);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear(-1234);
    }

    @Test
    public void testClearOAuthCacheKeyUserclass() throws Exception {

        String consumerKey = "consumer-key";
        User authorizedUser = new User();
        authorizedUser.setUserName("siripala");
        authorizedUser.setTenantDomain("is.com");
        authorizedUser.setUserStoreDomain("JDBC");
        String cacheKey = consumerKey + ":" + authorizedUser.toString() + ":" + LOCAL_IDP;

        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKey);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(cacheKey);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear(-1234);
    }

    @Test(dataProvider = "testClearOAuthCache")
    public void testClearOAuthCacheKeyUserScope(boolean isUserStoreCaseSensitive) throws Exception {

        String consumerKey = "consumer-key";
        String authorizedUser = "authorized-user";
        String scope = "scope";
        String cacheKey = consumerKey + ":" + authorizedUser + ":" + scope + ":" + LOCAL_IDP;
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKey);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(cacheKey);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear(-1234);
    }

    @Test
    public void testClearOAuthCacheKeyUserclassScope() throws Exception {

        String consumerKey = "consumer-key";
        User authorizedUser = new User();
        authorizedUser.setUserName("siripala");
        authorizedUser.setTenantDomain("is.com");
        authorizedUser.setUserStoreDomain("JDBC");
        String scope = "scope";
        String cacheKey = consumerKey + ":" + authorizedUser.toString() + ":" + scope + ":" + LOCAL_IDP;
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKey);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(cacheKey);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear(-1234);
    }

    @Test(dataProvider = "testGetAuthenticatedUser")
    public void testGetAuthenticatedUser(String fullQualifiedName, String username) throws Exception {
        assertEquals(OAuthUtil.getAuthenticatedUser(fullQualifiedName).getUserName(), username,
                "Should set the " + "cleared username from fullyQualifiedName.");
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGetAuthenticatedUserException() throws Exception {
        OAuthUtil.getAuthenticatedUser("");
    }

    @Test
    public void testRevokeTokensForApplicationAudienceRoles() throws Exception {

        String username = "testUser";
        String roleId = "testRoleId";
        String roleName = "testRole";
        String appId = "testAppId";
        String clientId = "testClientId";
        String accessToken = "testAccessToken";

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        when(userStoreManager.getTenantId()).thenReturn(-1234);
        when(userStoreManager.getRealmConfiguration()).thenReturn(mock(RealmConfiguration.class));
        when(userStoreManager.getRealmConfiguration().getUserStoreProperty(anyString())).thenReturn("PRIMARY");

        when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(false);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(-1234);

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo();
        roleBasicInfo.setId(roleId);
        roleBasicInfo.setAudience(RoleConstants.APPLICATION);
        roleBasicInfo.setAudienceId(appId);
        roleBasicInfo.setName(roleName);
        when(roleManagementService.getRoleBasicInfoById(roleId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(roleBasicInfo);

        ServiceProvider serviceProvider = new ServiceProvider();
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        InboundAuthenticationRequestConfig[] inboundAuthenticationRequestConfigs =
                new InboundAuthenticationRequestConfig[1];
        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig =
                new InboundAuthenticationRequestConfig();
        inboundAuthenticationRequestConfig.setInboundAuthKey(clientId);
        inboundAuthenticationRequestConfig.setInboundAuthType(ApplicationConstants.StandardInboundProtocols.OAUTH2);
        inboundAuthenticationRequestConfigs[0] = inboundAuthenticationRequestConfig;
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs);
        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        when(applicationManagementService.getApplicationByResourceId(
                appId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn(serviceProvider);

        OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockOAuthTokenPersistenceFactory);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        when(mockOAuthTokenPersistenceFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        Set<AccessTokenDO> accessTokens = new HashSet<>();
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken(accessToken);
        accessTokenDO.setConsumerKey(clientId);
        accessTokenDO.setScope(new String[]{"default"});

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserId("testUserId");
        authenticatedUser.setUserName(username);
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setTenantDomain("carbon.super");

        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokens.add(accessTokenDO);
        when(mockAccessTokenDAO.getAccessTokens(anyString(),
                any(AuthenticatedUser.class), nullable(String.class), anyBoolean())).thenReturn(accessTokens);

        when(OAuth2Util.buildCacheKeyStringForTokenWithUserIdOrgId(any(), any(), any(), any(), any(),
                any())).thenReturn("someCacheKey");

        idpManagementUtil.when(() -> IdPManagementUtil.getPreserveCurrentSessionAtPasswordUpdate(anyString()))
                .thenReturn(false);

        try (MockedStatic<AccessTokenEventUtil> mockedEventUtil = mockStatic(AccessTokenEventUtil.class)) {

            mockedEventUtil
                    .when(() -> AccessTokenEventUtil.publishTokenRevokeEvent(anySet(), any(AuthenticatedUser.class)))
                    .thenAnswer(invocation -> null);

            boolean result = OAuthUtil.revokeTokens(username, userStoreManager, roleId);
            verify(mockAccessTokenDAO, times(1)).revokeAccessTokens(any(), anyBoolean());
            assertTrue(result, "Token revocation failed.");
        }
    }

    @Test
    public void testRevokeTokensForOrganizationAudienceRoles() throws Exception {

        String username = "testUser";
        String roleId = "testRoleId";
        String roleName = "testRole";
        String appId = "testAppId";
        String clientId = "testClientId";
        String accessToken = "testAccessToken";

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        when(userStoreManager.getTenantId()).thenReturn(-1234);
        when(userStoreManager.getRealmConfiguration()).thenReturn(mock(RealmConfiguration.class));
        when(userStoreManager.getRealmConfiguration().getUserStoreProperty(anyString())).thenReturn("PRIMARY");

        when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(false);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(-1234);

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo();
        roleBasicInfo.setId(roleId);
        roleBasicInfo.setAudience(RoleConstants.ORGANIZATION);
        roleBasicInfo.setAudienceId(appId);
        roleBasicInfo.setName(roleName);
        when(roleManagementService.getRoleBasicInfoById(roleId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(roleBasicInfo);

        ServiceProvider serviceProvider = new ServiceProvider();
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        InboundAuthenticationRequestConfig[] inboundAuthenticationRequestConfigs =
                new InboundAuthenticationRequestConfig[1];
        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig =
                new InboundAuthenticationRequestConfig();
        inboundAuthenticationRequestConfig.setInboundAuthKey(clientId);
        inboundAuthenticationRequestConfig.setInboundAuthType(ApplicationConstants.StandardInboundProtocols.OAUTH2);
        inboundAuthenticationRequestConfigs[0] = inboundAuthenticationRequestConfig;
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs);
        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        lenient().when(applicationManagementService.getApplicationByResourceId(
                appId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn(serviceProvider);
        when(applicationManagementService.getApplicationResourceIDByInboundKey(anyString(), anyString(), anyString())).
                thenReturn(appId);
        when(applicationManagementService.getAllowedAudienceForRoleAssociation(anyString(), anyString())).
                thenReturn(RoleConstants.ORGANIZATION);
        OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockOAuthTokenPersistenceFactory);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        when(mockOAuthTokenPersistenceFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        Set<AccessTokenDO> accessTokens = new HashSet<>();
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken(accessToken);
        accessTokenDO.setConsumerKey(clientId);
        accessTokenDO.setScope(new String[]{"default"});

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserId("testUserId");
        authenticatedUser.setUserName(username);
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setTenantDomain("carbon.super");
        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokens.add(accessTokenDO);
        when(mockAccessTokenDAO.getAccessTokens(anyString(),
                any(AuthenticatedUser.class), nullable(String.class), anyBoolean())).thenReturn(accessTokens);

        when(mockOAuthTokenPersistenceFactory.getTokenManagementDAO()).thenReturn(tokenManagementDAO);
        Set<String> clientIds = new HashSet<>();
        clientIds.add(clientId);
        when(tokenManagementDAO.getAllTimeAuthorizedClientIds(any())).thenReturn(clientIds);

        when(OAuth2Util.buildCacheKeyStringForTokenWithUserIdOrgId(any(), any(), any(), any(), any(),
                any())).thenReturn("someCacheKey");

        idpManagementUtil.when(() -> IdPManagementUtil.getPreserveCurrentSessionAtPasswordUpdate(anyString()))
                .thenReturn(false);

        try (MockedStatic<AccessTokenEventUtil> mockedEventUtil = mockStatic(AccessTokenEventUtil.class)) {

            mockedEventUtil
                    .when(() -> AccessTokenEventUtil.publishTokenRevokeEvent(anySet(), any(AuthenticatedUser.class)))
                    .thenAnswer(invocation -> null);

            boolean result = OAuthUtil.revokeTokens(username, userStoreManager, roleId);
            verify(mockAccessTokenDAO, times(1)).revokeAccessTokens(any(), anyBoolean());
            assertTrue(result, "Token revocation failed.");
        }
    }

    @DataProvider(name = "authenticatedSharedUserFlowDataProvider")
    public Object[][] authenticatedSharedUserFlowDataProvider() {

        return new Object[][]{
                {false, true, false},   // Shared User Flow
                {true, true, false},    // SSO Login User Shared Flow
                {false, false, false},  // No user association found
                {false, true, true}     // Throws UserStoreException
        };
    }

    @Test(dataProvider = "authenticatedSharedUserFlowDataProvider")
    public void testAuthenticatedUserInSharedUserFlow(boolean isSSOLoginUser, boolean isUserAssociationFound,
                                                      boolean shouldThrowUserStoreException) throws Exception {

        try (MockedStatic<UserCoreUtil> userCoreUtil = mockStatic(UserCoreUtil.class)) {

            UniqueIDJDBCUserStoreManager userStoreManager = Mockito.spy(
                    new UniqueIDJDBCUserStoreManager(new RealmConfiguration(), 1));

            org.wso2.carbon.user.core.common.User mockUser = Mockito.mock(org.wso2.carbon.user.core.common.User.class);
            doReturn(mockUser).when(userStoreManager).getUser(any(), eq(null));

            Map<String, String> claimsMap = new HashMap<>();
            claimsMap.put(MANAGED_ORG_CLAIM_URI, SAMPLE_ID);
            doReturn(claimsMap).when(userStoreManager)
                    .getUserClaimValuesWithID(null, new String[]{MANAGED_ORG_CLAIM_URI}, null);

            if (isSSOLoginUser) {
                when(organizationManager.isPrimaryOrganization(anyString())).thenReturn(false);
            } else {
                when(organizationManager.isPrimaryOrganization(anyString())).thenReturn(true);
            }
            when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(true);
            when(UserCoreUtil.removeDomainFromName(null)).thenReturn(CARBON_TENANT_DOMAIN);

            if (isUserAssociationFound) {
                UserAssociation userAssociation = new UserAssociation();
                userAssociation.setAssociatedUserId(SAMPLE_ID);
                when(organizationUserSharingService.getUserAssociation(null, null)).thenReturn(userAssociation);
            }
            if (shouldThrowUserStoreException) {
                when(realmService.getTenantUserRealm(anyInt())).thenThrow(new UserStoreException());
            } else {
                UserRealm userRealm = mock(UserRealm.class);
                lenient().when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
                lenient().when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);

                OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory =
                        mock(OAuthTokenPersistenceFactory.class);
                when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockOAuthTokenPersistenceFactory);
                when(mockOAuthTokenPersistenceFactory.getTokenManagementDAO()).thenReturn(tokenManagementDAO);
            }

            idpManagementUtil.when(() -> IdPManagementUtil.getPreserveCurrentSessionAtPasswordUpdate(anyString()))
                    .thenReturn(false);

            if (isSSOLoginUser || !isUserAssociationFound) {
                boolean result = OAuthUtil.revokeTokens(null, userStoreManager, null);
                assertTrue(result);
                verify(mockUser, never()).getUserStoreDomain();
            } else if (shouldThrowUserStoreException) {
                try {
                    OAuthUtil.revokeTokens(null, userStoreManager, null);
                    fail();
                } catch (UserStoreException e) {
                    assertTrue(e.getMessage().contains("Failed to retrieve the user store domain"),
                            "Unexpected exception message: " + e.getMessage());
                }
            } else {
                boolean result = OAuthUtil.revokeTokens(null, userStoreManager, null);
                assertTrue(result);
                verify(mockUser, times(1)).getUserStoreDomain();
            }
        }
    }

    @Test
    public void testRevokeAuthzCodes() throws Exception {

        UserStoreManager userStoreManager = mock(UserStoreManager.class);

        // Create a real instance of AuthorizationCodeDAO and spy on it
        AuthorizationCodeDAO authorizationCodeDAO = Mockito.spy(new AuthorizationCodeDAOImpl());

        when(userStoreManager.getTenantId()).thenReturn(-1234);
        when(userStoreManager.getRealmConfiguration()).thenReturn(mock(RealmConfiguration.class));

        OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockOAuthTokenPersistenceFactory);
        when(mockOAuthTokenPersistenceFactory.getAuthorizationCodeDAO()).thenReturn(authorizationCodeDAO);

        List<AuthzCodeDO> authorizationCodes = new ArrayList<>();
        AuthzCodeDO mockAuthzCodeDO = mock(AuthzCodeDO.class);
        when(mockAuthzCodeDO.getConsumerKey()).thenReturn("consumer-key");
        when(mockAuthzCodeDO.getAuthorizationCode()).thenReturn("auth-code");
        when(mockAuthzCodeDO.getAuthzCodeId()).thenReturn("auth-code-id");

        authorizationCodes.add(mockAuthzCodeDO);

        // Mock the getAuthorizationCodesDataByUser method to return the list of authorization codes
        Mockito.doReturn(authorizationCodes).when(authorizationCodeDAO)
                .getAuthorizationCodesDataByUser(any(AuthenticatedUser.class));

        when(OAuth2Util.buildCacheKeyStringForAuthzCode(anyString(), anyString())).thenReturn("testAuthzCode");

        Connection connection = mock(Connection.class);
        PreparedStatement preparedStatement = mock(PreparedStatement.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);

        AuthorizationGrantCache mockAuthorizationGrantCache = mock(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(mockAuthorizationGrantCache);

        boolean result = OAuthUtil.revokeAuthzCodes("testUser", userStoreManager);
        // Verify the result
        assertTrue(result, "Authorization code revocation failed.");
    }

    @Test
    public void testRemoveAuthzGrantCacheForUser_WithoutDomainInUsername() throws Exception {

        String userName = "testUser";
        String userStoreDomain = "PRIMARY";
        String tenantDomain = "carbon.super";
        int tenantId = -1234;

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.getTenantId()).thenReturn(tenantId);

        OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockFactory);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        AuthorizationCodeDAO mockAuthorizationCodeDAO = mock(AuthorizationCodeDAO.class);
        when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        when(mockFactory.getAuthorizationCodeDAO()).thenReturn(mockAuthorizationCodeDAO);

        AccessTokenDO accessTokenDO = mock(AccessTokenDO.class);
        when(accessTokenDO.getGrantType()).thenReturn("authorization_code");
        when(accessTokenDO.getAccessToken()).thenReturn("accessToken");
        when(accessTokenDO.getTokenId()).thenReturn("tokenId");

        AuthzCodeDO authzCodeDO = mock(AuthzCodeDO.class);
        when(authzCodeDO.getAuthorizationCode()).thenReturn("authCode");
        when(authzCodeDO.getAuthzCodeId()).thenReturn("authzCodeId");

        when(mockAccessTokenDAO.getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean()))
                .thenReturn(new HashSet<>(Collections.singletonList(accessTokenDO)))
                .thenReturn(new HashSet<>());
        when(mockAuthorizationCodeDAO.getAuthorizationCodesByUserForOpenidScope(any(AuthenticatedUser.class)))
                .thenReturn(new ArrayList<>(Collections.singletonList(authzCodeDO)))
                .thenReturn(new ArrayList<>());

        AuthorizationGrantCache mockAuthorizationGrantCache = mock(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(mockAuthorizationGrantCache);
        when(OrganizationManagementUtil.isOrganization(tenantDomain)).thenReturn(false);

        try (MockedStatic<UserCoreUtil> mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
             MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            when(UserCoreUtil.getDomainName(realmConfiguration)).thenReturn(userStoreDomain);
            when(IdentityTenantUtil.getTenantDomain(tenantId)).thenReturn(tenantDomain);
            when(IdentityUtil.addDomainToName(userName, userStoreDomain)).thenReturn(userStoreDomain + "/" + userName);

            OAuthUtil.removeAuthzGrantCacheForUser(userName, userStoreManager);

            // Tokens and codes should be fetched twice: once with plain username, once with domain-qualified username.
            verify(mockAccessTokenDAO, times(2))
                    .getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean());
            verify(mockAuthorizationCodeDAO, times(2))
                    .getAuthorizationCodesByUserForOpenidScope(any(AuthenticatedUser.class));
            // Cache should be cleared for the retrieved token and code.
            verify(mockAuthorizationGrantCache)
                    .clearCacheEntryByTokenId(any(), eq("tokenId"), isNull());
            verify(mockAuthorizationGrantCache)
                    .clearCacheEntryByCodeId(any(), eq("authzCodeId"), isNull());
        }
    }

    @Test
    public void testRemoveAuthzGrantCacheForUser_WithDomainInUsername() throws Exception {

        String userName = "PRIMARY/testUser";
        String userStoreDomain = "PRIMARY";
        String tenantDomain = "carbon.super";
        int tenantId = -1234;

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.getTenantId()).thenReturn(tenantId);

        OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockFactory);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        AuthorizationCodeDAO mockAuthorizationCodeDAO = mock(AuthorizationCodeDAO.class);
        when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        when(mockFactory.getAuthorizationCodeDAO()).thenReturn(mockAuthorizationCodeDAO);

        AccessTokenDO accessTokenDO = mock(AccessTokenDO.class);
        when(accessTokenDO.getGrantType()).thenReturn("authorization_code");
        when(accessTokenDO.getAccessToken()).thenReturn("accessToken");
        when(accessTokenDO.getTokenId()).thenReturn("tokenId");

        AuthzCodeDO authzCodeDO = mock(AuthzCodeDO.class);
        when(authzCodeDO.getAuthorizationCode()).thenReturn("authCode");
        when(authzCodeDO.getAuthzCodeId()).thenReturn("authzCodeId");

        when(mockAccessTokenDAO.getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean()))
                .thenReturn(new HashSet<>(Collections.singletonList(accessTokenDO)));
        when(mockAuthorizationCodeDAO.getAuthorizationCodesByUserForOpenidScope(any(AuthenticatedUser.class)))
                .thenReturn(new ArrayList<>(Collections.singletonList(authzCodeDO)));

        AuthorizationGrantCache mockAuthorizationGrantCache = mock(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(mockAuthorizationGrantCache);
        when(OrganizationManagementUtil.isOrganization(tenantDomain)).thenReturn(false);

        try (MockedStatic<UserCoreUtil> mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
             MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            when(UserCoreUtil.getDomainName(realmConfiguration)).thenReturn(userStoreDomain);
            when(IdentityTenantUtil.getTenantDomain(tenantId)).thenReturn(tenantDomain);

            OAuthUtil.removeAuthzGrantCacheForUser(userName, userStoreManager);

            // Tokens and codes should be fetched only once since username already contains the domain separator.
            verify(mockAccessTokenDAO, times(1))
                    .getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean());
            verify(mockAuthorizationCodeDAO, times(1))
                    .getAuthorizationCodesByUserForOpenidScope(any(AuthenticatedUser.class));
            verify(mockAuthorizationGrantCache)
                    .clearCacheEntryByTokenId(any(), eq("tokenId"), isNull());
            verify(mockAuthorizationGrantCache)
                    .clearCacheEntryByCodeId(any(), eq("authzCodeId"), isNull());
        }
    }

    @Test
    public void testRemoveAuthzGrantCacheForUser_OrgUser() throws Exception {

        String userName = "testUser";
        String userStoreDomain = "PRIMARY";
        String tenantDomain = "org.carbon.super";
        int tenantId = 1;
        String userId = "testUserId";
        String accessingOrg = "accessingOrgId";
        String primaryOrgId = "primaryOrgId";
        String rootTenantDomain = "carbon.super";

        AbstractUserStoreManager abstractUserStoreManager = mock(AbstractUserStoreManager.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(abstractUserStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(abstractUserStoreManager.getTenantId()).thenReturn(tenantId);

        org.wso2.carbon.user.core.common.User user = mock(org.wso2.carbon.user.core.common.User.class);
        when(user.getUserID()).thenReturn(userId);
        when(abstractUserStoreManager.getUser(null, userName)).thenReturn(user);

        OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockFactory);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        AuthorizationCodeDAO mockAuthorizationCodeDAO = mock(AuthorizationCodeDAO.class);
        when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        when(mockFactory.getAuthorizationCodeDAO()).thenReturn(mockAuthorizationCodeDAO);

        when(mockAccessTokenDAO.getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean()))
                .thenReturn(new HashSet<>())
                .thenReturn(new HashSet<>())
                .thenReturn(new HashSet<>());
        when(mockAuthorizationCodeDAO.getAuthorizationCodesByUserForOpenidScope(any(AuthenticatedUser.class)))
                .thenReturn(new ArrayList<>())
                .thenReturn(new ArrayList<>())
                .thenReturn(new ArrayList<>());

        AuthorizationGrantCache mockAuthorizationGrantCache = mock(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(mockAuthorizationGrantCache);
        when(OrganizationManagementUtil.isOrganization(tenantDomain)).thenReturn(true);
        when(organizationManager.resolveOrganizationId(tenantDomain)).thenReturn(accessingOrg);
        when(organizationManager.getPrimaryOrganizationId(accessingOrg)).thenReturn(primaryOrgId);
        when(organizationManager.resolveTenantDomain(primaryOrgId)).thenReturn(rootTenantDomain);

        try (MockedStatic<UserCoreUtil> mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
             MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            when(UserCoreUtil.getDomainName(realmConfiguration)).thenReturn(userStoreDomain);
            when(IdentityTenantUtil.getTenantDomain(tenantId)).thenReturn(tenantDomain);
            when(IdentityUtil.addDomainToName(userName, userStoreDomain)).thenReturn(userStoreDomain + "/" + userName);

            OAuthUtil.removeAuthzGrantCacheForUser(userName, abstractUserStoreManager);

            // For org users: 2 fetches for regular user (plain + domain-qualified) + 1 fetch for federated user.
            verify(mockAccessTokenDAO, times(3))
                    .getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean());
            verify(mockAuthorizationCodeDAO, times(3))
                    .getAuthorizationCodesByUserForOpenidScope(any(AuthenticatedUser.class));
        }
    }

    @Test
    public void testRemoveAuthzGrantCacheForUser_WithIdentityOAuth2Exception() throws Exception {

        String userName = "testUser";
        String userStoreDomain = "PRIMARY";
        String tenantDomain = "carbon.super";
        int tenantId = -1234;

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.getTenantId()).thenReturn(tenantId);

        OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockFactory);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        when(mockAccessTokenDAO.getAccessTokensByUserForOpenidScope(any(AuthenticatedUser.class), anyBoolean()))
                .thenThrow(new IdentityOAuth2Exception("Test DAO error"));

        try (MockedStatic<UserCoreUtil> mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
             MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            when(UserCoreUtil.getDomainName(realmConfiguration)).thenReturn(userStoreDomain);
            when(IdentityTenantUtil.getTenantDomain(tenantId)).thenReturn(tenantDomain);

            // Should not throw; IdentityOAuth2Exception is caught and logged internally.
            OAuthUtil.removeAuthzGrantCacheForUser(userName, userStoreManager);
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_WhenAllowedScopesIsEmpty() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.emptyList());

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken("testAccessToken");
            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);

            OAuthUtil.clearOAuthCacheUsingPersistedScopes("tokenBindingRef",
             accessTokenDO, revokeRequestDTO);

            verify(mockAccessTokenDAO, never()).getAccessToken(anyString(), anyBoolean());
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_WhenAccessTokenIsBlank() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.singletonList("openid"));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);

            // Access token is not set — defaults to null (blank).
            AccessTokenDO accessTokenDO = new AccessTokenDO();
            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);

            OAuthUtil.clearOAuthCacheUsingPersistedScopes("tokenBindingRef",
             accessTokenDO, revokeRequestDTO);

            verify(mockAccessTokenDAO, never()).getAccessToken(anyString(), anyBoolean());
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_WhenDbTokenIsNull() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuthUtil> mockedOAuthUtil = mockStatic(OAuthUtil.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.singletonList("openid"));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
            when(mockAccessTokenDAO.getAccessToken("testAccessToken", true)).thenReturn(null);

            mockedOAuthUtil.when(() -> OAuthUtil.clearOAuthCacheUsingPersistedScopes(
                    anyString(), any(AccessTokenDO.class), any(OAuthRevocationRequestDTO.class)))
                    .thenCallRealMethod();

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken("testAccessToken");
            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);

            OAuthUtil.clearOAuthCacheUsingPersistedScopes("tokenBindingRef", accessTokenDO, revokeRequestDTO);

            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString(), anyString()), never());
            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString()), never());
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_WhenDbTokenScopeIsNull() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuthUtil> mockedOAuthUtil = mockStatic(OAuthUtil.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.singletonList("openid"));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);

            AccessTokenDO dbTokenDO = new AccessTokenDO();
            dbTokenDO.setScope(null);
            when(mockAccessTokenDAO.getAccessToken("testAccessToken",
             true)).thenReturn(dbTokenDO);

            mockedOAuthUtil.when(() -> OAuthUtil.clearOAuthCacheUsingPersistedScopes(
                    anyString(), any(AccessTokenDO.class), any(OAuthRevocationRequestDTO.class)))
                    .thenCallRealMethod();

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken("testAccessToken");
            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);

            OAuthUtil.clearOAuthCacheUsingPersistedScopes("tokenBindingRef",
             accessTokenDO, revokeRequestDTO);

            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString(), anyString()), never());
            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString()), never());
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_WhenDbTokenScopeIsEmpty() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuthUtil> mockedOAuthUtil = mockStatic(OAuthUtil.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.singletonList("openid"));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);

            AccessTokenDO dbTokenDO = new AccessTokenDO();
            dbTokenDO.setScope(new String[0]);
            when(mockAccessTokenDAO.getAccessToken("testAccessToken",
             true)).thenReturn(dbTokenDO);

            mockedOAuthUtil.when(() -> OAuthUtil.clearOAuthCacheUsingPersistedScopes(
                    anyString(), any(AccessTokenDO.class), any(OAuthRevocationRequestDTO.class)))
                    .thenCallRealMethod();

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken("testAccessToken");
            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);

            OAuthUtil.clearOAuthCacheUsingPersistedScopes("tokenBindingRef",
             accessTokenDO, revokeRequestDTO);

            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString(), anyString()), never());
            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString()), never());
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_ClearsCacheWithPersistedScopes() throws Exception {

        String tokenBindingReference = "tokenBindingRef";
        String accessToken = "testAccessToken";
        String consumerKey = "testConsumerKey";
        String[] dbScopes = {"scope1", "scope2"};
        String dbScopeString = "scope1 scope2";

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuthUtil> mockedOAuthUtil = mockStatic(OAuthUtil.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.singletonList("scope1"));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);

            AccessTokenDO dbTokenDO = new AccessTokenDO();
            dbTokenDO.setScope(dbScopes);
            when(mockAccessTokenDAO.getAccessToken(accessToken, true)).thenReturn(dbTokenDO);

            oAuth2Util.when(() -> OAuth2Util.buildScopeString(dbScopes)).thenReturn(dbScopeString);

            mockedOAuthUtil.when(() -> OAuthUtil.clearOAuthCacheUsingPersistedScopes(
                    anyString(), any(AccessTokenDO.class), any(OAuthRevocationRequestDTO.class)))
                    .thenCallRealMethod();

            AuthenticatedUser authzUser = mock(AuthenticatedUser.class);
            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken(accessToken);
            accessTokenDO.setAuthzUser(authzUser);

            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);
            when(revokeRequestDTO.getConsumerKey()).thenReturn(consumerKey);

            OAuthUtil.clearOAuthCacheUsingPersistedScopes(tokenBindingReference, accessTokenDO, revokeRequestDTO);

            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    eq(consumerKey), eq(authzUser), eq(dbScopeString), eq(tokenBindingReference)), times(1));
            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    eq(consumerKey), eq(authzUser), eq(dbScopeString)), times(1));
        }
    }

    @Test
    public void testClearOAuthCacheUsingPersistedScopes_WhenDaoThrowsException() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigStatic =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuthUtil> mockedOAuthUtil = mockStatic(OAuthUtil.class)) {
            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            oAuthServerConfigStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);
            when(mockServerConfig.getAllowedScopes()).thenReturn(Collections.singletonList("openid"));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
            when(mockAccessTokenDAO.getAccessToken(anyString(), anyBoolean()))
                    .thenThrow(new IdentityOAuth2Exception("DAO error"));

            mockedOAuthUtil.when(() -> OAuthUtil.clearOAuthCacheUsingPersistedScopes(
                    anyString(), any(AccessTokenDO.class), any(OAuthRevocationRequestDTO.class)))
                    .thenCallRealMethod();

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAccessToken("testAccessToken");
            OAuthRevocationRequestDTO revokeRequestDTO = mock(OAuthRevocationRequestDTO.class);
            when(revokeRequestDTO.getConsumerKey()).thenReturn("testConsumerKey");

            // Exception should be caught and logged internally, not propagated.
            OAuthUtil.clearOAuthCacheUsingPersistedScopes("tokenBindingRef",
             accessTokenDO, revokeRequestDTO);

            mockedOAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(
                    anyString(), any(AuthenticatedUser.class), anyString(), anyString()), never());
        }
    }

    private OAuthCache getOAuthCache(OAuthCacheKey oAuthCacheKey) {

        // Add some value to OAuthCache.
        DummyOAuthCacheEntry dummyOAuthCacheEntry = new DummyOAuthCacheEntry("identifier");
        OAuthCache oAuthCache = OAuthCache.getInstance();
        oAuthCache.addToCache(oAuthCacheKey, dummyOAuthCacheEntry);
        return oAuthCache;
    }

    private static class DummyOAuthCacheEntry extends CacheEntry {

        private String identifier;

        DummyOAuthCacheEntry(String identifier) {
            this.identifier = identifier;
        }

        public String getIdentifier() {
            return identifier;
        }
    }
}
