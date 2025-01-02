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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.TestConstants.LOCAL_IDP;

/**
 * Unit tests for OAuthUtil class.
 */
@WithCarbonHome
@WithRealmService
public class OAuthUtilTest {

    @Mock
    RoleManagementService roleManagementService;
    @Mock
    ApplicationManagementService applicationManagementService;

    private AutoCloseable closeable;
    private MockedStatic<OrganizationManagementUtil> organizationManagementUtil;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactory;

    @BeforeMethod
    public void setUp() throws Exception {

        organizationManagementUtil = mockStatic(OrganizationManagementUtil.class);
        oAuthComponentServiceHolder = mockStatic(OAuthComponentServiceHolder.class);
        oAuth2Util = mockStatic(OAuth2Util.class);
        oAuthTokenPersistenceFactory = mockStatic(OAuthTokenPersistenceFactory.class);
        closeable = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        organizationManagementUtil.close();
        oAuthComponentServiceHolder.close();
        oAuth2Util.close();
        oAuthTokenPersistenceFactory.close();
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

        OAuthComponentServiceHolder mockOAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockOAuthComponentServiceHolder);

        when(mockOAuthComponentServiceHolder.getRoleV2ManagementService()).thenReturn(roleManagementService);
        RoleBasicInfo roleBasicInfo = new RoleBasicInfo();
        roleBasicInfo.setId(roleId);
        roleBasicInfo.setAudience(RoleConstants.APPLICATION);
        roleBasicInfo.setAudienceId(appId);
        roleBasicInfo.setName(roleName);
        when(roleManagementService.getRoleBasicInfoById(roleId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(roleBasicInfo);

        when(mockOAuthComponentServiceHolder.getApplicationManagementService())
                .thenReturn(applicationManagementService);
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
        accessTokenDO.setAuthzUser(new AuthenticatedUser());
        accessTokens.add(accessTokenDO);
        when(mockAccessTokenDAO.getAccessTokens(anyString(),
                any(AuthenticatedUser.class), nullable(String.class), anyBoolean())).thenReturn(accessTokens);

        boolean result = OAuthUtil.revokeTokens(username, userStoreManager, roleId);
        assertTrue(result, "Token revocation failed.");
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
