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

package org.wso2.carbon.identity.oauth2.internal;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.TestOAuthDAOBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;

import java.sql.Connection;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Test class for OAuthApplicationMgtListener test cases.
 */
public class OAuthApplicationMgtListenerTest extends TestOAuthDAOBase {

    private static final String DB_NAME = "testDB";
    private static final String OAUTH2 = "oauth2";
    private static final String OAUTH = "oauth";
    private static final String OAUTH_CONSUMER_SECRET = "oauthConsumerSecret";
    private static final String SAAS_PROPERTY = "saasProperty";

    private String tenantDomain = "carbon.super";
    private String spName = "testOauthApp";
    private String userName = "randomUser";

    private OAuthApplicationMgtListener oAuthApplicationMgtListener;

    @Mock
    private ApplicationManagementService mockAppMgtService;

    @Mock
    private OAuthServerConfiguration mockOauthServicerConfig;

    @Mock
    private AuthorizationGrantCache mockAuthorizationGrantCache;

    @Mock
    private AuthorizationGrantCacheEntry mockAuthorizationGrantCacheEntry;

    @Mock
    private OAuthCache mockOauthCache;

    @Mock
    private CacheEntry mockCacheEntry;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<AuthorizationGrantCache> authorizationGrantCache;
    private MockedStatic<OAuthCache> oAuthCache;

    @BeforeClass
    public void setUp() throws Exception {

        // Initialize in-memory H2 DB.
        initiateH2Base(DB_NAME, getFilePath("identity.sql"));
        oAuthApplicationMgtListener = new OAuthApplicationMgtListener();
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {

        initMocks(this);

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        oAuth2ServiceComponentHolder = mockStatic(OAuth2ServiceComponentHolder.class);
        oAuth2ServiceComponentHolder.when(
                OAuth2ServiceComponentHolder::getApplicationMgtService).thenReturn(mockAppMgtService);

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServicerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockOauthServicerConfig.getPersistenceProcessor()).thenReturn(processor);

        authorizationGrantCache = mockStatic(AuthorizationGrantCache.class);
        authorizationGrantCache.when(AuthorizationGrantCache::getInstance).thenReturn(mockAuthorizationGrantCache);

        oAuthCache = mockStatic(OAuthCache.class);
        oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOauthCache);
    }

    @AfterMethod
    public void tearDownAfterMethod() {

        identityDatabaseUtil.close();
        oAuth2ServiceComponentHolder.close();
        oAuthServerConfiguration.close();
        authorizationGrantCache.close();
        oAuthCache.close();
    }

    @Test
    public void testGetDefaultOrderId() {

        int result = oAuthApplicationMgtListener.getDefaultOrderId();
        assertEquals(result, 11, "Default order ID should be 11.");
    }

    @DataProvider(name = "GetSPConfigData")
    public Object[][] spConfigData() {

        return new Object[][]{
                {true, true, OAUTH2, OAUTH_CONSUMER_SECRET},
                {true, true, OAUTH, OAUTH_CONSUMER_SECRET},
                {true, false, null, null},
                {true, true, "otherAuthType", "otherPropName"},
                {true, true, OAUTH2, "otherPropName"},
                {false, false, null, null}
        };
    }

    @Test(dataProvider = "GetSPConfigData")
    public void testDoPreUpdateApplication(boolean hasAuthConfig, boolean hasRequestConfig, String authType,
                                           String propName) throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);

        ServiceProvider persistedServiceProvider = new ServiceProvider();
        serviceProvider.setApplicationID(1);
        serviceProvider.setSaasApp(true);
        when(mockAppMgtService.getServiceProvider(serviceProvider.getApplicationID()))
                .thenReturn(persistedServiceProvider);

        boolean result = oAuthApplicationMgtListener.doPreUpdateApplication(serviceProvider, tenantDomain, userName);
        assertTrue(result, "Pre-update application failed.");
    }

    @Test(dataProvider = "GetSPConfigData")
    public void testDoPostGetServiceProvider(boolean hasAuthConfig, boolean hasRequestConfig, String authType,
                                             String propName) throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            ServiceProvider serviceProvider =
                    createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);
            boolean result =
                    oAuthApplicationMgtListener.doPostGetServiceProvider(serviceProvider, spName, tenantDomain);
            assertTrue(result, "Post-get service provider failed.");
        }
    }

    @Test
    public void testDoPostGetServiceProviderWhenSPisNull() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            boolean result = oAuthApplicationMgtListener.doPostGetServiceProvider(null, spName, tenantDomain);
            assertTrue(result, "Post-get service provider failed.");
        }
    }

    @Test
    public void testDoPostGetServiceProviderByClientId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
            boolean result = oAuthApplicationMgtListener.doPostGetServiceProviderByClientId(serviceProvider,
                    "clientId", "clientType", tenantDomain);
            assertTrue(result, "Post-get service provider by client ID failed.");
        }
    }

    @Test
    public void testDoPostCreateApplication() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
            boolean result =
                    oAuthApplicationMgtListener.doPostCreateApplication(serviceProvider, tenantDomain, userName);
            assertTrue(result, "Post-create application failed.");
        }
    }

    @DataProvider(name = "GetPostUpdateApplicationData")
    public Object[][] postUpdateApplicationData() {

        return new Object[][]{
                // Test the saas-token revocation and cache entry removal for an oauth application. If saas property
                // was enabled before and disabled with application update, saas-tokens should be revoked.
                {true, true, OAUTH2, OAUTH_CONSUMER_SECRET, true, true},
                // Test the normal flow of an oauth application when cache disabled and saas not enabled before.
                {true, true, OAUTH, OAUTH_CONSUMER_SECRET, false, false},
                // Test addClientSecret() and updateAuthApplication() for other authentication types.
                {true, true, "otherAuthType", "otherPropName", false, false},
                // Test addClientSecret() and for oauth applications with inboundRequestConfig properties without
                // oauthConsumerSecret property.
                {true, true, OAUTH2, "otherPropName", false, false},
                // Test addClientSecret() and updateAuthApplication() for the scenario where inboundAuthenticationConfig
                // is null.
                {false, false, null, null, false, false}
        };
    }

    @Test(dataProvider = "GetPostUpdateApplicationData")
    public void testDoPostUpdateApplication(boolean hasAuthConfig, boolean hasRequestConfig, String authType,
                                            String propName, boolean cacheEnabled, boolean saasEnabledBefore)
            throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);

            if (cacheEnabled) {
                when(mockAuthorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class)))
                        .thenReturn(mockAuthorizationGrantCacheEntry);
                when(mockOauthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(mockCacheEntry);
            }

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

            if (saasEnabledBefore) {
                IdentityUtil.threadLocalProperties.get().put(SAAS_PROPERTY, true);
            }

            System.setProperty(CarbonBaseConstants.CARBON_HOME, "");
            ServiceProvider serviceProvider =
                    createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);
            boolean result =
                    oAuthApplicationMgtListener.doPostUpdateApplication(serviceProvider, tenantDomain, userName);
            assertTrue(result, "Post-update application failed.");
        }
    }

    @Test
    public void testDoPostGetApplicationExcludingFileBasedSPs() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
            boolean result = oAuthApplicationMgtListener
                    .doPostGetApplicationExcludingFileBasedSPs(serviceProvider, spName, tenantDomain);
            assertTrue(result, "Post-get application excluding file based service providers failed.");
        }
    }

    @Test
    public void doPreDeleteApplication() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            ServiceProvider serviceProvider = createServiceProvider(1, false, false, "otherAuthType",
                    OAUTH_CONSUMER_SECRET);
            when(mockAppMgtService.getApplicationExcludingFileBasedSPs(anyString(), anyString()))
                    .thenReturn(serviceProvider);

            boolean result = oAuthApplicationMgtListener.doPreDeleteApplication(spName, tenantDomain, userName);
            assertTrue(result, "Post-delete application failed.");
        }
    }

    /**
     * Create service provider with required configurations.
     *
     * @param appId
     * @param hasAuthConfig
     * @param hasRequestConfig
     * @param authType
     * @param propName
     * @return
     */
    private ServiceProvider createServiceProvider(int appId, boolean hasAuthConfig, boolean hasRequestConfig,
                                                  String authType, String propName) {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationID(appId);

        if (hasAuthConfig) {
            InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
            if (hasRequestConfig) {
                InboundAuthenticationRequestConfig[] requestConfig = new InboundAuthenticationRequestConfig[1];
                requestConfig[0] = new InboundAuthenticationRequestConfig();
                requestConfig[0].setInboundAuthType(authType);
                requestConfig[0].setInboundAuthKey("authKey");
                Property[] properties = new Property[1];
                properties[0] = new Property();
                properties[0].setName(propName);
                requestConfig[0].setProperties(properties);
                inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(requestConfig);
            } else {
                inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(null);
            }
            serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        }
        return serviceProvider;
    }
}
