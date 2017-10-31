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

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterClass;
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
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;

import java.sql.Connection;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Test class for OAuthApplicationMgtListener test cases.
 */
@PrepareForTest({OAuth2ServiceComponentHolder.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class,
        OAuthApplicationMgtListener.class, AuthorizationGrantCache.class, OAuthCache.class, IdentityTenantUtil.class})
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
    private TokenMgtDAO mockTokenMgtDAO;

    @Mock
    private AuthorizationGrantCache mockAuthorizationGrantCache;

    @Mock
    private AuthorizationGrantCacheEntry mockAuthorizationGrantCacheEntry;

    @Mock
    private OAuthCache mockOauthCache;

    @Mock
    private CacheEntry mockCacheEntry;

    @BeforeClass
    public void setUp() throws Exception {

        //initialize in-memory H2 DB.
        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
        oAuthApplicationMgtListener = new OAuthApplicationMgtListener();
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {

        initMocks(this);
        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(mockAppMgtService);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOauthServicerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockOauthServicerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(mockTokenMgtDAO);

        mockStatic(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(mockAuthorizationGrantCache);

        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(mockOauthCache);
    }

    @Test
    public void testGetDefaultOrderId() {

        int result = oAuthApplicationMgtListener.getDefaultOrderId();
        assertEquals(result, 11, "Default order ID should be 11.");
    }

    @DataProvider(name = "GetSPConfigData")
    public Object[][] SPConfigData() {

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
    public void testDoPreUpdateApplication(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
                                           String propName) throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);

        ServiceProvider persistedServiceProvider = new ServiceProvider();
        serviceProvider.setApplicationID(1);
        serviceProvider.setSaasApp(true);
        when(mockAppMgtService.getServiceProvider(serviceProvider.getApplicationID()))
                .thenReturn(persistedServiceProvider);

        Boolean result = oAuthApplicationMgtListener.doPreUpdateApplication(serviceProvider, tenantDomain, userName);
        assertTrue(result, "Pre-update application failed.");
    }

    @Test(dataProvider = "GetSPConfigData")
    public void testDoPostGetServiceProvider(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
                                             String propName) throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            ServiceProvider serviceProvider =
                    createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);
            Boolean result =
                    oAuthApplicationMgtListener.doPostGetServiceProvider(serviceProvider, spName, tenantDomain);
            assertTrue(result, "Post-get service provider failed.");
        }
    }

    @Test
    public void testDoPostGetServiceProviderWhenSPisNull() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            Boolean result = oAuthApplicationMgtListener.doPostGetServiceProvider(null, spName, tenantDomain);
            assertTrue(result, "Post-get service provider failed.");
        }
    }

    @Test
    public void testDoPostGetServiceProviderByClientId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
            Boolean result = oAuthApplicationMgtListener.doPostGetServiceProviderByClientId(serviceProvider,
                    "clientId", "clientType", tenantDomain);
            assertTrue(result, "Post-get service provider by client ID failed.");
        }
    }

    @Test
    public void testDoPostCreateApplication() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
            Boolean result = oAuthApplicationMgtListener.doPostCreateApplication(serviceProvider, tenantDomain, userName);
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
    public void testDoPostUpdateApplication(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
                                            String propName, Boolean cacheEnabled, Boolean saasEnabledBefore)
            throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            if (StringUtils.equals(authType, OAUTH2) || StringUtils.equals(authType, OAUTH)) {
                Set<String> accessTokens = new HashSet<>();
                accessTokens.add("accessToken1");
                accessTokens.add("accessToken2");
                accessTokens.add("accessToken3");

                Set<String> authCodes = new HashSet<>();
                authCodes.add("authCode1");
                authCodes.add("authCode2");
                when(mockTokenMgtDAO.getActiveTokensForConsumerKey(anyString())).thenReturn(accessTokens);
                when(mockTokenMgtDAO.getAuthorizationCodesForConsumerKey(anyString())).thenReturn(authCodes);
            } else {
                when(mockTokenMgtDAO.getActiveTokensForConsumerKey(anyString())).thenReturn(new HashSet<String>());
                when(mockTokenMgtDAO.getActiveAuthorizationCodesForConsumerKey(anyString())).thenReturn(new HashSet<String>());
            }

            if (cacheEnabled) {
                when(mockAuthorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class)))
                        .thenReturn(mockAuthorizationGrantCacheEntry);
                when(mockOauthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(mockCacheEntry);
            }

            mockStatic(IdentityTenantUtil.class);
            when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

            if (saasEnabledBefore) {
                IdentityUtil.threadLocalProperties.get().put(SAAS_PROPERTY, true);
            }

            System.setProperty(CarbonBaseConstants.CARBON_HOME, "");
            ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);
            Boolean result = oAuthApplicationMgtListener.doPostUpdateApplication(serviceProvider, tenantDomain,
                    userName);
            assertTrue(result, "Post-update application failed.");
        }
    }

    @Test
    public void testDoPostGetApplicationExcludingFileBasedSPs() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
            Boolean result = oAuthApplicationMgtListener.doPostGetApplicationExcludingFileBasedSPs(serviceProvider,
                    spName, tenantDomain);
            assertTrue(result, "Post-get application excluding file based service providers failed.");
        }
    }

    @Test
    public void doPreDeleteApplication() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            ServiceProvider serviceProvider = createServiceProvider(1, false, false, "otherAuthType",
                    OAUTH_CONSUMER_SECRET);
            when(mockAppMgtService.getApplicationExcludingFileBasedSPs(anyString(), anyString())).thenReturn(serviceProvider);

            Boolean result = oAuthApplicationMgtListener.doPreDeleteApplication(spName, tenantDomain, userName);
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
    private ServiceProvider createServiceProvider(int appId, Boolean hasAuthConfig, Boolean hasRequestConfig,
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
