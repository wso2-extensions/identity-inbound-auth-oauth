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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtSystemConfig;
import org.wso2.carbon.identity.application.mgt.dao.ApplicationDAO;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.common.testng.WithRegistry;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.registry.core.config.RegistryContext;
import org.wso2.carbon.registry.core.internal.RegistryDataHolder;
import org.wso2.carbon.registry.core.jdbc.EmbeddedRegistryService;
import org.wso2.carbon.registry.core.jdbc.dataaccess.JDBCDataAccessManager;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.util.HashSet;
import java.util.Set;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Test class for OAuthApplicationMgtListener test cases.
 */
@WithCarbonHome
@WithH2Database(files = { "dbScripts/identity.sql", "dbScripts/h2.sql", "dbScripts/registry.sql" })
@WithRealmService(initUserStoreManager = true,
                  injectToSingletons = { ApplicationManagementServiceComponentHolder.class, OSGiDataHolder.class,
                          RegistryDataHolder.class })
@WithRegistry (injectToSingletons = {ApplicationManagementServiceComponentHolder.class})
public class OAuthApplicationMgtListenerTest {

    private static final String OAUTH2 = "oauth2";
    private static final String OAUTH = "oauth";
    private static final String OAUTH_CONSUMER_SECRET = "oauthConsumerSecret";
    private static final String SAAS_PROPERTY = "saasProperty";

    private String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    private String spName = "testOauthApp";
    private String userName = "randomUser";

    private OAuthApplicationMgtListener oAuthApplicationMgtListener;
    private ApplicationManagementService applicationManagementService;
    private RegistryService registryService;

    @BeforeMethod
    public void setUp() throws Exception {
        oAuthApplicationMgtListener = new OAuthApplicationMgtListener();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
        applicationManagementService = ApplicationManagementService.getInstance();
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);

        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        OAuthServerConfiguration.getInstance().getPersistenceProcessor();

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(spName);

        applicationManagementService.createApplication(serviceProvider, tenantDomain, userName);
    }

    @AfterMethod
    protected void tearDown() throws IdentityApplicationManagementException {
        ApplicationDAO applicationDAO = ApplicationMgtSystemConfig.getInstance().getApplicationDAO();
        applicationDAO.deleteApplication(spName);
    }

    @Test
    public void testGetDefaultOrderId() {

        int result = oAuthApplicationMgtListener.getDefaultOrderId();
        assertEquals(result, 11, "Default order ID should be 11.");
    }

    @DataProvider(name = "GetSPConfigData")
    public Object[][] SPConfigData() {

        return new Object[][] { { true, true, OAUTH2, OAUTH_CONSUMER_SECRET },
                { true, true, OAUTH, OAUTH_CONSUMER_SECRET }, { true, false, null, null },
                { true, true, "otherAuthType", "otherPropName" }, { true, true, OAUTH2, "otherPropName" },
                { false, false, null, null } };
    }

    @Test(dataProvider = "GetSPConfigData")
    public void testDoPreUpdateApplication(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
            String propName) throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);

        serviceProvider.setApplicationID(1);
        serviceProvider.setSaasApp(true);
        serviceProvider.setApplicationName(spName);
        ApplicationDAO appDAO = ApplicationMgtSystemConfig.getInstance().getApplicationDAO();
        appDAO.deleteApplication(spName);
        int createdAppId = appDAO.createApplication(serviceProvider, tenantDomain);
        serviceProvider.setApplicationID(createdAppId);

        Boolean result = oAuthApplicationMgtListener.doPreUpdateApplication(serviceProvider, tenantDomain, userName);
        assertTrue(result, "Pre-update application failed.");
    }

    @Test(dataProvider = "GetSPConfigData")
    public void testDoPostGetServiceProvider(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
            String propName) throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);
        Boolean result = oAuthApplicationMgtListener.doPostGetServiceProvider(serviceProvider, spName, tenantDomain);
        assertTrue(result, "Post-get service provider failed.");
    }

    @Test
    public void testDoPostGetServiceProviderWhenSPisNull() throws Exception {

        Boolean result = oAuthApplicationMgtListener.doPostGetServiceProvider(null, spName, tenantDomain);
        assertTrue(result, "Post-get service provider failed.");
    }

    @Test
    public void testDoPostGetServiceProviderByClientId() throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
        Boolean result = oAuthApplicationMgtListener
                .doPostGetServiceProviderByClientId(serviceProvider, "clientId", "clientType", tenantDomain);
        assertTrue(result, "Post-get service provider by client ID failed.");
    }

    @Test
    public void testDoPostCreateApplication() throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
        Boolean result = oAuthApplicationMgtListener.doPostCreateApplication(serviceProvider, tenantDomain, userName);
        assertTrue(result, "Post-create application failed.");
    }

    @DataProvider(name = "GetPostUpdateApplicationData")
    public Object[][] postUpdateApplicationData() {

        return new Object[][] {
                // Test the saas-token revocation and cache entry removal for an oauth application. If saas property
                // was enabled before and disabled with application update, saas-tokens should be revoked.
                { true, true, OAUTH2, OAUTH_CONSUMER_SECRET, true, true },
                // Test the normal flow of an oauth application when cache disabled and saas not enabled before.
                { true, true, OAUTH, OAUTH_CONSUMER_SECRET, false, false },
                // Test addClientSecret() and updateAuthApplication() for other authentication types.
                { true, true, "otherAuthType", "otherPropName", false, false },
                // Test addClientSecret() and for oauth applications with inboundRequestConfig properties without
                // oauthConsumerSecret property.
                { true, true, OAUTH2, "otherPropName", false, false },
                // Test addClientSecret() and updateAuthApplication() for the scenario where inboundAuthenticationConfig
                // is null.
                { false, false, null, null, false, false } };
    }

    @Test(dataProvider = "GetPostUpdateApplicationData")
    public void testDoPostUpdateApplication(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
            String propName, Boolean cacheEnabled, Boolean saasEnabledBefore) throws Exception {

        if (StringUtils.equals(authType, OAUTH2) || StringUtils.equals(authType, OAUTH)) {
            Set<String> accessTokens = new HashSet<>();
            accessTokens.add("accessToken1");
            accessTokens.add("accessToken2");
            accessTokens.add("accessToken3");

            Set<String> authCodes = new HashSet<>();
            authCodes.add("authCode1");
            authCodes.add("authCode2");
        }

        if (saasEnabledBefore) {
            IdentityUtil.threadLocalProperties.get().put(SAAS_PROPERTY, true);
        }

        ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType, propName);
        Boolean result = oAuthApplicationMgtListener.doPostUpdateApplication(serviceProvider, tenantDomain, userName);
        assertTrue(result, "Post-update application failed.");
    }

    @Test
    public void testDoPostGetApplicationExcludingFileBasedSPs() throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, true, true, OAUTH2, OAUTH_CONSUMER_SECRET);
        Boolean result = oAuthApplicationMgtListener
                .doPostGetApplicationExcludingFileBasedSPs(serviceProvider, spName, tenantDomain);
        assertTrue(result, "Post-get application excluding file based service providers failed.");
    }

    @Test
    public void doPreDeleteApplication() throws Exception {

        ServiceProvider serviceProvider = createServiceProvider(1, false, false, "otherAuthType",
                OAUTH_CONSUMER_SECRET);

        Boolean result = oAuthApplicationMgtListener.doPreDeleteApplication(spName, tenantDomain, userName);
        assertTrue(result, "Post-delete application failed.");
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
