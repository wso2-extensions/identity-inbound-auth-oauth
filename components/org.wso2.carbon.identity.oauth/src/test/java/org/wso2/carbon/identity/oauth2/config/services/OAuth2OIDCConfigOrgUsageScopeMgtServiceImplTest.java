/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.config.services;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigOrgUsageScopeMgtClientException;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigOrgUsageScopeMgtServerException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.models.IssuerUsageScopeConfig;
import org.wso2.carbon.identity.oauth2.config.models.UsageScope;
import org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigOrgUsageScopeMgtConstants;
import org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigOrgUsageScopeUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.OrgResourceResolverService;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IS_FRAGMENT_APP;

/**
 * Unit test cases for OAuth2OIDCConfigMgtServiceImpl class.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class OAuth2OIDCConfigOrgUsageScopeMgtServiceImplTest {

    @Mock
    private ConfigurationManager configurationManager;

    @Mock
    private OrganizationManager organizationManager;

    @Mock
    private ApplicationManagementService applicationManagementService;

    @Mock
    private OrgResourceResolverService orgResourceResolverService;

    @Mock
    private PrivilegedCarbonContext privilegedCarbonContext;

    @Mock
    private OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance;

    private OAuth2OIDCConfigOrgUsageScopeMgtServiceImpl oAuth2OIDCConfigMgtService;
    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMock;
    private MockedStatic<OAuth2Util> oAuth2UtilMock;
    private MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic;

    // Map to store tenant domain to issuer URL mappings for test-specific configurations
    private final java.util.Map<String, String> tenantIssuerMap = new java.util.HashMap<>();

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String ORG_ID = "f7fa55f6-6011-4398-a4d3-de831c1bb39a";
    private static final String ISSUER_URL = "https://localhost:9443/oauth2/token";
    private static final String SUB_ORG_TENANT_DOMAIN = "sub-org.com";
    private static final String SUB_ORG_ID = "bd2de88d-89b8-4388-b9c3-fceecfaedd67";
    private static final String CLIENT_ID = "test-client-id";
    private static final int TENANT_ID = -1234;

    @BeforeMethod
    public void setUp() throws Exception {

        // Mock OAuth2ServiceComponentHolder first, before creating service instance
        oAuth2ServiceComponentHolder = mockStatic(OAuth2ServiceComponentHolder.class);
        oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                .thenReturn(oAuth2ServiceComponentHolderInstance);
        oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getApplicationMgtService)
                .thenReturn(applicationManagementService);

        // Mock instance methods with lenient() to avoid strict stubbing issues
        lenient().when(oAuth2ServiceComponentHolderInstance.getConfigurationManager())
                .thenReturn(configurationManager);
        lenient().when(oAuth2ServiceComponentHolderInstance.getOrganizationManager())
                .thenReturn(organizationManager);
        lenient().when(oAuth2ServiceComponentHolderInstance.getOrgResourceResolverService())
                .thenReturn(orgResourceResolverService);

        // Mock PrivilegedCarbonContext
        privilegedCarbonContextMock = mockStatic(PrivilegedCarbonContext.class);
        privilegedCarbonContextMock.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(privilegedCarbonContext);
        lenient().when(privilegedCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
        lenient().when(privilegedCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        lenient().when(privilegedCarbonContext.getUsername()).thenReturn("admin");

        // Mock OAuth2Util
        oAuth2UtilMock = mockStatic(OAuth2Util.class);
        oAuth2UtilMock.when(() -> OAuth2Util.getTenantId(anyString())).thenReturn(TENANT_ID);

        // Mock OAuth2OIDCConfigUtils - use tenant issuer map for flexible configuration
        oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic = mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class);
        oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic.when(() ->
                        OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(anyString()))
                .thenAnswer(invocation -> {
                    String tenantDomain = invocation.getArgument(0);
                    return tenantIssuerMap.getOrDefault(tenantDomain, ISSUER_URL);
                });

        // Mock getDefaultIssuerUsageScopeConfig to use the issuer from the map
        oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic.when(() ->
                        OAuth2OIDCConfigOrgUsageScopeUtils.getDefaultIssuerUsageScopeConfig(anyString()))
                .thenAnswer(invocation -> {
                    String tenantDomain = invocation.getArgument(0);
                    IssuerUsageScopeConfig config = new IssuerUsageScopeConfig();
                    config.setIssuer(tenantIssuerMap.getOrDefault(tenantDomain, ISSUER_URL));
                    config.setUsageScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);
                    return config;
                });

        // For the exception handling methods, we can call the real methods to ensure proper exception wrapping
        oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic.when(() ->
                        OAuth2OIDCConfigOrgUsageScopeUtils.handleServerException(any(), any(), any())).
                thenCallRealMethod();
        oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic.when(() ->
                OAuth2OIDCConfigOrgUsageScopeUtils.handleClientException(any(), any(), any())).thenCallRealMethod();

        // Create the service instance after all mocks are set up
        oAuth2OIDCConfigMgtService = new OAuth2OIDCConfigOrgUsageScopeMgtServiceImpl();
    }

    @AfterMethod
    public void tearDown() {

        if (oAuth2ServiceComponentHolder != null) {
            oAuth2ServiceComponentHolder.close();
        }
        if (privilegedCarbonContextMock != null) {
            privilegedCarbonContextMock.close();
        }
        if (oAuth2UtilMock != null) {
            oAuth2UtilMock.close();
        }
        if (oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic != null) {
            oAuth2OIDCConfigOrgUsageScopeUtilsMockedStatic.close();
        }

        // Clear the tenant issuer map for next test
        tenantIssuerMap.clear();
    }

    @DataProvider(name = "getOAuth2OIDCConfigsData")
    public Object[][] getOAuth2OIDCConfigsData() {

        // Create resources using helper method
        Resource resourceAllOrgs = createResourceWithScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);
        Resource resourceNone = createResourceWithScope(UsageScope.NONE);

        return new Object[][]{
                // Resource, Expected UsageScope
                {resourceAllOrgs, UsageScope.ALL_EXISTING_AND_FUTURE_ORGS},
                {resourceNone, UsageScope.NONE},
                {null, UsageScope.ALL_EXISTING_AND_FUTURE_ORGS} // Default case
        };
    }

    @Test(dataProvider = "getOAuth2OIDCConfigsData")
    public void testGetOAuth2OIDCConfigs(Object resource, UsageScope expectedScope)
            throws Exception {

        Resource tenantResource = (Resource) resource;
        if (resource != null) {
            mockGetResource(tenantResource);
        } else {
            ConfigurationManagementException configException = new ConfigurationManagementException(
                    ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                    ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
            mockGetResourceThrowsException(configException);
        }

        IssuerUsageScopeConfig result = oAuth2OIDCConfigMgtService.getIssuerUsageScopeConfig(TENANT_DOMAIN);

        assertNotNull(result, "OAuth2OIDCConfig should not be null");
        assertNotNull(result.getUsageScope(), "IssuerUsageScopeConfig should not be null");
        assertEquals(result.getUsageScope(), expectedScope, "Usage scope should match expected value");
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetOAuth2OIDCConfigsException() throws Exception {

        ConfigurationManagementException configException = new ConfigurationManagementException(
                "Configuration error", "CONFIG_ERROR");
        when(configurationManager.getResource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                false)).thenThrow(configException);

        oAuth2OIDCConfigMgtService.getIssuerUsageScopeConfig(TENANT_DOMAIN);
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtClientException.class)
    public void testUpdateOAuth2OIDCConfigsWithNull() throws Exception {

        oAuth2OIDCConfigMgtService.updateIssuerUsageScopeConfig(TENANT_DOMAIN, null);
        fail("Expected OAuth2OIDCConfigMgtClientException");
    }

    @Test
    public void testUpdateOAuth2OIDCConfigsAddNewResource() throws Exception {

        // Create a config with ALL_EXISTING_AND_FUTURE_ORGS scope to trigger addResource flow
        IssuerUsageScopeConfig issuerUsageScopeConfig = createOAuth2OIDCConfigWithScope(
                UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);

        // Prepare the resource to return after addResource
        Resource resource = createResourceWithScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);

        // First call returns null (no existing resource), second call returns the resource (after add)
        when(configurationManager.getResource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                false)).thenReturn(null, resource);

        when(configurationManager.addResource(
                eq(OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME),
                any(ResourceAdd.class))).thenReturn(new Resource());

        IssuerUsageScopeConfig updatedIssuerUsageScope = oAuth2OIDCConfigMgtService.updateIssuerUsageScopeConfig(
                TENANT_DOMAIN, issuerUsageScopeConfig);

        assertNotNull(updatedIssuerUsageScope);
        // Verify that addResource was called since there was no existing resource
        verify(configurationManager).addResource(
                eq(OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME),
                any(ResourceAdd.class));
    }

    @Test
    public void testUpdateOAuth2OIDCConfigsReplaceExistingResource() throws Exception {

        // Create a config with NONE scope to trigger replaceResource flow
        IssuerUsageScopeConfig issuerUsageScopeConfig = createOAuth2OIDCConfigWithScope(UsageScope.NONE);

        // Existing resource and updated resource
        Resource existingResource = createResourceWithScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);
        Resource updatedResource = createResourceWithScope(UsageScope.NONE);

        // First call returns existing resource, second call returns updated resource (after replace)
        when(configurationManager.getResource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                false)).thenReturn(existingResource, updatedResource);

        // Mock organization calls for NONE scope validation
        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN)).thenReturn(ORG_ID);
        when(organizationManager.getChildOrganizationsIds(ORG_ID, true)).thenReturn(Collections.emptyList());

        // Mock resource replacement
        when(configurationManager.replaceResource(
                eq(OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME),
                any(ResourceAdd.class))).thenReturn(new Resource());

        IssuerUsageScopeConfig updatedIssuerUsageScope = oAuth2OIDCConfigMgtService.updateIssuerUsageScopeConfig(
                TENANT_DOMAIN, issuerUsageScopeConfig);

        assertNotNull(updatedIssuerUsageScope);
        // Verify that replaceResource was called since there was an existing resource
        verify(configurationManager).replaceResource(
                eq(OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME),
                any(ResourceAdd.class));
    }

    @Test
    public void testUpdateOAuth2OIDCConfigsToNoneScopeWithSubOrgApps() throws Exception {

        // Create a config with NONE scope to trigger replaceResource flow
        IssuerUsageScopeConfig issuerUsageScopeConfig = createOAuth2OIDCConfigWithScope(UsageScope.NONE);

        // Existing resource
        Resource existingResource = createResourceWithScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);

        when(configurationManager.getResource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                false)).thenReturn(existingResource);

        // Mock organization calls
        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN)).thenReturn(ORG_ID);
        when(organizationManager.getChildOrganizationsIds(ORG_ID, true))
                .thenReturn(Collections.singletonList(SUB_ORG_ID));
        when(organizationManager.resolveTenantDomain(SUB_ORG_ID)).thenReturn(SUB_ORG_TENANT_DOMAIN);

        // Mock application calls - app exists with parent issuer
        ApplicationBasicInfo appBasicInfo = new ApplicationBasicInfo();
        appBasicInfo.setApplicationResourceId("ab995fbe-f399-4836-a855-05b9ce46f853");
        when(applicationManagementService.getCountOfApplications(eq(SUB_ORG_TENANT_DOMAIN), anyString(),
                any(), anyBoolean())).thenReturn(1);
        when(applicationManagementService.getApplicationBasicInfo(eq(SUB_ORG_TENANT_DOMAIN), anyString(),
                any(), anyInt(), anyInt(), anyBoolean()))
                .thenReturn(new ApplicationBasicInfo[]{appBasicInfo});

        ServiceProvider serviceProvider = createServiceProviderWithOAuth2(CLIENT_ID);
        when(applicationManagementService.getApplicationByResourceId(appBasicInfo.getApplicationResourceId(),
                SUB_ORG_TENANT_DOMAIN)).thenReturn(serviceProvider);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setIssuerOrg(ORG_ID);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID, SUB_ORG_TENANT_DOMAIN))
                .thenReturn(oAuthAppDO);

        try {
            oAuth2OIDCConfigMgtService.updateIssuerUsageScopeConfig(TENANT_DOMAIN, issuerUsageScopeConfig);
            fail("Expected OAuth2OIDCConfigMgtClientException");
        } catch (OAuth2OIDCConfigOrgUsageScopeMgtClientException e) {
            // Expected - should reject update to NONE when apps exist in sub-orgs
            validateClientException(e, "60002",
                    "Cannot modify issuer usage scope. It is currently in use by sub-organization applications.");
        }

        // Verify that replaceResource was never called since the update should be rejected
        verify(configurationManager, never()).replaceResource(anyString(), any(ResourceAdd.class));
    }

    @DataProvider(name = "fragmentAppScenarios")
    public Object[][] fragmentAppScenarios() {
        return new Object[][]{
                // Scenario description, shouldUpdateSucceed, appCount, ServiceProviders array
                {"Only fragment app in sub-org", true, 1, new ServiceProvider[]{
                        createFragmentServiceProviderWithOAuth2("fragment-client-1")}},

                {"Mixed fragment and regular apps", false, 2, new ServiceProvider[]{
                        createFragmentServiceProviderWithOAuth2("fragment-client-1"),
                        createServiceProviderWithOAuth2(CLIENT_ID)}},

                {"App with null spProperties", false, 1, new ServiceProvider[]{
                        createServiceProviderWithNullProperties(CLIENT_ID)}}
        };
    }

    @Test(dataProvider = "fragmentAppScenarios")
    public void testUpdateOAuth2OIDCConfigsToNoneScopeWithFragmentApps(
            String scenario, boolean shouldUpdateSucceed, int appCount, ServiceProvider[] serviceProviders)
            throws Exception {

        // Create a config with NONE scope to trigger replaceResource flow
        IssuerUsageScopeConfig issuerUsageScopeConfig = createOAuth2OIDCConfigWithScope(UsageScope.NONE);

        // Existing resource with ALL_EXISTING_AND_FUTURE_ORGS scope
        Resource existingResource = createResourceWithScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);
        Resource updatedResource = createResourceWithScope(UsageScope.NONE);

        // Mock getResource - return existing first, then updated after replace (if successful)
        if (shouldUpdateSucceed) {
            when(configurationManager.getResource(
                    OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                    OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                    false)).thenReturn(existingResource, updatedResource);
        } else {
            when(configurationManager.getResource(
                    OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                    OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                    false)).thenReturn(existingResource);
        }

        // Mock organization calls for NONE scope validation
        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN)).thenReturn(ORG_ID);
        when(organizationManager.getChildOrganizationsIds(ORG_ID, true))
                .thenReturn(Collections.singletonList(SUB_ORG_ID));
        when(organizationManager.resolveTenantDomain(SUB_ORG_ID)).thenReturn(SUB_ORG_TENANT_DOMAIN);

        // Mock application calls
        ApplicationBasicInfo[] appBasicInfoArray = new ApplicationBasicInfo[appCount];
        for (int i = 0; i < appCount; i++) {
            ApplicationBasicInfo appBasicInfo = new ApplicationBasicInfo();
            appBasicInfo.setApplicationResourceId("app-resource-id-" + i);
            appBasicInfoArray[i] = appBasicInfo;
            when(applicationManagementService.getApplicationByResourceId(
                    appBasicInfo.getApplicationResourceId(), SUB_ORG_TENANT_DOMAIN))
                    .thenReturn(serviceProviders[i]);
        }

        when(applicationManagementService.getCountOfApplications(eq(SUB_ORG_TENANT_DOMAIN), anyString(),
                any(), anyBoolean())).thenReturn(appCount);
        when(applicationManagementService.getApplicationBasicInfo(eq(SUB_ORG_TENANT_DOMAIN), anyString(),
                any(), anyInt(), anyInt(), anyBoolean())).thenReturn(appBasicInfoArray);

        // Mock OAuth app for regular apps (needed when regular app exists)
        if (!shouldUpdateSucceed) {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setIssuerOrg(ORG_ID);
            oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID, SUB_ORG_TENANT_DOMAIN))
                    .thenReturn(oAuthAppDO);
        }

        // Mock resource replacement (only used if update succeeds)
        if (shouldUpdateSucceed) {
            when(configurationManager.replaceResource(
                    eq(OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME),
                    any(ResourceAdd.class))).thenReturn(new Resource());
        }

        if (shouldUpdateSucceed) {
            // Should succeed - fragment apps are ignored
            IssuerUsageScopeConfig result = oAuth2OIDCConfigMgtService.updateIssuerUsageScopeConfig(
                    TENANT_DOMAIN, issuerUsageScopeConfig);

            assertNotNull(result, "Result should not be null for scenario: " + scenario);
            assertEquals(result.getUsageScope(), UsageScope.NONE,
                    "Usage scope should be updated to NONE for scenario: " + scenario);

            // Verify that replaceResource was called
            verify(configurationManager).replaceResource(
                    eq(OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME),
                    any(ResourceAdd.class));
        } else {
            // Should fail - regular apps block the update
            try {
                oAuth2OIDCConfigMgtService.updateIssuerUsageScopeConfig(TENANT_DOMAIN, issuerUsageScopeConfig);
                fail("Expected OAuth2OIDCConfigMgtClientException for scenario: " + scenario);
            } catch (OAuth2OIDCConfigOrgUsageScopeMgtClientException e) {
                // Expected - regular apps prevent update
                validateClientException(e, "60002",
                        "Cannot modify issuer usage scope. It is currently in use by sub-organization applications.");
            }

            // Verify that replaceResource was never called
            verify(configurationManager, never()).replaceResource(anyString(), any(ResourceAdd.class));
        }
    }

    @Test
    public void testGetAllowedIssuersForPrimaryOrganization() throws Exception {

        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN)).thenReturn(ORG_ID);
        when(organizationManager.isPrimaryOrganization(ORG_ID)).thenReturn(true);

        List<String> allowedIssuers = oAuth2OIDCConfigMgtService.getAllowedIssuers();

        assertNull(allowedIssuers, "Primary organization should return null for allowed issuers");
    }

    @Test
    public void testGetAllowedIssuers() throws Exception {

        String subOrgIssuerUrl =
                "https://localhost:9443/t/carbon.super/o/bd2de88d-89b8-4388-b9c3-fceecfaedd67/oauth2/token";
        lenient().when(privilegedCarbonContext.getTenantDomain()).thenReturn(SUB_ORG_TENANT_DOMAIN);
        when(organizationManager.resolveOrganizationId(SUB_ORG_TENANT_DOMAIN)).thenReturn(SUB_ORG_ID);
        when(organizationManager.isPrimaryOrganization(SUB_ORG_ID)).thenReturn(false);

        List<String> expectedIssuers = List.of(ISSUER_URL, subOrgIssuerUrl);
        when(orgResourceResolverService.getResourcesFromOrgHierarchy(eq(SUB_ORG_ID), any(), any()))
                .thenReturn(expectedIssuers);

        List<String> result = oAuth2OIDCConfigMgtService.getAllowedIssuers();

        assertNotNull(result);
        assertEquals(result.size(), 2);
        assertEquals(result.get(0), ISSUER_URL);
        assertEquals(result.get(1), subOrgIssuerUrl);
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetAllowedIssuersException() throws Exception {

        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN))
                .thenThrow(new OrganizationManagementException("Organization error"));

        oAuth2OIDCConfigMgtService.getAllowedIssuers();
    }

    @Test
    public void testGetAllowedIssuerDetailsForPrimaryOrganization() throws Exception {

        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN)).thenReturn(ORG_ID);
        when(organizationManager.isPrimaryOrganization(ORG_ID)).thenReturn(true);

        List<IssuerDetails> result = oAuth2OIDCConfigMgtService.getAllowedIssuerDetails();

        assertNull(result, "Primary organization should return null for allowed issuer details");
    }

    @Test
    public void testGetAllowedIssuerDetails() throws Exception {

        String subOrgIssuerUrl =
                "https://localhost:9443/t/carbon.super/o/bd2de88d-89b8-4388-b9c3-fceecfaedd67/oauth2/token";
        lenient().when(privilegedCarbonContext.getTenantDomain()).thenReturn(SUB_ORG_TENANT_DOMAIN);
        when(organizationManager.resolveOrganizationId(SUB_ORG_TENANT_DOMAIN)).thenReturn(SUB_ORG_ID);
        when(organizationManager.isPrimaryOrganization(SUB_ORG_ID)).thenReturn(false);

        IssuerDetails issuerDetails = createIssuerDetails(ISSUER_URL, ORG_ID, TENANT_DOMAIN);
        IssuerDetails subOrgIssuerDetails = createIssuerDetails(subOrgIssuerUrl, SUB_ORG_ID, SUB_ORG_TENANT_DOMAIN);

        List<IssuerDetails> expectedIssuerDetails = List.of(issuerDetails, subOrgIssuerDetails);
        when(orgResourceResolverService.getResourcesFromOrgHierarchy(eq(SUB_ORG_ID), any(), any()))
                .thenReturn(expectedIssuerDetails);

        List<IssuerDetails> result = oAuth2OIDCConfigMgtService.getAllowedIssuerDetails();

        assertNotNull(result);
        assertEquals(result.size(), 2);
        verifyIssuerDetails(result.get(0), ISSUER_URL, ORG_ID, TENANT_DOMAIN);
        verifyIssuerDetails(result.get(1), subOrgIssuerUrl, SUB_ORG_ID, SUB_ORG_TENANT_DOMAIN);
    }

    @Test
    public void testGetAllowedIssuerDetailsWithAppResidentOrgId() throws Exception {

        String appResidentOrgId = "app-resident-org-id";
        String appResidentTenantDomain = "app-resident.carbon.super";

        when(privilegedCarbonContext.getApplicationResidentOrganizationId()).thenReturn(appResidentOrgId);
        when(organizationManager.resolveTenantDomain(appResidentOrgId)).thenReturn(appResidentTenantDomain);
        when(organizationManager.resolveOrganizationId(appResidentTenantDomain)).thenReturn(appResidentOrgId);
        when(organizationManager.isPrimaryOrganization(appResidentOrgId)).thenReturn(false);

        IssuerDetails issuerDetails = createIssuerDetails(ISSUER_URL, appResidentOrgId, appResidentTenantDomain);

        List<IssuerDetails> expectedIssuerDetails = Collections.singletonList(issuerDetails);
        when(orgResourceResolverService.getResourcesFromOrgHierarchy(eq(appResidentOrgId), any(), any()))
                .thenReturn(expectedIssuerDetails);

        List<IssuerDetails> result = oAuth2OIDCConfigMgtService.getAllowedIssuerDetails();

        assertNotNull(result);
        assertEquals(result.size(), 1);
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetAllowedIssuerDetailsException() throws Exception {

        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN))
                .thenThrow(new OrganizationManagementException("Organization error"));

        oAuth2OIDCConfigMgtService.getAllowedIssuerDetails();
    }

    // ========== Direct Tests for private getAllowedIssuerDetailsForOrg method ==========

    /**
     * Helper method to invoke the private getAllowedIssuerDetailsForOrg method using reflection.
     * Unwraps InvocationTargetException to throw the actual exception from the method.
     *
     * @param orgId The organization ID to get issuer details for
     * @param allowedOrgList List of organization IDs that are allowed (typically contains primaryOrgId and
     *                       requestingOrgId)
     */
    @SuppressWarnings("unchecked")
    private java.util.Optional<List<IssuerDetails>> invokeGetAllowedIssuerDetailsForOrg(String orgId,
                                                                                         List<String> allowedOrgList)
            throws Exception {

        java.lang.reflect.Method method = OAuth2OIDCConfigOrgUsageScopeMgtServiceImpl.class.getDeclaredMethod(
                "getAllowedIssuerDetailsForOrg", String.class, List.class);
        method.setAccessible(true);
        try {
            return (java.util.Optional<List<IssuerDetails>>) method.invoke(oAuth2OIDCConfigMgtService, orgId,
                    allowedOrgList);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // Unwrap and rethrow the actual exception thrown by the method
            Throwable cause = e.getCause();
            if (cause instanceof OAuth2OIDCConfigOrgUsageScopeMgtServerException) {
                throw (OAuth2OIDCConfigOrgUsageScopeMgtServerException) cause;
            } else if (cause instanceof Exception) {
                throw (Exception) cause;
            } else if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw e;
        }
    }

    /**
     * Helper method to create a Resource with the specified usage scope.
     */
    private Resource createResourceWithScope(UsageScope usageScope) {

        Attribute attribute = new Attribute(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_USAGE_SCOPE_ATTRIBUTE,
                usageScope.getValue());
        Resource resource = new Resource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME);
        resource.setHasAttribute(true);
        resource.setAttributes(Collections.singletonList(attribute));
        return resource;
    }

    /**
     * Helper method to create an OAuth2OIDCConfig with the specified usage scope.
     */
    private IssuerUsageScopeConfig createOAuth2OIDCConfigWithScope(UsageScope usageScope) {

        IssuerUsageScopeConfig issuerUsageScopeConfig = new IssuerUsageScopeConfig();
        issuerUsageScopeConfig.setUsageScope(usageScope);
        return issuerUsageScopeConfig;
    }

    /**
     * Helper method to create a ServiceProvider with OAuth2 inbound auth configured.
     */
    private ServiceProvider createServiceProviderWithOAuth2(String clientId) {

        ServiceProvider serviceProvider = new ServiceProvider();
        InboundAuthenticationConfig inboundAuthConfig = new InboundAuthenticationConfig();
        InboundAuthenticationRequestConfig requestConfig = new InboundAuthenticationRequestConfig();
        requestConfig.setInboundAuthType(OAuth2OIDCConfigOrgUsageScopeMgtConstants.INBOUND_PROTOCOL_TYPE_OAUTH2);
        requestConfig.setInboundAuthKey(clientId);
        InboundAuthenticationRequestConfig[] requestConfigs = new InboundAuthenticationRequestConfig[]{requestConfig};
        inboundAuthConfig.setInboundAuthenticationRequestConfigs(requestConfigs);
        serviceProvider.setInboundAuthenticationConfig(inboundAuthConfig);
        return serviceProvider;
    }

    /**
     * Helper method to create a fragment ServiceProvider with OAuth2 inbound auth configured.
     */
    private ServiceProvider createFragmentServiceProviderWithOAuth2(String clientId) {

        ServiceProvider serviceProvider = createServiceProviderWithOAuth2(clientId);

        // Add fragment app property
        ServiceProviderProperty fragmentProperty = new ServiceProviderProperty();
        fragmentProperty.setName(IS_FRAGMENT_APP);
        fragmentProperty.setValue("true");
        serviceProvider.setSpProperties(new ServiceProviderProperty[]{fragmentProperty});

        return serviceProvider;
    }

    /**
     * Helper method to create a ServiceProvider with OAuth2 inbound auth and null spProperties.
     */
    private ServiceProvider createServiceProviderWithNullProperties(String clientId) {

        ServiceProvider serviceProvider = createServiceProviderWithOAuth2(clientId);
        serviceProvider.setSpProperties(null);
        return serviceProvider;
    }

    /**
     * Helper method to verify IssuerDetails object fields.
     */
    private void verifyIssuerDetails(IssuerDetails actual, String expectedIssuer, String expectedOrgId,
                                     String expectedTenantDomain) {

        assertEquals(actual.getIssuer(), expectedIssuer, "Issuer URL should match");
        assertEquals(actual.getIssuerOrgId(), expectedOrgId, "Org ID should match");
        assertEquals(actual.getIssuerTenantDomain(), expectedTenantDomain, "Tenant domain should match");
    }

    /**
     * Helper method to ensure component holder dependencies are properly wired.
     * Call this in tests that invoke private methods directly.
     */
    private void mockOAuth2ServiceComponentHolder() {

        when(oAuth2ServiceComponentHolderInstance.getOrganizationManager()).thenReturn(organizationManager);
        when(oAuth2ServiceComponentHolderInstance.getConfigurationManager()).thenReturn(configurationManager);
    }

    /**
     * Helper method to mock getResource to return a specific resource.
     */
    private void mockGetResource(Resource resource) throws ConfigurationManagementException {

        when(configurationManager.getResource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                false)).thenReturn(resource);
    }

    /**
     * Helper method to mock getResource to throw an exception.
     */
    private void mockGetResourceThrowsException(Exception exception) throws ConfigurationManagementException {

        when(configurationManager.getResource(
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                OAuth2OIDCConfigOrgUsageScopeMgtConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME,
                false)).thenThrow(exception);
    }

    /**
     * Helper method to create an IssuerDetails object.
     */
    private IssuerDetails createIssuerDetails(String issuer, String orgId, String tenantDomain) {

        IssuerDetails issuerDetails = new IssuerDetails();
        issuerDetails.setIssuer(issuer);
        issuerDetails.setIssuerOrgId(orgId);
        issuerDetails.setIssuerTenantDomain(tenantDomain);
        return issuerDetails;
    }

    /**
     * Helper method to validate OAuth2OIDCConfigMgtClientException details.
     */
    private void validateClientException(OAuth2OIDCConfigOrgUsageScopeMgtClientException e, String expectedErrorCode,
                                         String expectedMessage) {

        assertEquals(e.getErrorCode(), expectedErrorCode,
                "Error code should be " + expectedErrorCode);
        assertNotNull(e.getMessage(), "Error message should not be null");
        assertEquals(e.getMessage(), expectedMessage, "Error message should match expected");
    }

    // ========== Direct Tests for private getAllowedIssuerDetailsForOrg method ==========

    @Test
    public void testGetAllowedIssuerDetailsForOrgWithNoResourceReturnsDefaultConfig() throws Exception {

        String testOrgId = "test-org-id";
        String testTenantDomain = "test.com";
        String testIssuerUrl = "https://localhost:9443/t/test.com/oauth2/token";

        // Ensure mocks are properly wired through component holder
        mockOAuth2ServiceComponentHolder();

        // Setup mocks
        when(organizationManager.resolveTenantDomain(testOrgId)).thenReturn(testTenantDomain);
        tenantIssuerMap.put(testTenantDomain, testIssuerUrl);

        // Mock getResource to return null (no resource configured)
        mockGetResource(null);

        // Create allowed org list containing the test org (simulating direct org lookup)
        List<String> allowedOrgList = Arrays.asList(testOrgId);

        // Invoke the private method
        java.util.Optional<List<IssuerDetails>> result = invokeGetAllowedIssuerDetailsForOrg(testOrgId,
                allowedOrgList);

        // Validate results
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isPresent(), "Result should be present (default config)");

        List<IssuerDetails> issuerDetailsList = result.get();
        assertEquals(issuerDetailsList.size(), 1, "Should return one issuer detail");

        IssuerDetails issuerDetails = issuerDetailsList.get(0);
        verifyIssuerDetails(issuerDetails, testIssuerUrl, testOrgId, testTenantDomain);
    }

    @Test
    public void testGetAllowedIssuerDetailsForOrgWithNoneScopeReturnsEmpty() throws Exception {

        String testOrgId = "test-org-none-id";
        String testTenantDomain = "test-none.com";

        // Ensure mocks are properly wired through component holder
        mockOAuth2ServiceComponentHolder();

        // Setup mocks
        when(organizationManager.resolveTenantDomain(testOrgId)).thenReturn(testTenantDomain);

        // Create resource with NONE scope
        Resource noneResource = createResourceWithScope(UsageScope.NONE);
        mockGetResource(noneResource);

        // Create allowed org list containing the test org
        List<String> allowedOrgList = Arrays.asList(testOrgId);

        // Invoke the private method
        java.util.Optional<List<IssuerDetails>> result = invokeGetAllowedIssuerDetailsForOrg(testOrgId,
                allowedOrgList);

        // Validate results - should return empty due to NONE scope
        assertNotNull(result, "Result should not be null");
        assertFalse(result.isPresent(), "Result should be empty for NONE scope");
    }

    @Test
    public void testGetAllowedIssuerDetailsForOrgWithAllExistingAndFutureOrgsScopeReturnsIssuer() throws Exception {

        String testOrgId = "test-org-all-id";
        String testTenantDomain = "test-all.com";
        String testIssuerUrl = "https://localhost:9443/t/test-all.com/oauth2/token";

        // Ensure mocks are properly wired through component holder
        mockOAuth2ServiceComponentHolder();

        // Setup mocks - only mock what the private method actually calls
        when(organizationManager.resolveTenantDomain(testOrgId)).thenReturn(testTenantDomain);
        tenantIssuerMap.put(testTenantDomain, testIssuerUrl);

        // Create resource with ALL_EXISTING_AND_FUTURE_ORGS scope
        Resource allOrgsResource = createResourceWithScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);
        mockGetResource(allOrgsResource);

        // Create allowed org list containing the test org
        List<String> allowedOrgList = Arrays.asList(testOrgId);

        // Invoke the private method
        java.util.Optional<List<IssuerDetails>> result = invokeGetAllowedIssuerDetailsForOrg(testOrgId,
                allowedOrgList);

        // Validate results
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isPresent(), "Result should be present");

        List<IssuerDetails> issuerDetailsList = result.get();
        assertEquals(issuerDetailsList.size(), 1, "Should return one issuer detail");

        IssuerDetails issuerDetails = issuerDetailsList.get(0);
        verifyIssuerDetails(issuerDetails, testIssuerUrl, testOrgId, testTenantDomain);
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetAllowedIssuerDetailsForOrgWithConfigurationExceptionThrowsServerException() throws Exception {

        String testOrgId = "test-org-error-id";
        String testTenantDomain = "test-error.com";

        // Ensure mocks are properly wired through component holder
        mockOAuth2ServiceComponentHolder();

        // Setup mocks
        when(organizationManager.resolveTenantDomain(testOrgId)).thenReturn(testTenantDomain);

        // Mock getResource to throw ConfigurationManagementException
        ConfigurationManagementException configException = new ConfigurationManagementException(
                "Configuration error", "CONFIG_ERROR");
        mockGetResourceThrowsException(configException);

        // Create allowed org list containing the test org
        List<String> allowedOrgList = Arrays.asList(testOrgId);

        // Invoke the private method - should throw OAuth2OIDCConfigMgtServerException
        invokeGetAllowedIssuerDetailsForOrg(testOrgId, allowedOrgList);
        fail("Expected OAuth2OIDCConfigMgtServerException to be thrown");
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetAllowedIssuerDetailsForOrgWithOrganizationExceptionThrowsServerException() throws Exception {

        String testOrgId = "test-org-org-error-id";

        // Ensure mocks are properly wired through component holder
        mockOAuth2ServiceComponentHolder();

        // Mock resolveTenantDomain to throw OrganizationManagementException
        when(organizationManager.resolveTenantDomain(testOrgId))
                .thenThrow(new OrganizationManagementException("Organization error"));

        // Create allowed org list containing the test org
        List<String> allowedOrgList = List.of(testOrgId);

        // Invoke the private method - should throw OAuth2OIDCConfigMgtServerException
        invokeGetAllowedIssuerDetailsForOrg(testOrgId, allowedOrgList);
        fail("Expected OAuth2OIDCConfigMgtServerException to be thrown");
    }
}


