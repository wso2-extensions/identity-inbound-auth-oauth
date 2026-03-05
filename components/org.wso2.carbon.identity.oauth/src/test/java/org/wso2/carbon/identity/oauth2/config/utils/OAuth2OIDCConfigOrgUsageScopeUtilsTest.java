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

package org.wso2.carbon.identity.oauth2.config.utils;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigOrgUsageScopeMgtClientException;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigOrgUsageScopeMgtServerException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerUsageScopeConfig;
import org.wso2.carbon.identity.oauth2.config.models.UsageScope;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;

/**
 * Unit test cases for OAuth2OIDCConfigOrgUsageScopeUtils class.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class OAuth2OIDCConfigOrgUsageScopeUtilsTest {

    @Mock
    private OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance;

    @Mock
    private OrganizationManager organizationManager;

    @Mock
    private PrivilegedCarbonContext privilegedCarbonContext;

    @Mock
    private ServiceURLBuilder serviceURLBuilder;

    @Mock
    private org.wso2.carbon.identity.core.ServiceURL serviceURL;

    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder;
    private MockedStatic<OAuth2Util> oAuth2UtilMock;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMock;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderMock;

    private static final String PRIMARY_TENANT_DOMAIN = "carbon.super";
    private static final String SUB_ORG_TENANT_DOMAIN = "suborg.example.com";
    private static final String PRIMARY_ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String SUB_ORG_ID = "a8d113f4-211a-0d5e-fe36-b082211e36b0";
    private static final String PRIMARY_ISSUER_URL = "https://localhost:9443/oauth2/token";
    private static final String SUB_ORG_ISSUER_URL =
            "https://localhost:9443/t/carbon.super/o/a8d113f4-211a-0d5e-fe36-b082211e36b0/oauth2/token";
    private static final String ERROR_MESSAGE = "Test error message";
    private static final String ERROR_DATA = "test-data";
    private static final String TEST_DATA_1 = "data1";
    private static final String TEST_DATA_2 = "data2";

    @BeforeMethod
    public void setUp() throws Exception {

        // Mock OAuth2ServiceComponentHolder
        oAuth2ServiceComponentHolder = mockStatic(OAuth2ServiceComponentHolder.class);
        oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                .thenReturn(oAuth2ServiceComponentHolderInstance);

        lenient().when(oAuth2ServiceComponentHolderInstance.getOrganizationManager())
                .thenReturn(organizationManager);

        // Mock PrivilegedCarbonContext
        privilegedCarbonContextMock = mockStatic(PrivilegedCarbonContext.class);
        privilegedCarbonContextMock.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(privilegedCarbonContext);
        privilegedCarbonContextMock.when(PrivilegedCarbonContext::startTenantFlow)
                .then(invocation -> null);
        privilegedCarbonContextMock.when(PrivilegedCarbonContext::endTenantFlow)
                .then(invocation -> null);

        // Mock OAuth2Util
        oAuth2UtilMock = mockStatic(OAuth2Util.class);

        // Mock ServiceURLBuilder
        serviceURLBuilderMock = mockStatic(ServiceURLBuilder.class);
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
        if (serviceURLBuilderMock != null) {
            serviceURLBuilderMock.close();
        }

        // Clear thread local properties
        if (IdentityUtil.threadLocalProperties.get() != null) {
            IdentityUtil.threadLocalProperties.get().clear();
        }
    }

    @DataProvider(name = "defaultIssuerUsageScopeConfigData")
    public Object[][] defaultIssuerUsageScopeConfigData() {

        return new Object[][]{
                {PRIMARY_TENANT_DOMAIN, PRIMARY_ORG_ID, PRIMARY_ISSUER_URL},
                {"another.tenant.com", "f5e44a2b-3c1d-4e8f-9b2a-1d3c4e5f6a7b",
                        "https://localhost:9443/t/another.tenant.com/oauth2/token"}
        };
    }

    @Test(dataProvider = "defaultIssuerUsageScopeConfigData")
    public void testGetDefaultIssuerUsageScopeConfig(String tenantDomain, String orgId, String expectedIssuer)
            throws Exception {

        setupMocksForPrimaryOrganization(tenantDomain, orgId, expectedIssuer);

        IssuerUsageScopeConfig result = OAuth2OIDCConfigOrgUsageScopeUtils.
                getDefaultIssuerUsageScopeConfig(tenantDomain);

        assertNotNull(result, "IssuerUsageScopeConfig should not be null");
        assertEquals(result.getIssuer(), expectedIssuer, "Issuer should match expected value");
        assertEquals(result.getUsageScope(), UsageScope.ALL_EXISTING_AND_FUTURE_ORGS,
                "Usage scope should be ALL_EXISTING_AND_FUTURE_ORGS");
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetDefaultIssuerUsageScopeConfigWithException() throws Exception {

        when(organizationManager.resolveOrganizationId(PRIMARY_TENANT_DOMAIN))
                .thenThrow(new OrganizationManagementException("Organization error"));

        OAuth2OIDCConfigOrgUsageScopeUtils.getDefaultIssuerUsageScopeConfig(PRIMARY_TENANT_DOMAIN);
    }

    @DataProvider(name = "issuerLocationData")
    public Object[][] issuerLocationData() {

        return new Object[][]{
                {PRIMARY_TENANT_DOMAIN, PRIMARY_ORG_ID, true, PRIMARY_ISSUER_URL},
                {SUB_ORG_TENANT_DOMAIN, SUB_ORG_ID, false, SUB_ORG_ISSUER_URL}
        };
    }

    @Test(dataProvider = "issuerLocationData")
    public void testGetIssuerLocationForOrganization(String tenantDomain, String orgId, boolean isPrimaryOrg,
                                                     String expectedIssuer) throws Exception {

        when(organizationManager.resolveOrganizationId(tenantDomain)).thenReturn(orgId);
        when(organizationManager.isPrimaryOrganization(orgId)).thenReturn(isPrimaryOrg);

        if (isPrimaryOrg) {
            oAuth2UtilMock.when(() -> OAuth2Util.getIssuerLocation(tenantDomain))
                    .thenReturn(expectedIssuer);
        } else {
            when(organizationManager.getPrimaryOrganizationId(orgId)).thenReturn(PRIMARY_ORG_ID);
            when(organizationManager.resolveTenantDomain(PRIMARY_ORG_ID)).thenReturn(PRIMARY_TENANT_DOMAIN);

            serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn(expectedIssuer);
        }

        String result = OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(tenantDomain);

        assertEquals(result, expectedIssuer, "Issuer location should match expected value");
        verify(organizationManager, times(1)).resolveOrganizationId(tenantDomain);
        verify(organizationManager, times(1)).isPrimaryOrganization(orgId);

        if (!isPrimaryOrg) {
            privilegedCarbonContextMock.verify(PrivilegedCarbonContext::startTenantFlow, times(1));
            privilegedCarbonContextMock.verify(PrivilegedCarbonContext::endTenantFlow, times(1));
            verify(privilegedCarbonContext, times(1)).setTenantDomain(PRIMARY_TENANT_DOMAIN);
            verify(privilegedCarbonContext, times(1)).setApplicationResidentOrganizationId(orgId);
        }
    }

    @Test
    public void testGetIssuerLocationRestoresThreadLocalProperties() throws Exception {

        String initialTenantName = "initial.tenant.com";
        String initialRootTenant = "initial.root.com";
        IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, initialTenantName);
        IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN,
                initialRootTenant);

        setupMocksForPrimaryOrganization(PRIMARY_TENANT_DOMAIN, PRIMARY_ORG_ID, PRIMARY_ISSUER_URL);

        OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(PRIMARY_TENANT_DOMAIN);

        assertEquals(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT), initialTenantName,
                "TENANT_NAME_FROM_CONTEXT should be restored");
        assertEquals(IdentityUtil.threadLocalProperties.get().get(OrganizationManagementConstants.ROOT_TENANT_DOMAIN),
                initialRootTenant, "ROOT_TENANT_DOMAIN should be restored");
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetIssuerLocationWithOrganizationManagementException() throws Exception {

        when(organizationManager.resolveOrganizationId(PRIMARY_TENANT_DOMAIN))
                .thenThrow(new OrganizationManagementException("Organization error"));

        OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(PRIMARY_TENANT_DOMAIN);
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetIssuerLocationWithIdentityOAuth2Exception() throws Exception {

        when(organizationManager.resolveOrganizationId(PRIMARY_TENANT_DOMAIN)).thenReturn(PRIMARY_ORG_ID);
        when(organizationManager.isPrimaryOrganization(PRIMARY_ORG_ID)).thenReturn(true);
        oAuth2UtilMock.when(() -> OAuth2Util.getIssuerLocation(PRIMARY_TENANT_DOMAIN))
                .thenThrow(new IdentityOAuth2Exception("OAuth2 error"));

        OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(PRIMARY_TENANT_DOMAIN);
    }

    @Test(expectedExceptions = OAuth2OIDCConfigOrgUsageScopeMgtServerException.class)
    public void testGetIssuerLocationWithURLBuilderException() throws Exception {

        when(organizationManager.resolveOrganizationId(SUB_ORG_TENANT_DOMAIN)).thenReturn(SUB_ORG_ID);
        when(organizationManager.isPrimaryOrganization(SUB_ORG_ID)).thenReturn(false);
        when(organizationManager.getPrimaryOrganizationId(SUB_ORG_ID)).thenReturn(PRIMARY_ORG_ID);
        when(organizationManager.resolveTenantDomain(PRIMARY_ORG_ID)).thenReturn(PRIMARY_TENANT_DOMAIN);

        serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenThrow(new URLBuilderException("URL builder error"));

        try {
            OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(SUB_ORG_TENANT_DOMAIN);
        } finally {
            privilegedCarbonContextMock.verify(PrivilegedCarbonContext::startTenantFlow, times(1));
            privilegedCarbonContextMock.verify(PrivilegedCarbonContext::endTenantFlow, times(1));
        }
    }

    @Test
    public void testHandleServerException() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_USAGE_SCOPE_ISSUER_BUILD;
        Throwable cause = new RuntimeException(ERROR_MESSAGE);

        OAuth2OIDCConfigOrgUsageScopeMgtServerException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleServerException(error, cause, ERROR_DATA);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
        assertNotNull(exception.getMessage(), "Exception message should not be null");
        assertEquals(exception.getCause(), cause, "Exception cause should match");
    }

    @Test
    public void testHandleServerExceptionWithMultipleData() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_USAGE_SCOPE_ISSUER_BUILD;
        Throwable cause = new RuntimeException(ERROR_MESSAGE);

        OAuth2OIDCConfigOrgUsageScopeMgtServerException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleServerException(error, cause, TEST_DATA_1, TEST_DATA_2);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
        assertEquals(exception.getCause(), cause, "Exception cause should match");
    }

    @Test
    public void testHandleServerExceptionWithNoData() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_USAGE_SCOPE_CONFIG_RETRIEVE;
        Throwable cause = new RuntimeException(ERROR_MESSAGE);

        OAuth2OIDCConfigOrgUsageScopeMgtServerException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleServerException(error, cause, (String) null);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
        assertEquals(exception.getCause(), cause, "Exception cause should match");
    }

    @Test
    public void testHandleClientException() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_USAGE_SCOPE_CONFIG_EMPTY_PATCH_OBJECT;
        Throwable cause = new RuntimeException(ERROR_MESSAGE);

        OAuth2OIDCConfigOrgUsageScopeMgtClientException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleClientException(error, cause, ERROR_DATA);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
        assertNotNull(exception.getMessage(), "Exception message should not be null");
        assertEquals(exception.getCause(), cause, "Exception cause should match");
    }

    @Test
    public void testHandleClientExceptionWithMultipleData() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_USAGE_SCOPE_CONFIG_EMPTY_PATCH_OBJECT;
        Throwable cause = new RuntimeException(ERROR_MESSAGE);

        OAuth2OIDCConfigOrgUsageScopeMgtClientException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleClientException(error, cause, TEST_DATA_1, TEST_DATA_2);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
        assertEquals(exception.getCause(), cause, "Exception cause should match");
    }

    @Test
    public void testHandleClientExceptionWithNoData() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_ISSUER_USAGE_SCOPE_CHANGE_REJECT;
        Throwable cause = new RuntimeException(ERROR_MESSAGE);

        OAuth2OIDCConfigOrgUsageScopeMgtClientException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleClientException(error, cause);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
        assertEquals(exception.getCause(), cause, "Exception cause should match");
    }

    @Test
    public void testHandleExceptionWithNullCause() {

        OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages error =
                OAuth2OIDCConfigOrgUsageScopeMgtErrorMessages.ERROR_CODE_USAGE_SCOPE_ISSUER_BUILD;

        OAuth2OIDCConfigOrgUsageScopeMgtServerException exception =
                OAuth2OIDCConfigOrgUsageScopeUtils.handleServerException(error, null, ERROR_DATA);

        assertNotNull(exception, "Exception should not be null");
        assertEquals(exception.getErrorCode(), error.getCode(), "Error code should match");
    }

    /**
     * Helper method to setup mocks for primary organization scenario.
     *
     * @param tenantDomain  Tenant domain.
     * @param orgId         Organization ID.
     * @param issuerUrl     Expected issuer URL.
     * @throws Exception If an error occurs during mock setup.
     */
    private void setupMocksForPrimaryOrganization(String tenantDomain, String orgId, String issuerUrl)
            throws Exception {

        when(organizationManager.resolveOrganizationId(tenantDomain)).thenReturn(orgId);
        when(organizationManager.isPrimaryOrganization(orgId)).thenReturn(true);
        oAuth2UtilMock.when(() -> OAuth2Util.getIssuerLocation(tenantDomain)).thenReturn(issuerUrl);
    }
}
