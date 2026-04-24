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

package org.wso2.carbon.identity.oauth2.fapi;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtException;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiConfig;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiProfileEnum;
import org.wso2.carbon.identity.oauth2.fapi.services.FapiConfigMgtServiceImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;
import static org.testng.FileAssert.fail;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RETRIEVE_RESOURCE_TYPE;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_ENABLED;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth2.fapi.utils.ErrorMessage.ERROR_CODE_FAPI_CONFIG_RETRIEVE;
import static org.wso2.carbon.identity.oauth2.fapi.utils.ErrorMessage.ERROR_CODE_FAPI_CONFIG_UPDATE;
import static org.wso2.carbon.identity.oauth2.fapi.utils.ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN;

/**
 * Unit tests for {@link FapiConfigMgtServiceImpl}.
 */
@Listeners(MockitoTestNGListener.class)
public class FapiConfigMgtServiceImplTest {

    @Mock
    private ConfigurationManager configurationManager;

    private final FapiConfigMgtServiceImpl fapiConfigMgtService = new FapiConfigMgtServiceImpl();
    private static final String TENANT_DOMAIN = "carbon.super";

    @BeforeMethod
    public void setUp() {

        OAuth2ServiceComponentHolder.getInstance().setConfigurationManager(configurationManager);
    }

    @DataProvider(name = "GetFapiConfigData")
    public Object[][] getFapiConfigData() {

        Attribute enabledAttr = new Attribute(FAPI_ENABLED, "true");
        Resource resourceEnabled = new Resource(FAPI_RESOURCE_NAME, FAPI_RESOURCE_TYPE_NAME);
        resourceEnabled.setHasAttribute(true);
        resourceEnabled.setAttributes(Collections.singletonList(enabledAttr));

        Attribute disabledAttr = new Attribute(FAPI_ENABLED, "false");
        Resource resourceDisabled = new Resource(FAPI_RESOURCE_NAME, FAPI_RESOURCE_TYPE_NAME);
        resourceDisabled.setHasAttribute(true);
        resourceDisabled.setAttributes(Collections.singletonList(disabledAttr));

        return new Object[][]{
                // resource returned by ConfigurationManager, expected isEnabled value
                {resourceEnabled, Boolean.TRUE},
                {resourceDisabled, Boolean.FALSE},
                // null simulates "resource not found" — getResource() returns null → default config (enabled=true)
                {null, Boolean.TRUE}
        };
    }

    @Test(dataProvider = "GetFapiConfigData")
    public void testGetFapiConfig(Object resource, boolean expectedEnabled) throws Exception {

        Resource tenantResource = (Resource) resource;
        if (tenantResource != null) {
            when(configurationManager.getResource(FAPI_RESOURCE_TYPE_NAME, FAPI_RESOURCE_NAME, true))
                    .thenReturn(tenantResource);
        } else {
            // Simulate resource not found — service's private getResource() catches this and returns null.
            ConfigurationManagementException notFound = new ConfigurationManagementException(
                    ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                    ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
            when(configurationManager.getResource(FAPI_RESOURCE_TYPE_NAME, FAPI_RESOURCE_NAME, true))
                    .thenThrow(notFound);
        }

        try {
            FapiConfig fapiConfig = fapiConfigMgtService.getFapiConfig(TENANT_DOMAIN);
            assertNotNull(fapiConfig);
            assertEquals(expectedEnabled, fapiConfig.isEnabled());
        } catch (FapiConfigMgtException e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    public void testGetFapiConfigServerException() throws ConfigurationManagementException {

        ConfigurationManagementException unexpectedException = new ConfigurationManagementException(
                ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getMessage(),
                ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getCode());
        when(configurationManager.getResource(FAPI_RESOURCE_TYPE_NAME, FAPI_RESOURCE_NAME, true))
                .thenThrow(unexpectedException);

        try {
            fapiConfigMgtService.getFapiConfig(TENANT_DOMAIN);
            fail("Expected FapiConfigMgtServerException was not thrown");
        } catch (FapiConfigMgtServerException e) {
            assertEquals(ERROR_CODE_FAPI_CONFIG_RETRIEVE.getCode(), e.getErrorCode());
            assertEquals(String.format(ERROR_CODE_FAPI_CONFIG_RETRIEVE.getDescription(), TENANT_DOMAIN),
                    e.getMessage());
        } catch (FapiConfigMgtException e) {
            fail("Expected FapiConfigMgtServerException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test
    public void testSetFapiConfig() throws ConfigurationManagementException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            lenient().when(configurationManager.replaceResource(eq(FAPI_RESOURCE_TYPE_NAME), any(ResourceAdd.class)))
                    .thenReturn(new Resource());

            FapiConfig fapiConfig = new FapiConfig();
            fapiConfig.setEnabled(true);
            fapiConfig.setSupportedProfiles(Collections.singletonList(FapiProfileEnum.FAPI1_ADVANCED));

            try {
                fapiConfigMgtService.setFapiConfig(fapiConfig, TENANT_DOMAIN);
            } catch (FapiConfigMgtException e) {
                fail("Unexpected exception: " + e.getMessage());
            }
        }
    }

    @Test
    public void testSetFapiConfigServerException() throws ConfigurationManagementException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            ConfigurationManagementException configMgtException = new ConfigurationManagementException(
                    ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                    ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
            lenient().when(configurationManager.replaceResource(eq(FAPI_RESOURCE_TYPE_NAME), any(ResourceAdd.class)))
                    .thenThrow(configMgtException);

            FapiConfig fapiConfig = new FapiConfig();
            fapiConfig.setEnabled(false);

            try {
                fapiConfigMgtService.setFapiConfig(fapiConfig, TENANT_DOMAIN);
                fail("Expected FapiConfigMgtServerException was not thrown");
            } catch (FapiConfigMgtServerException e) {
                assertEquals(ERROR_CODE_FAPI_CONFIG_UPDATE.getCode(), e.getErrorCode());
                assertEquals(String.format(ERROR_CODE_FAPI_CONFIG_UPDATE.getDescription(), TENANT_DOMAIN),
                        e.getMessage());
            } catch (FapiConfigMgtException e) {
                fail("Expected FapiConfigMgtServerException, got: " + e.getClass().getSimpleName());
            }
        }
    }

    @Test
    public void testSetFapiConfigInvalidTenantDomain() {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                    .thenThrow(new IdentityRuntimeException("Invalid tenant: " + TENANT_DOMAIN));

            FapiConfig fapiConfig = new FapiConfig();
            fapiConfig.setEnabled(true);

            try {
                fapiConfigMgtService.setFapiConfig(fapiConfig, TENANT_DOMAIN);
                fail("Expected FapiConfigMgtClientException was not thrown");
            } catch (FapiConfigMgtClientException e) {
                assertEquals(ERROR_CODE_INVALID_TENANT_DOMAIN.getCode(), e.getErrorCode());
            } catch (FapiConfigMgtException e) {
                fail("Expected FapiConfigMgtClientException, got: " + e.getClass().getSimpleName());
            }
        }
    }

    @Test
    public void testGetFapiConfigDefaultHasExpectedValues() throws Exception {

        // When resource not found, default config has enabled=true and FAPI1_ADVANCED profile.
        ConfigurationManagementException notFound = new ConfigurationManagementException(
                ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
        when(configurationManager.getResource(FAPI_RESOURCE_TYPE_NAME, FAPI_RESOURCE_NAME, true))
                .thenThrow(notFound);

        FapiConfig fapiConfig = fapiConfigMgtService.getFapiConfig(TENANT_DOMAIN);
        assertTrue(fapiConfig.isEnabled());
        assertNotNull(fapiConfig.getSupportedProfiles());
        assertFalse(fapiConfig.getSupportedProfiles().isEmpty());
        assertEquals(FapiProfileEnum.FAPI1_ADVANCED, fapiConfig.getSupportedProfiles().get(0));
    }
}
