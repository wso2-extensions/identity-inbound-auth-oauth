/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtException;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationConfig;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationConfigMgtServiceImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.FileAssert.fail;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RETRIEVE_RESOURCE_TYPE;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.ENABLE_EMAIL_NOTIFICATION;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.ErrorMessage.ERROR_CODE_IMP_CONFIG_RETRIEVE;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.ErrorMessage.ERROR_CODE_IMP_CONFIG_UPDATE;

/**
 * Unit test cases for ImpersonationConfigMgtService clas.
 */
@Listeners(MockitoTestNGListener.class)
public class ImpersonationConfigMgtTest {
    @Mock
    private ConfigurationManager configurationManager;

    private ImpersonationConfigMgtServiceImpl impersonationConfigMgtService
                = new ImpersonationConfigMgtServiceImpl();
    private static final String tenantDomain = "carbon.super";


    @BeforeMethod
    public void setUp() throws Exception {

        OAuth2ServiceComponentHolder.getInstance().setConfigurationManager(configurationManager);
    }

    @DataProvider(name = "GetImpersonationConfigData")
    public Object[][] getImpersonationConfigData() {

            Attribute attributeEnabled = new Attribute(ENABLE_EMAIL_NOTIFICATION, "true");
            Resource resourceEnabled = new Resource(IMPERSONATION_RESOURCE_NAME, IMPERSONATION_RESOURCE_TYPE_NAME);
            resourceEnabled.setHasAttribute(true);
            resourceEnabled.setAttributes(Collections.singletonList(attributeEnabled));

            Attribute attributeDisabled = new Attribute(ENABLE_EMAIL_NOTIFICATION, "false");
            Resource resourceDisabled = new Resource(IMPERSONATION_RESOURCE_NAME, IMPERSONATION_RESOURCE_TYPE_NAME);
            resourceDisabled.setHasAttribute(true);
            resourceDisabled.setAttributes(Collections.singletonList(attributeDisabled));

            return new Object[][]{
                 // Resource to be return
                 // isEmailNotificationEnabled
                {resourceEnabled, true},
                {resourceDisabled, false},
                {null, true}
            };
    }

    @Test(dataProvider = "GetImpersonationConfigData")
    public void testGetImpersonationConfig(Object resource, boolean isEmailNotificationEnabled)
            throws Exception {

        Resource tenantResource = (Resource) resource;
         if (resource != null) {
              when(configurationManager.getResource(IMPERSONATION_RESOURCE_TYPE_NAME, IMPERSONATION_RESOURCE_NAME))
                      .thenReturn(tenantResource);
         }  else {
             ConfigurationManagementException configurationManagementException = new ConfigurationManagementException
                     (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(), ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
              when(configurationManager.getResource(IMPERSONATION_RESOURCE_TYPE_NAME, IMPERSONATION_RESOURCE_NAME))
                      .thenThrow(configurationManagementException);
         }

        try {
            ImpersonationConfig impersonationConfig = impersonationConfigMgtService
                    .getImpersonationConfig(tenantDomain);
            assertEquals(isEmailNotificationEnabled, impersonationConfig.isEnableEmailNotification());

        } catch (ImpersonationConfigMgtException e) {
            fail("Unexpected Exception");
        }
    }

    @Test
    public void testGetImpersonationConfigException() throws ConfigurationManagementException {


        ConfigurationManagementException configurationManagementException = new ConfigurationManagementException
                (ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getMessage(), ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getCode());
        when(configurationManager.getResource(IMPERSONATION_RESOURCE_TYPE_NAME, IMPERSONATION_RESOURCE_NAME))
                    .thenThrow(configurationManagementException);

        try {
            impersonationConfigMgtService.getImpersonationConfig(tenantDomain);
        } catch (ImpersonationConfigMgtException e) {
            assertEquals(e.getErrorCode(), ERROR_CODE_IMP_CONFIG_RETRIEVE.getCode());
            assertEquals(e.getMessage(), String.format(ERROR_CODE_IMP_CONFIG_RETRIEVE.getDescription(), tenantDomain));
        }
    }

    @Test
    public void testSetImpersonationConfig() throws ConfigurationManagementException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(-1234);
            lenient().when(configurationManager.replaceResource(eq(IMPERSONATION_RESOURCE_TYPE_NAME),
                            any(Resource.class))).thenReturn(new Resource());
            ImpersonationConfig impersonationConfig = new ImpersonationConfig();
            impersonationConfig.setEnableEmailNotification(true);
            try {
                impersonationConfigMgtService.setImpersonationConfig(impersonationConfig, tenantDomain);
            } catch (ImpersonationConfigMgtException e) {
                fail("Unexpected Exception");
            }
        }
    }

    @Test
    public void testSetImpersonationConfigException() throws ConfigurationManagementException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(-1234);
            ConfigurationManagementException configurationManagementException = new ConfigurationManagementException
                    (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(), ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
            lenient().when(configurationManager.replaceResource(eq(IMPERSONATION_RESOURCE_TYPE_NAME),
                            any(Resource.class))).thenThrow(configurationManagementException);
            ImpersonationConfig impersonationConfig = new ImpersonationConfig();
            impersonationConfig.setEnableEmailNotification(true);
            try {
                impersonationConfigMgtService.setImpersonationConfig(impersonationConfig, tenantDomain);
            } catch (ImpersonationConfigMgtException e) {
                assertEquals(e.getErrorCode(), ERROR_CODE_IMP_CONFIG_UPDATE.getCode());
                assertEquals(e.getMessage(),
                        String.format(ERROR_CODE_IMP_CONFIG_UPDATE.getDescription(), tenantDomain));
            }
        }
    }
}
