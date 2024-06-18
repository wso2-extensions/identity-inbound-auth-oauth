/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.dcr;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.ENABLE_FAPI_ENFORCEMENT;

/**
 * Unit tests covering DCRConfigurationMgtServiceImpl class.
 * The getDCRConfiguration and setDCRConfiguration methods are called by the api layer in server configuration api.
 * Hence, the unit tests are written to cover the getDCRConfiguration and setDCRConfiguration methods.
 */
public class DCRConfigurationMgtServiceImplTest {

    private DCRConfigurationMgtService dcrConfigurationMgtService;
    private DCRConfiguration dcrConfiguration;
    private String dummySSAJwks = "http://localhost.com/jwks";
    private ConfigurationManager mockConfigurationManager;

    @BeforeMethod
    public void setUp() throws Exception {

        dcrConfigurationMgtService = new DCRConfigurationMgtServiceImpl();
        mockConfigurationManager = Mockito.mock(ConfigurationManager.class);
        DCRDataHolder.getInstance().setConfigurationManager(mockConfigurationManager);

    }

    @Test(priority = 1, description = "Test getDCRConfiguration method gets correct dcr configs")
    public void testGetDCRConfiguration() {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);) {
            try {
                identityUtil.when(() -> IdentityUtil.getProperty(OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT))
                        .thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(OAuthConstants.DCR_CLIENT_AUTHENTICATION_REQUIRED))
                        .thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(OAuthConstants.DCR_SSA_VALIDATION_JWKS))
                        .thenReturn(dummySSAJwks);

                dcrConfiguration = dcrConfigurationMgtService.getDCRConfiguration();

                assertEquals(true, dcrConfiguration.getEnableFapiEnforcement());
                assertEquals(true, dcrConfiguration.getAuthenticationRequired());
                assertEquals(dummySSAJwks, dcrConfiguration.getSsaJwks());

            } catch (Exception e) {
                Assert.assertTrue(e instanceof DCRMException);
            }
        }
    }

    @Test(priority =  2, description = "Test setDCRConfiguration method properly sets DCRConfiguration")
    public void testSetDCRConfiguration() {

        try {
            dcrConfigurationMgtService.setDCRConfiguration(dcrConfiguration);
            dcrConfiguration.setAuthenticationRequired(false);
            dcrConfigurationMgtService.setDCRConfiguration(dcrConfiguration);

        } catch (Exception e) {
            Assert.assertTrue(e instanceof DCRMException);
            Assert.assertEquals(DCRMConstants.DCRConfigErrorMessage.ERROR_CODE_SSA_NOT_MANDATED.getCode(),
                    ((DCRMException) e).getErrorCode());
        }
    }

    @Test(priority = 3, description = "Test overrideDCRServerConfigsWithDCRResourceConfig method properly overrides " +
            "the DCRConfiguration object")
    public void testOverrideDCRServerConfigsWithDCRResourceConfig() throws Exception {

        Resource resource = new Resource();
        Attribute attribute1 = new Attribute(ENABLE_FAPI_ENFORCEMENT, "false");
        Attribute attribute2 = new Attribute(DCRMConstants.CLIENT_AUTHENTICATION_REQUIRED, "true");
        resource.setAttributes(Arrays.asList(attribute1, attribute2));
        resource.setHasAttribute(true);

        when(mockConfigurationManager.getResource(DCR_CONFIG_RESOURCE_TYPE_NAME, DCR_CONFIG_RESOURCE_NAME))
                .thenReturn(resource);

        dcrConfiguration = dcrConfigurationMgtService.getDCRConfiguration();

        assertEquals(false, dcrConfiguration.getEnableFapiEnforcement());
        assertEquals(true, dcrConfiguration.getAuthenticationRequired());
    }
}
