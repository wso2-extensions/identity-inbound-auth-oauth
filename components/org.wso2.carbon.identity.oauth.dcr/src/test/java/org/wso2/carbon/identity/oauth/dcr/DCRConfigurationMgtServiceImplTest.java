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

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.caching.impl.DataHolder;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManagerImpl;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.reflect.Whitebox.invokeMethod;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.CLIENT_AUTHENTICATION_REQUIRED;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.ENABLE_FAPI_ENFORCEMENT;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.SSA_JWKS;

/**
 * Unit tests covering DCRConfigurationMgtServiceImpl class.
 * The getDCRConfiguration and setDCRConfiguration methods are called by the api layer in server configuration api.
 * Hence, the unit tests are written to cover the getDCRConfiguration and setDCRConfiguration methods.
 */
@PrepareForTest({DCRDataHolder.class, IdentityTenantUtil.class, IdentityUtil.class,
        DCRConfigurationMgtServiceImpl.class})
public class DCRConfigurationMgtServiceImplTest extends PowerMockTestCase {

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

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        try {
            Assert.assertTrue(invokeMethod(dcrConfigurationMgtService, "getDCRConfiguration")
                    instanceof DCRConfiguration);

            when(IdentityUtil.getProperty(OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT)).thenReturn("true");
            when(IdentityUtil.getProperty(OAuthConstants.DCR_CLIENT_AUTHENTICATION_REQUIRED)).thenReturn("true");
            when(IdentityUtil.getProperty(OAuthConstants.DCR_SSA_VALIDATION_JWKS)).thenReturn(dummySSAJwks);

            dcrConfiguration = dcrConfigurationMgtService.getDCRConfiguration();

            assertEquals(true, dcrConfiguration.getEnableFapiEnforcement());
            assertEquals(true, dcrConfiguration.getAuthenticationRequired());
            assertEquals(dummySSAJwks, dcrConfiguration.getSsaJwks());

        } catch (Exception e) {
            Assert.assertTrue(e instanceof DCRMException);
        }
    }

    @Test(priority =  2, description = "Test setDCRConfiguration method sets DCRConfiguration properly" )
    public void testSetDCRConfiguration() {


    }

//    @Test(priority = 3, description = "Test overrideDCRServerConfigsWithDCRResourceConfig method properly overrides " +
//            "the DCRConfiguration object")
//    public void testOverrideDCRServerConfigsWithDCRResourceConfig() throws Exception {
//
//        Resource resource = new Resource();
//        Attribute attribute1 = new Attribute(ENABLE_FAPI_ENFORCEMENT, "false");
//        Attribute attribute2 = new Attribute(DCRMConstants.CLIENT_AUTHENTICATION_REQUIRED, "false");
//        resource.setAttributes(Arrays.asList(attribute1, attribute2));
//        resource.setHasAttribute(true);
//
//        invokeMethod(DCRConfigurationMgtServiceImpl.class,
//                "overrideDCRServerConfigsWithDCRResourceConfig", resource, this.dcrConfiguration);
//
//        dcrConfigurationMgtService.
//
//        assertEquals(false, this.dcrConfiguration.getEnableFapiEnforcement());
//        assertEquals(false, this.dcrConfiguration.getAuthenticationRequired());
//    }

//    @Test(priority = 4, description = "Test parseConfig method properly converts the DCRConfiguration object to " +
//            "a ResourceAdd object")
//    public void testParseConfigurations() throws Exception {
//
//        ResourceAdd resourceAdd = invokeMethod(DCRConfigurationMgtServiceImpl.class,
//                "parseConfig", this.dcrConfiguration);
//
//        List<Attribute> attributes = resourceAdd.getAttributes();
//        Map<String, String> attributeMap = invokeMethod(DCRConfigurationMgtServiceImpl.class, "getAttributeMap",
//                attributes);
//
//        String enableDCRFapiValue = attributeMap.get(ENABLE_FAPI_ENFORCEMENT);
//        Boolean enableDCRFapi = enableDCRFapiValue != null ? Boolean.parseBoolean(enableDCRFapiValue) : null;
//
//        String clientAuthenticationRequiredValue = attributeMap.get(CLIENT_AUTHENTICATION_REQUIRED);
//        Boolean clientAuthenticationRequired = clientAuthenticationRequiredValue != null ?
//                Boolean.parseBoolean(clientAuthenticationRequiredValue) : null;
//
//        String ssaJwks = attributeMap.get(SSA_JWKS);
//
//        assertEquals(3, attributes.size());
//        assertEquals(false, enableDCRFapi);
//        assertEquals(false, clientAuthenticationRequired);
//        assertEquals(dummySSAJwks, ssaJwks);
//
//    }
}
