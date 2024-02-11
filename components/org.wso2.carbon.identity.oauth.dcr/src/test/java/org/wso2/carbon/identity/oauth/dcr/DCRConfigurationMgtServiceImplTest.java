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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConfigUtils;

import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.reflect.Whitebox.invokeMethod;

/**
 * Unit tests covering DCRConfigurationMgtServiceImpl class.
 * The getDCRConfiguration and setDCRConfiguration methods are called by the api layer in server configuration api.
 * Hence, the unit tests are written to cover the getDCRConfiguration and setDCRConfiguration methods.
 */
@PrepareForTest({DCRDataHolder.class, DCRConfigUtils.class, IdentityTenantUtil.class})
public class DCRConfigurationMgtServiceImplTest extends PowerMockTestCase {

    @Mock
    DCRDataHolder dataHolder;

    private DCRConfigurationMgtServiceImpl dcrConfigurationMgtServiceImpl;

    @BeforeMethod
    public void setUp() throws Exception {
        dcrConfigurationMgtServiceImpl = new DCRConfigurationMgtServiceImpl();
    }

    @Test(description = "Test getDCRConfiguration method accepts tenant domain and returns DCRConfiguration object")
    public void testGetDCRConfiguration() throws DCRMServerException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        mockStatic(DCRConfigUtils.class);
        DCRConfiguration dcrConfiguration = new DCRConfiguration();
        when(DCRConfigUtils.getDCRConfigurationByTenantDomain(anyString())).thenReturn(dcrConfiguration);

        String tenantDomain = "carbon.super";
        try {
            Assert.assertTrue(invokeMethod(dcrConfigurationMgtServiceImpl, "getDCRConfiguration",
                    tenantDomain) instanceof DCRConfiguration);
        } catch (Exception e) {
            Assert.assertTrue(e instanceof DCRMException);
        }
    }

    @Test(description = "Test setDCRConfiguration method accepts DCRConfiguration object and tenant domain.")
    public void testSetDCRConfiguration() throws DCRMServerException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        mockStatic(DCRConfigUtils.class);
        DCRConfiguration dcrConfiguration = new DCRConfiguration();
        when(DCRConfigUtils.getDCRConfigurationByTenantDomain(anyString())).thenReturn(dcrConfiguration);

        mockStatic(DCRDataHolder.class);
        when(DCRDataHolder.getInstance()).thenReturn(dataHolder);

        String tenantDomain = "carbon.super";

        try {
            invokeMethod(dcrConfigurationMgtServiceImpl, "setDCRConfiguration",
                    dcrConfiguration, tenantDomain);
        } catch (Exception e) {
            Assert.assertTrue(e instanceof DCRMException);
        }
    }
}
