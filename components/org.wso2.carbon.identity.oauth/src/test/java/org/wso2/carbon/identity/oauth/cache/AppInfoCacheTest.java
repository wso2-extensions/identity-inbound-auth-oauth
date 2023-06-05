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

package org.wso2.carbon.identity.oauth.cache;

import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.utils.CarbonUtils;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertNotEquals;

@PrepareForTest({CarbonUtils.class})
@WithCarbonHome
@PowerMockIgnore({"org.mockito.*", "javax.xml.*", "org.w3c.*", "com.sun.org.apache.xerces.*", "org.xml.*" })
public class AppInfoCacheTest {
    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
    @BeforeMethod
    public void setup() throws Exception {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        privilegedCarbonContext.setTenantId(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID);
        privilegedCarbonContext.setTenantDomain(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }
    @Test
    public void testGetInstance() throws Exception {
        mockStatic(CarbonUtils.class);
        CarbonUtils carbonUtils = new CarbonUtils();
        assertNotEquals(AppInfoCache.getInstance(), carbonUtils, "Message not equal");
    }
}
