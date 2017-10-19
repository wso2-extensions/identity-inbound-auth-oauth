/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.test.utils;


import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;

import java.nio.file.Paths;

public class CommonTestUtils {

    private CommonTestUtils() {
    }

    public static void initPrivilegedCarbonContext(String tenantDomain, int tenantID, String userName) throws Exception {
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }

    public static void initPrivilegedCarbonContext(String tenantDomain, String userName) throws Exception {
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        initPrivilegedCarbonContext(tenantDomain, tenantID, userName);
    }

    public static void initPrivilegedCarbonContext(String tenantDomain) throws Exception {
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        String userName = "testUser";

        initPrivilegedCarbonContext(tenantDomain, tenantID, userName);
    }

    public static void initPrivilegedCarbonContext() throws Exception {
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        String userName = "testUser";

        initPrivilegedCarbonContext(tenantDomain, tenantID, userName);
    }

}
