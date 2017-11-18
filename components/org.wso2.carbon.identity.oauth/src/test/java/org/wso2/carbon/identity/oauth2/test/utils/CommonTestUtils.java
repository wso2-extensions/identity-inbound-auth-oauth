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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

public class CommonTestUtils {

    public static final String JDBC_SUBCONTEXT = "jdbc";
    private static Map<String, ServiceProvider> fileBasedSPs = null;

    private CommonTestUtils() {
    }

    public static void testSingleton(Object instance, Object anotherInstance) {
        assertNotNull(instance);
        assertNotNull(anotherInstance);
        assertEquals(instance, anotherInstance);
    }

    public static void initPrivilegedCarbonContext(String tenantDomain,
                                                   int tenantID,
                                                   String userName) throws Exception {
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }

    public static void initPrivilegedCarbonContext() throws Exception {
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        String userName = "testUser";

        initPrivilegedCarbonContext(tenantDomain, tenantID, userName);
    }

    public static Map<String, ServiceProvider> getFileBasedSPs() throws Exception {
        if (fileBasedSPs == null) {
            buildFileBasedSPList();
        }
        return Collections.unmodifiableMap(fileBasedSPs);
    }

    private static void buildFileBasedSPList() throws Exception {
        fileBasedSPs = new HashMap();
        String spConfigDirPath = CarbonUtils.getCarbonConfigDirPath() + File.separator + "identity" +
                                 File.separator + "service-providers";
        FileInputStream fileInputStream = null;
        File spConfigDir = new File(spConfigDirPath);
        if (spConfigDir.exists()) {
            File[] arr$ = spConfigDir.listFiles();
            int len$ = arr$.length;

            for (int i$ = 0; i$ < len$; ++i$) {
                File fileEntry = arr$[i$];

                try {
                    if (!fileEntry.isDirectory()) {
                        fileInputStream = new FileInputStream(new File(fileEntry.getAbsolutePath()));
                        OMElement documentElement = (new StAXOMBuilder(fileInputStream)).getDocumentElement();
                        ServiceProvider e = ServiceProvider.build(documentElement);
                        if (e != null) {
                            fileBasedSPs.put(e.getApplicationName(), e);
                        }
                    }
                } finally {
                    if (fileInputStream != null) {
                        fileInputStream.close();
                    }

                }
            }
        }
    }

    public static void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }

}
