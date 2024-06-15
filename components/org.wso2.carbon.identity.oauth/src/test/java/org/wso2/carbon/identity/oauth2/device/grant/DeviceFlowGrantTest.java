/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.grant;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.Date;

import static org.mockito.Mockito.mockStatic;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/identity.sql", "dbScripts/insert_consumer_app.sql",
        "dbScripts/insert_local_idp.sql"})
public class DeviceFlowGrantTest {

    private Date date = new Date();
    private Timestamp newTime = new Timestamp(date.getTime());
    private DeviceFlowDO deviceFlowDO1 = new DeviceFlowDO();
    private DeviceFlowDO deviceFlowDO2 = new DeviceFlowDO();

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT1_NAME = "h2.sql";
    public static final String H2_SCRIPT2_NAME = "identity.sql";
    MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setupBeforeClass() throws Exception {
        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath(H2_SCRIPT2_NAME));
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        System.setProperty(
                "java.naming.factory.initial",
                "org.wso2.carbon.identity.common.testng.MockInitialContextFactory"
        );
    }

    @BeforeMethod
    public void setUp() throws Exception {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(DAOUtils.getConnection(DB_NAME));
        deviceFlowDO1.setExpiryTime(new Timestamp(date.getTime() - 1000));
        deviceFlowDO1.setLastPollTime(new Timestamp(date.getTime() - 1000));
        deviceFlowDO1.setPollTime(1500);
        deviceFlowDO2.setExpiryTime(new Timestamp(date.getTime() + 1000));
        deviceFlowDO2.setLastPollTime(new Timestamp(date.getTime() - 2000));
        deviceFlowDO2.setPollTime(1500);
    }

    @AfterMethod
    public void tearDown() {
        identityDatabaseUtil.close();
    }

    @Test
    public void testIsExpiredDeviceCode() throws Exception {

        Assert.assertTrue(
                (Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class, "isExpiredDeviceCode", deviceFlowDO1, date));
        Assert.assertFalse((Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class,
                "isExpiredDeviceCode", deviceFlowDO2, date));
    }

    @Test
    public void testIsValidPollTime() throws Exception {
        Assert.assertFalse((Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class,
                "isWithinValidPollInterval", newTime, deviceFlowDO1));
        Assert.assertTrue((Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class,
                "isWithinValidPollInterval", newTime, deviceFlowDO2));
    }

    private Object invokePrivateStaticMethod(Class<?> clazz, String methodName, Object... params) throws Exception {

        Class<?>[] paramTypes = new Class[params.length];
        for (int i = 0; i < params.length; i++) {
            paramTypes[i] = params[i].getClass();
        }
        Method method = clazz.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(null, params);
    }
}
