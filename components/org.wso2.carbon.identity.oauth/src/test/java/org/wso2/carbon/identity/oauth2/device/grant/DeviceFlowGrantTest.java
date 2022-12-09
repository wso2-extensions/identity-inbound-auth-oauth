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

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;

import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.Date;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@PrepareForTest({IdentityDatabaseUtil.class})
public class DeviceFlowGrantTest extends PowerMockTestCase {

    private Date date = new Date();
    private Timestamp newTime = new Timestamp(date.getTime());
    private DeviceFlowDO deviceFlowDO1 = new DeviceFlowDO();
    private DeviceFlowDO deviceFlowDO2 = new DeviceFlowDO();

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT1_NAME = "h2.sql";
    public static final String H2_SCRIPT2_NAME = "identity.sql";

    @BeforeClass
    public void setupBeforeClass() throws Exception {
        DAOUtils.initializeBatchDataSource(DB_NAME, H2_SCRIPT1_NAME, H2_SCRIPT2_NAME);
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

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(DAOUtils.getConnection(DB_NAME));
        deviceFlowDO1.setExpiryTime(new Timestamp(date.getTime() - 1000));
        deviceFlowDO1.setLastPollTime(new Timestamp(date.getTime() - 1000));
        deviceFlowDO1.setPollTime(1500);
        deviceFlowDO2.setExpiryTime(new Timestamp(date.getTime() + 1000));
        deviceFlowDO2.setLastPollTime(new Timestamp(date.getTime() - 2000));
        deviceFlowDO2.setPollTime(1500);
    }

    @Test
    public void testIsExpiredDeviceCode() throws Exception {
        Assert.assertTrue(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class, "isExpiredDeviceCode", deviceFlowDO1, date));
        Assert.assertFalse(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isExpiredDeviceCode", deviceFlowDO2, date));
    }

    @Test
    public void testIsValidPollTime() throws Exception {
        Assert.assertFalse(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isWithinValidPollInterval", newTime, deviceFlowDO1));
        Assert.assertTrue(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isWithinValidPollInterval", newTime, deviceFlowDO2));
    }
}
