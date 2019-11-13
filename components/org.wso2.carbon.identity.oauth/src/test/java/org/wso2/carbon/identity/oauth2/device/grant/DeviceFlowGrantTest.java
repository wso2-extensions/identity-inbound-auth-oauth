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

import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
public class DeviceFlowGrantTest extends PowerMockTestCase {

    private HashMap<String, String> results = new HashMap<>();
    private HashMap<String, String> results1 = new HashMap<>();
    private Date date = new Date();
    private Timestamp newTime = new Timestamp(date.getTime());
    private DeviceFlowDO deviceFlowDO1 = new DeviceFlowDO();
    private DeviceFlowDO deviceFlowDO2 = new DeviceFlowDO();

    @BeforeTest
    public void setUp() throws Exception {

        deviceFlowDO1.setExpiryTime(date.getTime()-1000);
        deviceFlowDO1.setLastPollTime(new Timestamp(date.getTime()-1000));
        deviceFlowDO1.setPollTime(1500);
        deviceFlowDO2.setExpiryTime(date.getTime()+1000);
        deviceFlowDO2.setLastPollTime(new Timestamp(date.getTime()-2000));
        deviceFlowDO2.setPollTime(1500);

    }

    @AfterMethod
    public void tearDown() {
    }

    @Test
    public void testIsValidDeviceCode() throws Exception {

        Assert.assertTrue(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isValidDeviceCode",deviceFlowDO1, date));
        Assert.assertFalse(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isValidDeviceCode",deviceFlowDO2, date));
    }

    @Test
    public void testIsValidPollTime() throws Exception {
        Assert.assertFalse(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,"isValidPollTime"
                , newTime, deviceFlowDO1));
        Assert.assertTrue(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,"isValidPollTime"
                , newTime, deviceFlowDO2));
    }

}
