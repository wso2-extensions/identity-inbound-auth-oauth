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

package org.wso2.carbon.identity.oauth.endpoint.device;

import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;

import java.nio.file.Paths;

import static org.testng.Assert.assertEquals;

public class DeviceEndpointTest {

    private DeviceEndpoint deviceEndpoint = new DeviceEndpoint();

    @BeforeTest
    public void setUp() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, Paths.get(System.getProperty("user.dir"),
                "src", "test", "resources").toString());
    }

    @AfterTest
    public void cleanData() {

    }

    @DataProvider(name = "provideValues")
    public Object[][] provideValues() {

        long value1 = 1000;
        return new Object[][]{
                {value1}
        };
    }

    @Test(dataProvider = "provideValues")
    public void testStringValueInSeconds(long value) throws Exception {

        String realValue = "1";
        assertEquals(WhiteboxImpl.invokeMethod(deviceEndpoint, "stringValueInSeconds", value),
                realValue);
    }
}
