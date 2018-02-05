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

package org.wso2.carbon.identity.oauth.config;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import java.util.Properties;

public class OAuthCallbackHandlerMetaDataTest extends IdentityBaseTest {
    private OAuthCallbackHandlerMetaData oAuthCallbackHandlerMetaData;

    @Test
    public void testGetPriority() throws Exception {
        Assert.assertEquals(oAuthCallbackHandlerMetaData.getPriority(), 1);
    }

    @Test
    public void testGetProperties() throws Exception {
        Properties assertProperty = oAuthCallbackHandlerMetaData.getProperties();
        Assert.assertEquals(assertProperty.getProperty("property1"), "propertyValue");
    }

    @Test
    public void testGetClassName() throws Exception {
        Assert.assertEquals(oAuthCallbackHandlerMetaData.getClassName(), "testClass");
    }

    @BeforeTest
    public void setUp() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("property1", "propertyValue");
        oAuthCallbackHandlerMetaData = new OAuthCallbackHandlerMetaData("testClass", properties, 1);
    }
}
