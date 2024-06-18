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
package org.wso2.carbon.identity.oidc.session.config;

import org.apache.axiom.om.OMElement;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test coverage for OIDCSessionManagementConfiguration.
 */
@Listeners(MockitoTestNGListener.class)
public class OIDCSessionManagementConfigurationTest {

    @Mock
    IdentityConfigParser mockConfigParser;

    @Mock
    OMElement oauthConfigElement;

    @DataProvider(name = "provideDataForTestGetInstance")
    public Object[][] provideDataForTestGetInstance() {

        return new Object[][]{
                {oauthConfigElement}, {null}
        };
    }

    @Test(dataProvider = "provideDataForTestGetInstance")
    public void testGetInstance(Object oauthConfigElement) {

        try (MockedStatic<IdentityConfigParser> identityConfigParser = mockStatic(IdentityConfigParser.class)) {
            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(mockConfigParser);
            lenient().when(mockConfigParser.getConfigElement(eq("OAuth"))).thenReturn((OMElement) oauthConfigElement);
            assertNotNull(OIDCSessionManagementConfiguration.getInstance());
        }
    }
}
