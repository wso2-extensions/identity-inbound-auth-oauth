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
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test coverage for OIDCSessionManagementConfiguration.
 * Migrated from PowerMock to Mockito MockedStatic (Java 21 compatible).
 */
public class OIDCSessionManagementConfigurationTest {

    @Mock
    IdentityConfigParser configParser;

    @Mock
    OMElement oauthConfigElement;

    private AutoCloseable mocks;

    @BeforeMethod
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        mocks.close();
    }

    @DataProvider(name = "provideDataForTestGetInstance")
    public Object[][] provideDataForTestGetInstance() {

        return new Object[][]{
                {oauthConfigElement}, {null}
        };
    }

    @Test(dataProvider = "provideDataForTestGetInstance")
    public void testGetInstance(Object oauthConfigElement) {

        try (MockedStatic<IdentityConfigParser> identityConfigParserMock =
                     Mockito.mockStatic(IdentityConfigParser.class)) {
            identityConfigParserMock.when(IdentityConfigParser::getInstance).thenReturn(configParser);
            Mockito.when(configParser.getConfigElement(eq("OAuth"))).thenReturn((OMElement) oauthConfigElement);
            assertNotNull(OIDCSessionManagementConfiguration.getInstance());
        }
    }
}
