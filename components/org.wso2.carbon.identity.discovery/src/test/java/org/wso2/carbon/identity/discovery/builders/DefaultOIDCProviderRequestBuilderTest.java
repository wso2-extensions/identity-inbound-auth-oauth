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

package org.wso2.carbon.identity.discovery.builders;

import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.discovery.OIDProviderRequest;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

public class DefaultOIDCProviderRequestBuilderTest {

    @Mock
    private HttpServletRequest mockHttpServletRequest;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
    }

    @DataProvider(name = "test1")
    public static Object[][] tenant() {
        return new Object[][]{
                {null, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME},
                {"tenant", "tenant"}
        };
    }

    @Test(dataProvider = "test1")
    public void testBuildRequest(String value, String output) throws Exception {
        when(mockHttpServletRequest.getRequestURI()).thenReturn("https://test.com");
        DefaultOIDCProviderRequestBuilder defaultOIDCProviderRequestBuilder = new DefaultOIDCProviderRequestBuilder();
        OIDProviderRequest oidProviderRequest = defaultOIDCProviderRequestBuilder.buildRequest(mockHttpServletRequest,
                value);
        assertEquals(oidProviderRequest.getUri(), "https://test.com", "Result URI is different from " +
                "the expected URI");
        assertEquals(oidProviderRequest.getTenantDomain(), output, "Error in tenant domain");
    }

}
