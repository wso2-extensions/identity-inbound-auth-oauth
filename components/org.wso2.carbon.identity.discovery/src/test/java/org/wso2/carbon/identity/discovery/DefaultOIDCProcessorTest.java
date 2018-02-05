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

package org.wso2.carbon.identity.discovery;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.discovery.builders.DefaultOIDCProviderRequestBuilder;
import org.wso2.carbon.identity.discovery.builders.ProviderConfigBuilder;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({DefaultOIDCProcessor.class})
public class DefaultOIDCProcessorTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private DefaultOIDCProviderRequestBuilder mockOidcProviderRequestBuilder;

    @Mock
    private OIDProviderRequest mockOidProviderRequest;

    @Mock
    private ProviderConfigBuilder mockProviderConfigBuilder;

    @Mock
    private OIDProviderConfigResponse mockOidProviderConfigResponse;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetInstance() throws Exception {
        assertNotNull(DefaultOIDCProcessor.getInstance());
    }

    @Test
    public void testGetResponse() throws Exception {
        when(mockOidcProviderRequestBuilder.buildRequest(any(HttpServletRequest.class), anyString()))
                .thenReturn(mockOidProviderRequest);
        when(mockProviderConfigBuilder.buildOIDProviderConfig(any(OIDProviderRequest.class)))
                .thenReturn(mockOidProviderConfigResponse);

        whenNew(DefaultOIDCProviderRequestBuilder.class).withNoArguments().thenReturn(mockOidcProviderRequestBuilder);
        whenNew(ProviderConfigBuilder.class).withNoArguments().thenReturn(mockProviderConfigBuilder);

        OIDCProcessor oidcProcessor = DefaultOIDCProcessor.getInstance();
        OIDProviderConfigResponse response = oidcProcessor.getResponse(httpServletRequest, "tenantDomain");
        assertNotNull(response, "Error while calling getResponse()");
    }

    @DataProvider(name = "errorData")
    public static Object[][] tenant() {
        return new Object[][]{
                {OIDCDiscoveryEndPointException.ERROR_CODE_NO_OPENID_PROVIDER_FOUND,
                        OIDCDiscoveryEndPointException.ERROR_MESSAGE_NO_OPENID_PROVIDER_FOUND},
                {OIDCDiscoveryEndPointException.ERROR_CODE_INVALID_REQUEST,
                        OIDCDiscoveryEndPointException.ERROR_MESSAGE_INVALID_REQUEST},
                {OIDCDiscoveryEndPointException.ERROR_CODE_INVALID_TENANT,
                        OIDCDiscoveryEndPointException.ERROR_MESSAGE_INVALID_TENANT},
                {OIDCDiscoveryEndPointException.ERROR_CODE_JSON_EXCEPTION,
                        OIDCDiscoveryEndPointException.ERROR_MESSAGE_JSON_EXCEPTION},
                {"", "Internal server error occurred. "}
        };
    }

    @Test(dataProvider = "errorData")
    public void testHandleError(String errorCode, String errorMessage) throws Exception {
        OIDCDiscoveryEndPointException oidcDiscoveryEndPointException =
                new OIDCDiscoveryEndPointException(errorCode, errorMessage);
        assertEquals(DefaultOIDCProcessor.getInstance().handleError(oidcDiscoveryEndPointException), 500);
    }
}
