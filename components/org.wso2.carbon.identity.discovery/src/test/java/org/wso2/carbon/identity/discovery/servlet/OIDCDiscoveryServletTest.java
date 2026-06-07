/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.discovery.servlet;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OIDCDiscoveryServlet}.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class OIDCDiscoveryServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private PrintWriter printWriter;

    @Test
    public void testDoGet_resolvedTenantDomain_returnsDiscovery() throws Exception {

        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = new OIDProviderConfigResponse();
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq("test.com"))).thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class);
             MockedStatic<OAuth2Util> oauth2UtilStatic = mockStatic(OAuth2Util.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);
            oauth2UtilStatic.when(() -> OAuth2Util.resolveTenantDomain(request)).thenReturn("test.com");

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            verify(response).setContentType("application/json");
            verify(mockProcessor).getResponse(request, "test.com");
        }
    }

    @Test
    public void testDoGet_superTenantDomain_returnsDiscovery() throws Exception {

        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = new OIDProviderConfigResponse();
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)))
                .thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class);
             MockedStatic<OAuth2Util> oauth2UtilStatic = mockStatic(OAuth2Util.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);
            oauth2UtilStatic.when(() -> OAuth2Util.resolveTenantDomain(request))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            verify(response).setContentType("application/json");
            verify(mockProcessor).getResponse(request, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
    }

    @Test
    public void testDoGet_oidcDiscoveryEndPointException_returnsErrorStatus() throws Exception {

        when(response.getWriter()).thenReturn(printWriter);

        OIDCDiscoveryEndPointException exception = new OIDCDiscoveryEndPointException("Discovery error");
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), anyString())).thenThrow(exception);
        when(mockProcessor.handleError(exception)).thenReturn(HttpServletResponse.SC_BAD_REQUEST);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class);
             MockedStatic<OAuth2Util> oauth2UtilStatic = mockStatic(OAuth2Util.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);
            oauth2UtilStatic.when(() -> OAuth2Util.resolveTenantDomain(request))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
            verify(response).setContentType("application/json");
            verify(printWriter).print("{\"error\":\"Discovery error\"}");
        }
    }

    @Test
    public void testDoGet_serverConfigurationException_returns500() throws Exception {

        when(response.getWriter()).thenReturn(printWriter);

        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), anyString()))
                .thenThrow(new ServerConfigurationException("Config error"));

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class);
             MockedStatic<OAuth2Util> oauth2UtilStatic = mockStatic(OAuth2Util.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);
            oauth2UtilStatic.when(() -> OAuth2Util.resolveTenantDomain(request))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            verify(response).setContentType("application/json");
            verify(printWriter).print("{\"error\":\"Error in reading configuration.\"}");
        }
    }
}
