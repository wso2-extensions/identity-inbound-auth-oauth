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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
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

    @AfterMethod
    public void tearDown() {

        IdentityUtil.threadLocalProperties.get().remove(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
    }

    @Test
    public void testDoGet_nullPathInfo_returnsSuperTenantDiscovery() throws Exception {

        when(request.getPathInfo()).thenReturn(null);
        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = buildMockConfigResponse();
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)))
                .thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            verify(response).setContentType("application/json");
            verify(mockProcessor).getResponse(request, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
    }

    @Test
    public void testDoGet_rootPathInfo_returnsSuperTenantDiscovery() throws Exception {

        when(request.getPathInfo()).thenReturn("/");
        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = buildMockConfigResponse();
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)))
                .thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            verify(response).setContentType("application/json");
            verify(mockProcessor).getResponse(request, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
    }

    @Test
    public void testDoGet_tenantInThreadLocal_usesThatTenant() throws Exception {

        IdentityUtil.threadLocalProperties.get().put(OAuthConstants.TENANT_NAME_FROM_CONTEXT, "test.com");
        when(request.getPathInfo()).thenReturn(null);
        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = buildMockConfigResponse();
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq("test.com"))).thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            verify(mockProcessor).getResponse(request, "test.com");
        }
    }

    @Test
    public void testDoGet_tenantFromPathInfo_usesTenantName() throws Exception {

        when(request.getPathInfo()).thenReturn("/t/xyz.com");
        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = buildMockConfigResponse();
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq("xyz.com"))).thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            verify(mockProcessor).getResponse(request, "xyz.com");
        }
    }

    @DataProvider(name = "invalidPaths")
    public Object[][] invalidPaths() {

        return new Object[][]{
                {"/bad"},
                {"/t/a/b"},
                {"/t/"},
                {"/t"}
        };
    }

    @Test(dataProvider = "invalidPaths")
    public void testDoGet_invalidPathInfo_returns404(String pathInfo) throws Exception {

        when(request.getPathInfo()).thenReturn(pathInfo);

        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
            verify(mockProcessor, never()).getResponse(eq(request), anyString());
        }
    }

    @Test
    public void testDoGet_oidcDiscoveryEndPointException_returnsErrorStatus() throws Exception {

        when(request.getPathInfo()).thenReturn(null);
        when(response.getWriter()).thenReturn(printWriter);

        OIDCDiscoveryEndPointException exception = new OIDCDiscoveryEndPointException("Discovery error");
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), anyString())).thenThrow(exception);
        when(mockProcessor.handleError(exception)).thenReturn(HttpServletResponse.SC_BAD_REQUEST);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
            verify(response).setContentType("application/json");
            verify(printWriter).print("Discovery error");
        }
    }

    @Test
    public void testDoGet_serverConfigurationException_returns500() throws Exception {

        when(request.getPathInfo()).thenReturn(null);
        when(response.getWriter()).thenReturn(printWriter);

        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), anyString()))
                .thenThrow(new ServerConfigurationException("Config error"));

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new OIDCDiscoveryServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            verify(response).setContentType("application/json");
            verify(printWriter).print("Error in reading configuration.");
        }
    }

    private OIDProviderConfigResponse buildMockConfigResponse() {

        return new OIDProviderConfigResponse();
    }
}
