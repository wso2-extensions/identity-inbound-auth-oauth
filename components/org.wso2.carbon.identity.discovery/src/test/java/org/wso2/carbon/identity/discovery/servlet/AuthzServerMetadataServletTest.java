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

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;

import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for {@link AuthzServerMetadataServlet}.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class AuthzServerMetadataServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private PrintWriter printWriter;

    @DataProvider
    public Object[][] clientIdMetadataDocumentSupportedValues() {

        return new Object[][]{
                {Boolean.TRUE, true},
                {null, false}
        };
    }

    @Test(dataProvider = "clientIdMetadataDocumentSupportedValues")
    public void testDoGetClientIdMetadataDocumentSupported(Boolean configured, boolean expectedInResponse)
            throws Exception {

        when(request.getPathInfo()).thenReturn("/oauth2/token");
        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = new OIDProviderConfigResponse();
        configResponse.setIssuer("https://localhost:9443/oauth2/token");
        configResponse.setClientIdMetadataDocumentSupported(configured);
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)))
                .thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new AuthzServerMetadataServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
            verify(printWriter).print(body.capture());
            assertEquals(body.getValue().contains("\"client_id_metadata_document_supported\":true"),
                    expectedInResponse);
        }
    }

    @DataProvider
    public Object[][] issuerPaths() {

        return new Object[][]{
                {"/t/cimdb.test/oauth2/token", "cimdb.test"},
                {"/oauth2/token", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME}
        };
    }

    @Test(dataProvider = "issuerPaths")
    public void testDoGetUsesTenantOfIssuerPath(String pathInfo, String expectedTenant) throws Exception {

        when(request.getPathInfo()).thenReturn(pathInfo);
        when(response.getWriter()).thenReturn(printWriter);

        OIDProviderConfigResponse configResponse = new OIDProviderConfigResponse();
        configResponse.setIssuer("https://localhost:9443" + pathInfo);
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);
        when(mockProcessor.getResponse(eq(request), eq(expectedTenant))).thenReturn(configResponse);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new AuthzServerMetadataServlet().doGet(request, response);

            verify(mockProcessor).getResponse(request, expectedTenant);
            verify(response).setStatus(HttpServletResponse.SC_OK);
        }
    }

    @DataProvider
    public Object[][] invalidPaths() {

        return new Object[][]{
                {null},
                {"/t/a/b/oauth2/token"},
                {"/t//oauth2/token"},
                {"/oauth2/token/extra"}
        };
    }

    @Test(dataProvider = "invalidPaths")
    public void testDoGetRejectsInvalidPath(String pathInfo) throws Exception {

        when(request.getPathInfo()).thenReturn(pathInfo);
        DefaultOIDCProcessor mockProcessor = mock(DefaultOIDCProcessor.class);

        try (MockedStatic<DefaultOIDCProcessor> processorStatic = mockStatic(DefaultOIDCProcessor.class)) {
            processorStatic.when(DefaultOIDCProcessor::getInstance).thenReturn(mockProcessor);

            new AuthzServerMetadataServlet().doGet(request, response);

            verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
            verify(mockProcessor, never()).getResponse(any(), anyString());
        }
    }
}
