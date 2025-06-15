/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.endpoint.authzservermetadata;

import org.mockito.*;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.discovery.builders.OIDProviderResponseBuilder;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OIDCProviderServiceFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.atLeastOnce;

/**
 * Unit tests for AuthzServerMetadataEndpoint class.
 */
public class AuthzServerMetadataEndpointTest {

    @Mock
    BundleContext bundleContext;

    @Mock
    DefaultOIDCProcessor defaultOIDCProcessor;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private OIDCProcessor mockOIDCProcessor;

    @Mock
    OIDProviderResponseBuilder oidProviderResponseBuilder;

    MockedConstruction<ServiceTracker> mockedConstruction;

    @InjectMocks
    private AuthzServerMetadataEndpoint authzServerMetadataEndpoint;

    private MockedStatic<CarbonContext> carbonContextMockedStatic;
    private MockedStatic<OIDCProviderServiceFactory> oidcProviderServiceFactoryMockedStatic;

    @BeforeMethod
    public void setUpMethod() {

        MockitoAnnotations.openMocks(this);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(OIDProviderResponseBuilder.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oidProviderResponseBuilder});
                    }
                    if (argumentCaptor.getValue().contains(OIDCProcessor.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{defaultOIDCProcessor});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() {
        if (carbonContextMockedStatic != null) {
            carbonContextMockedStatic.close();
        }
        if (oidcProviderServiceFactoryMockedStatic != null) {
            oidcProviderServiceFactoryMockedStatic.close();
        }

        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @Test
    public void testGetAuthzServerMetadata_Success() throws Exception {
        // Arrange
        String tenantDomain = "test.com";
        String expectedResponse = "{\"issuer\":\"https://localhost:9443/oauth2/token\"}";
        // Create OIDProviderConfigResponse instance instead of string
        OIDProviderConfigResponse oidcResponse = new OIDProviderConfigResponse();
        oidcResponse.setIssuer("https://localhost:9443/oauth2/token");
        oidcResponse.setAuthorizationEndpoint("https://localhost:9443/oauth2/authorize");
        oidcResponse.setTokenEndpoint("https://localhost:9443/oauth2/token");
        oidcResponse.setUserinfoEndpoint("https://localhost:9443/oauth2/userinfo");
        oidcResponse.setJwksUri("https://localhost:9443/oauth2/jwks");

        when(mockOIDCProcessor.getResponse(mockRequest, tenantDomain)).thenReturn(oidcResponse);
    }

    @Test
    public void testGetAuthzServerMetadata_NullRequest() throws Exception {
        // Arrange
        String tenantDomain = "test.com";
        String expectedResponse = "{\"issuer\":\"https://localhost:9443/oauth2/token\"}";

        // Create OIDProviderConfigResponse instance instead of string
        OIDProviderConfigResponse oidcResponse = new OIDProviderConfigResponse();
        oidcResponse.setIssuer("https://localhost:9443/oauth2/token");
        oidcResponse.setAuthorizationEndpoint("https://localhost:9443/oauth2/authorize");
        oidcResponse.setTokenEndpoint("https://localhost:9443/oauth2/token");
        oidcResponse.setUserinfoEndpoint("https://localhost:9443/oauth2/userinfo");
        oidcResponse.setJwksUri("https://localhost:9443/oauth2/jwks");

        when(mockOIDCProcessor.getResponse(null, tenantDomain)).thenReturn(oidcResponse);
    }

    @Test
    public void testGetAuthzServerMetadata_MultipleExceptionHandling() throws Exception {
        // Arrange
        String tenantDomain = "test.com";
        String oidcErrorMessage = "OIDC error";
        int oidcErrorStatus = HttpServletResponse.SC_UNAUTHORIZED;

        OIDCDiscoveryEndPointException oidcException = new OIDCDiscoveryEndPointException(oidcErrorMessage);

        when(mockOIDCProcessor.getResponse(mockRequest, tenantDomain)).thenThrow(oidcException);
        when(mockOIDCProcessor.handleError(oidcException)).thenReturn(oidcErrorStatus);

        // Act
        Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(mockRequest);

        // Assert
        Assert.assertEquals(response.getStatus(), oidcErrorStatus);
        Assert.assertEquals(response.getEntity(), oidcErrorMessage);

        // Verify that ServerConfigurationException path is not executed
        verify(mockOIDCProcessor, never()).getResponse(any(), any());
    }
}
