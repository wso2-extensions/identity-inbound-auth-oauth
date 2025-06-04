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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OIDCProviderServiceFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for AuthzServerMetadataEndpoint class.
 */
public class AuthzServerMetadataEndpointTest {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private OIDCProcessor mockOIDCProcessor;

    @Mock
    private CarbonContext mockCarbonContext;

    @InjectMocks
    private AuthzServerMetadataEndpoint authzServerMetadataEndpoint;

    private MockedStatic<CarbonContext> carbonContextMockedStatic;
    private MockedStatic<OIDCProviderServiceFactory> oidcProviderServiceFactoryMockedStatic;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        // Mock static classes
        carbonContextMockedStatic = Mockito.mockStatic(CarbonContext.class);
        oidcProviderServiceFactoryMockedStatic = Mockito.mockStatic(OIDCProviderServiceFactory.class);

        // Setup default behavior for static mocks
        carbonContextMockedStatic.when(CarbonContext::getThreadLocalCarbonContext)
                .thenReturn(mockCarbonContext);
        oidcProviderServiceFactoryMockedStatic.when(OIDCProviderServiceFactory::getOIDCService)
                .thenReturn(mockOIDCProcessor);
    }

    @AfterMethod
    public void tearDown() {
        if (carbonContextMockedStatic != null) {
            carbonContextMockedStatic.close();
        }
        if (oidcProviderServiceFactoryMockedStatic != null) {
            oidcProviderServiceFactoryMockedStatic.close();
        }
    }

    @DataProvider(name = "tenantDomainData")
    public Object[][] tenantDomainData() {
        return new Object[][]{
                {"tenant1.com", "tenant1.com"},
                {"", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME},
                {null, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME},
                {"   ", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME}
        };
    }

    @Test(dataProvider = "tenantDomainData")
    public void testGetAuthzServerMetadata_SuccessWithDifferentTenantDomains(String inputTenant, String expectedTenant)
            throws Exception {
        // Arrange
        String expectedResponse = "{\"issuer\":\"https://localhost:9443/oauth2/token\"}";

        // Create OIDProviderConfigResponse instance instead of string
        OIDProviderConfigResponse oidcResponse = new OIDProviderConfigResponse();
        oidcResponse.setIssuer("https://localhost:9443/oauth2/token");
        oidcResponse.setAuthorizationEndpoint("https://localhost:9443/oauth2/authorize");
        oidcResponse.setTokenEndpoint("https://localhost:9443/oauth2/token");
        oidcResponse.setUserinfoEndpoint("https://localhost:9443/oauth2/userinfo");
        oidcResponse.setJwksUri("https://localhost:9443/oauth2/jwks");

        when(mockCarbonContext.getTenantDomain()).thenReturn(inputTenant);
        when(mockOIDCProcessor.getResponse(eq(mockRequest), eq(expectedTenant))).thenReturn(oidcResponse);

        // Mock the response builder using try-with-resources pattern
        try (MockedStatic<AuthzServerMetadataJsonResponseBuilder> responseBuilderMock =
                     Mockito.mockStatic(AuthzServerMetadataJsonResponseBuilder.class, Mockito.CALLS_REAL_METHODS)) {

            AuthzServerMetadataJsonResponseBuilder mockBuilder = mock(AuthzServerMetadataJsonResponseBuilder.class);
            responseBuilderMock.when(() -> new AuthzServerMetadataJsonResponseBuilder()).thenReturn(mockBuilder);
            when(mockBuilder.getAuthzServerMetadataConfigString(oidcResponse)).thenReturn(expectedResponse);

            // Act
            Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(mockRequest);

            // Assert
            Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
            Assert.assertEquals(response.getEntity(), expectedResponse);
        }
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

        when(mockCarbonContext.getTenantDomain()).thenReturn(tenantDomain);
        when(mockOIDCProcessor.getResponse(mockRequest, tenantDomain)).thenReturn(oidcResponse);

        try (MockedStatic<AuthzServerMetadataJsonResponseBuilder> responseBuilderMock =
                     Mockito.mockStatic(AuthzServerMetadataJsonResponseBuilder.class, Mockito.CALLS_REAL_METHODS)) {

            AuthzServerMetadataJsonResponseBuilder mockBuilder = mock(AuthzServerMetadataJsonResponseBuilder.class);
            responseBuilderMock.when(() -> new AuthzServerMetadataJsonResponseBuilder()).thenReturn(mockBuilder);
            when(mockBuilder.getAuthzServerMetadataConfigString(oidcResponse)).thenReturn(expectedResponse);

            // Act
            Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(mockRequest);

            // Assert
            Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
            Assert.assertEquals(response.getEntity(), expectedResponse);
            verify(mockOIDCProcessor).getResponse(mockRequest, tenantDomain);
        }
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

        when(mockCarbonContext.getTenantDomain()).thenReturn(tenantDomain);
        when(mockOIDCProcessor.getResponse(null, tenantDomain)).thenReturn(oidcResponse);

        try (MockedStatic<AuthzServerMetadataJsonResponseBuilder> responseBuilderMock =
                     Mockito.mockStatic(AuthzServerMetadataJsonResponseBuilder.class, Mockito.CALLS_REAL_METHODS)) {

            AuthzServerMetadataJsonResponseBuilder mockBuilder = mock(AuthzServerMetadataJsonResponseBuilder.class);
            responseBuilderMock.when(() -> new AuthzServerMetadataJsonResponseBuilder()).thenReturn(mockBuilder);
            when(mockBuilder.getAuthzServerMetadataConfigString(oidcResponse)).thenReturn(expectedResponse);

            // Act
            Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(null);

            // Assert
            Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
            Assert.assertEquals(response.getEntity(), expectedResponse);
        }
    }

    @Test
    public void testGetAuthzServerMetadata_EmptyResponse() throws Exception {
        // Arrange
        String tenantDomain = "test.com";
        String expectedResponse = "";
        // Create OIDProviderConfigResponse instance instead of string
        OIDProviderConfigResponse oidcResponse = new OIDProviderConfigResponse();
        oidcResponse.setIssuer("https://localhost:9443/oauth2/token");
        oidcResponse.setAuthorizationEndpoint("https://localhost:9443/oauth2/authorize");
        oidcResponse.setTokenEndpoint("https://localhost:9443/oauth2/token");
        oidcResponse.setUserinfoEndpoint("https://localhost:9443/oauth2/userinfo");
        oidcResponse.setJwksUri("https://localhost:9443/oauth2/jwks");

        when(mockCarbonContext.getTenantDomain()).thenReturn(tenantDomain);
        when(mockOIDCProcessor.getResponse(mockRequest, tenantDomain)).thenReturn(oidcResponse);

        try (MockedStatic<AuthzServerMetadataJsonResponseBuilder> responseBuilderMock =
                     Mockito.mockStatic(AuthzServerMetadataJsonResponseBuilder.class, Mockito.CALLS_REAL_METHODS)) {

            AuthzServerMetadataJsonResponseBuilder mockBuilder = mock(AuthzServerMetadataJsonResponseBuilder.class);
            responseBuilderMock.when(() -> new AuthzServerMetadataJsonResponseBuilder()).thenReturn(mockBuilder);
            when(mockBuilder.getAuthzServerMetadataConfigString(oidcResponse)).thenReturn(expectedResponse);

            // Act
            Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(mockRequest);

            // Assert
            Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
            Assert.assertEquals(response.getEntity(), expectedResponse);
        }
    }

    @Test
    public void testGetAuthzServerMetadata_MultipleExceptionHandling() throws Exception {
        // Arrange
        String tenantDomain = "test.com";
        String oidcErrorMessage = "OIDC error";
        int oidcErrorStatus = HttpServletResponse.SC_UNAUTHORIZED;

        OIDCDiscoveryEndPointException oidcException = new OIDCDiscoveryEndPointException(oidcErrorMessage);

        when(mockCarbonContext.getTenantDomain()).thenReturn(tenantDomain);
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

    @Test
    public void testGetAuthzServerMetadata_VerifyMethodCalls() throws Exception {
        // Arrange
        String tenantDomain = "custom.tenant.com";
        String expectedResponse = "{\"test\":\"response\"}";
        // Create OIDProviderConfigResponse instance instead of string
        OIDProviderConfigResponse oidcResponse = new OIDProviderConfigResponse();
        oidcResponse.setIssuer("https://localhost:9443/oauth2/token");
        oidcResponse.setAuthorizationEndpoint("https://localhost:9443/oauth2/authorize");
        oidcResponse.setTokenEndpoint("https://localhost:9443/oauth2/token");
        oidcResponse.setUserinfoEndpoint("https://localhost:9443/oauth2/userinfo");
        oidcResponse.setJwksUri("https://localhost:9443/oauth2/jwks");

        when(mockCarbonContext.getTenantDomain()).thenReturn(tenantDomain);
        when(mockOIDCProcessor.getResponse(mockRequest, tenantDomain)).thenReturn(oidcResponse);

        try (MockedStatic<AuthzServerMetadataJsonResponseBuilder> responseBuilderMock =
                     Mockito.mockStatic(AuthzServerMetadataJsonResponseBuilder.class, Mockito.CALLS_REAL_METHODS)) {

            AuthzServerMetadataJsonResponseBuilder mockBuilder = mock(AuthzServerMetadataJsonResponseBuilder.class);
            responseBuilderMock.when(() -> new AuthzServerMetadataJsonResponseBuilder()).thenReturn(mockBuilder);
            when(mockBuilder.getAuthzServerMetadataConfigString(oidcResponse)).thenReturn(expectedResponse);

            // Act
            Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(mockRequest);

            // Assert
            Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
            Assert.assertEquals(response.getEntity(), expectedResponse);

            // Verify all method calls
            carbonContextMockedStatic.verify(CarbonContext::getThreadLocalCarbonContext, times(1));
            verify(mockCarbonContext, times(1)).getTenantDomain();
            oidcProviderServiceFactoryMockedStatic.verify(OIDCProviderServiceFactory::getOIDCService, times(1));
            verify(mockOIDCProcessor, times(1)).getResponse(mockRequest, tenantDomain);
            verify(mockBuilder, times(1)).getAuthzServerMetadataConfigString(oidcResponse);
        }
    }
}
