/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.lang.StringUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuth2TokenValidatorServiceFactory;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@Listeners(MockitoTestNGListener.class)
public class UserInfoISAccessTokenValidatorTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private OAuth2TokenValidationService oAuth2TokenValidationService;

    @Mock
    private DefaultTokenProvider defaultTokenProvider;

    @Mock
    BundleContext bundleContext;

    MockedConstruction<ServiceTracker> mockedConstruction;

    private AutoCloseable closeable;
    private UserInforRequestDefaultValidator userInforRequestDefaultValidator;
    private UserInfoISAccessTokenValidator userInfoISAccessTokenValidator;
    private final String token = "ZWx1c3VhcmlvOnlsYWNsYXZl";
    private static final String contentTypeHeaderValue = "application/x-www-form-urlencoded";

    @BeforeClass
    public void setup() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, Paths.get(System.getProperty("user.dir"),
                "src", "test", "resources").toString());

        userInforRequestDefaultValidator = new UserInforRequestDefaultValidator();
        userInfoISAccessTokenValidator = new UserInfoISAccessTokenValidator();
        if (mockedConstruction != null) {
            mockedConstruction.close();
        }
    }

    @BeforeMethod
    public void setUp() {

        closeable = openMocks(this);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(OAuth2TokenValidationService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2TokenValidationService});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
        closeable.close();
    }

    @Test
    public void testValidateToken() throws Exception {

        String bearerAuthHeader = "Bearer " + token;
        prepareHttpServletRequest(bearerAuthHeader, null);
        assertEquals(bearerAuthHeader.split(" ")[1], userInforRequestDefaultValidator.validateRequest
                (httpServletRequest));
    }

    @DataProvider
    public Object[][] getAuthorizationScenarios() {
        String dpopAuthHeaderWithToken = "DPoP " + token;
        return new Object[][]{
                // Valid DPoP token with proof header
                {dpopAuthHeaderWithToken, contentTypeHeaderValue, "mocked-dpop-proof", null},
                // Missing DPoP proof header
                {dpopAuthHeaderWithToken, contentTypeHeaderValue, null,
                        "DPoP header is required with DPoP tokens"},
                {dpopAuthHeaderWithToken, contentTypeHeaderValue, "",
                        "DPoP header is required with DPoP tokens"},
                {dpopAuthHeaderWithToken, contentTypeHeaderValue, " ",
                        "DPoP header is required with DPoP tokens"},
                // Unsupported token scheme
                {"Basic " + token, contentTypeHeaderValue, null,
                        "Bearer token missing"},
        };
    }

    @Test(dataProvider = "getAuthorizationScenarios")
    public void testAuthorizationScenarios(String authHeader, String contentType, String dpopHeader,
                                           String expectedExceptionMessage) {

        prepareHttpServletRequest(authHeader, contentType);
        if (StringUtils.isNotBlank(dpopHeader)) {
            when(httpServletRequest.getHeader("DPoP")).thenReturn(dpopHeader);
        }

        try {
            String validatedToken = userInforRequestDefaultValidator.validateRequest(httpServletRequest);
            if (expectedExceptionMessage != null) {
                fail("Expected exception with message: " + expectedExceptionMessage);
            }
            assertEquals(validatedToken, token);
        } catch (UserInfoEndpointException userInfoEndpointException) {
            if (expectedExceptionMessage == null) {
                fail("Did not expect exception, but got: " + userInfoEndpointException.getMessage());
            }
            assertEquals(userInfoEndpointException.getMessage(), expectedExceptionMessage);
        }
    }

    @DataProvider
    public Object[][] getInvalidAuthorizations() {

        return new Object[][]{
                {token, null},
                {"Bearer", null},
                {null, "application/text"},
                {null, ""},
        };
    }

    @Test(dataProvider = "getInvalidAuthorizations", expectedExceptions = UserInfoEndpointException.class)
    public void testValidateTokenInvalidAuthorization(String authorization, String contentType) throws Exception {

        prepareHttpServletRequest(authorization, contentType);
        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }

    @DataProvider
    public Object[][] getValidBearerTokenAuthorizations() {

        return new Object[][]{
                {"Bearer" + " " + token},
                {"bearer" + " " + token},
                {"bEARER" + " " + token},
        };
    }

    @Test(dataProvider = "getValidBearerTokenAuthorizations")
    public void testValidateTokenAuthorization(String authorization) throws Exception {

        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorization);
        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }
    @DataProvider
    public Object[][] requestBodyWithNonASCII() {

        return new Object[][]{
                {contentTypeHeaderValue, "access_token=" + "¥" + token, token},
                {contentTypeHeaderValue, "access_token=" + "§" + token +
                        "&someOtherParam=value", token},
                {contentTypeHeaderValue, "otherParam=value2©&access_token=" + token +
                        "&someOtherParam=value", token},
        };
    }

    @DataProvider
    public Object[][] getTokens() {

        return new Object[][]{
                {"48544572-a796-3d42-a571-505bc609acd8"},
        };
    }

    @Test(dataProvider = "getTokens", expectedExceptions = UserInfoEndpointException.class)
    public void testTokenValidation(String accessTokenIdentifier) throws Exception {

        prepareOAuth2TokenValidationService();

        try (MockedStatic<OAuth2TokenValidatorServiceFactory> utilServiceHolder =
                     mockStatic(OAuth2TokenValidatorServiceFactory.class)) {
            utilServiceHolder.when(OAuth2TokenValidatorServiceFactory::getOAuth2TokenValidatorService)
                    .thenReturn(oAuth2TokenValidationService);

            OAuth2TokenValidationResponseDTO responseDTO = userInfoISAccessTokenValidator
                    .validateToken(accessTokenIdentifier);
            assertEquals(responseDTO.getAuthorizationContextToken().getTokenString(), accessTokenIdentifier);
        }
    }

    @Test(dataProvider = "getTokens", expectedExceptions = UserInfoEndpointException.class)
    public void testTokenValidationVerifyTokenError(String accessTokenIdentifier) throws Exception {

        prepareOAuth2TokenValidationService();

        try (MockedStatic<OAuth2TokenValidatorServiceFactory> utilServiceHolder =
                     mockStatic(OAuth2TokenValidatorServiceFactory.class)) {
            utilServiceHolder.when(OAuth2TokenValidatorServiceFactory::getOAuth2TokenValidatorService)
                    .thenReturn(oAuth2TokenValidationService);

            OAuth2TokenValidationResponseDTO mockedResponseDTO = new OAuth2TokenValidationResponseDTO();
            mockedResponseDTO.setValid(true);
            when(oAuth2TokenValidationService.validate(any())).thenReturn(mockedResponseDTO);

            OAuth2ServiceComponentHolder.getInstance().setTokenProvider(defaultTokenProvider);
            lenient().when(OAuth2ServiceComponentHolder.getInstance().getTokenProvider().getVerifiedAccessToken(
                    accessTokenIdentifier, false)).thenThrow(
                            new IdentityOAuth2Exception("Error in getting AccessToken"));
            userInfoISAccessTokenValidator.validateToken(accessTokenIdentifier);
        }
    }

    @Test(expectedExceptions = UserInfoEndpointException.class)
    public void testValidateTokenWithWrongInputStream() throws Exception {

        prepareHttpServletRequest(null, contentTypeHeaderValue);

        when(httpServletRequest.getInputStream()).thenThrow(new IOException());

        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }

    private void prepareOAuth2TokenValidationService() {

        when(oAuth2TokenValidationService.validate(any()))
                .thenReturn(new OAuth2TokenValidationResponseDTO());
    }

    private void prepareHttpServletRequest(String authorization, String contentType) {

        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorization);
        lenient().when(httpServletRequest.getHeader(HttpHeaders.CONTENT_TYPE)).thenReturn(contentType);
    }

    @DataProvider
    public Object[][] requestBody() {

        return new Object[][]{{contentTypeHeaderValue, "", null}, {contentTypeHeaderValue, null, null},
                {contentTypeHeaderValue, "access_token=" + token, token},
                {contentTypeHeaderValue, "access_token=" + token + "&someOtherParam=value", token},
                {contentTypeHeaderValue, "otherParam=value2&access_token=" + token + "&someOtherParam=value", token}};
    }

    @Test(dataProvider = "requestBody")
    public void testValidateTokenWithRequestBodySuccess(String contentType, String requestBody, String expected)
            throws Exception {

        String token = testValidateTokenWithRequestBody(contentType, requestBody, true);
        assertEquals(token, expected, "Expected token did not receive");
    }

    private String testValidateTokenWithRequestBody(String contentType, String requestBody, boolean mockScanner)
            throws Exception {

        prepareHttpServletRequest(null, contentType);
        if (mockScanner) {
            ServletInputStream inputStream = new ServletInputStream() {
                private InputStream stream =
                        new ByteArrayInputStream(requestBody == null ? "".getBytes() : requestBody.getBytes());

                @Override
                public int read() throws IOException {

                    return stream.read();
                }
            };
            doReturn(inputStream).when(httpServletRequest).getInputStream();
        } else {
            when(httpServletRequest.getInputStream()).thenThrow(new IOException());
        }
        return userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }
}
