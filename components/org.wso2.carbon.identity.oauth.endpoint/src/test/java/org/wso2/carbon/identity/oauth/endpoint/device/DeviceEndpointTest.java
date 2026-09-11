/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.device;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.DeviceServiceFactory;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Use for unit tests in device end-point.
 */
@Listeners(MockitoTestNGListener.class)
public class DeviceEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    private TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    DeviceFlowPersistenceFactory deviceFlowPersistenceFactory;

    @Mock
    DeviceAuthServiceImpl deviceAuthService;

    @Mock
    DeviceFlowDAO deviceFlowDAO;

    @Mock
    HttpServletRequest request;

    @Mock
    BundleContext bundleContext;

    MockedConstruction<ServiceTracker> mockedConstruction;

    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String TEST_URL = "testURL";
    private static final String APPLICATION_DISABLED_MESSAGE = "Application is disabled.";

    private MockedStatic<LoggerUtils> loggerUtils;
    MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setUpClass() throws Exception {

        initiateInMemoryH2();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, Paths.get(System.getProperty("user.dir"),
                "src", "test", "resources").toString());
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        mockDatabase(identityDatabaseUtil);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(DeviceAuthService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{deviceAuthService});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
        identityDatabaseUtil.close();
        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @DataProvider(name = "provideValues")
    public Object[][] provideValues() {

        long value1 = 1000;
        return new Object[][]{
                {value1}
        };
    }

    @DataProvider(name = "dataValues")
    public Object[][] dataValues() {

        MultivaluedMap<String, String> mapWithClientId = new MultivaluedHashMap<>();
        List<String> clientId = new ArrayList<>();
        clientId.add(CLIENT_ID_VALUE);

        mapWithClientId.put(OAuth.OAUTH_CLIENT_ID, clientId);

        return new Object[][]{
                {"testClientId", HttpServletResponse.SC_BAD_REQUEST, false},
                {null, HttpServletResponse.SC_BAD_REQUEST, false},
                {"testClientId", HttpServletResponse.SC_OK, true}
        };
    }

    @Test(dataProvider = "errorResponseValues")
    public void testhandleErrorResponse(String code, String clientId) throws Exception {

        OAuthClientAuthnContext context = new OAuthClientAuthnContext();
        context.setErrorCode(code);
        context.setErrorMessage(code);
        context.setClientId(clientId);
        DeviceEndpoint deviceEndpoint = new DeviceEndpoint();
        Response response = (Response) invokePrivateMethod(deviceEndpoint, "handleErrorResponse", context);
        String res = (String) response.getEntity();
        assertTrue(res.contains(code));
    }

    @DataProvider
    public static Object[][] errorResponseValues() {

        return new Object[][]{
                {OAuth2ErrorCodes.INVALID_CLIENT, "sample-client"},
                {OAuth2ErrorCodes.INVALID_REQUEST, null},
                {OAuth2ErrorCodes.SERVER_ERROR, null}

        };
    }

    /**
     * Test the device_authorize endpoint.
     *
     * @param clientId       Consumer key of the application.
     * @param expectedStatus Expected status for response.
     * @param status         Status of user code.
     * @throws IdentityOAuth2Exception If failed at device endpoint
     * @throws OAuthSystemException    If failed at device endpoint.
     */
    @Test(dataProvider = "dataValues")
    public void testDevice(String clientId, int expectedStatus, boolean status)
            throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class)) {
            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            mockEndpointUtil(endpointUtil);

            ServiceURLBuilder mockServiceURLBuilder = Mockito.mock(ServiceURLBuilder.class);
            serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
            ServiceURL mockServiceURL = Mockito.mock(ServiceURL.class);
            lenient().when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.addParameter(anyString(), isNull())).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
            lenient().when(mockServiceURL.getAbsolutePublicURL())
                    .thenReturn("http://localhost:9443/authenticationendpoint/device.do");

            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setClientId(clientId);
            oAuthClientAuthnContext.setAuthenticated(status);
            lenient().when(request.getAttribute(anyString())).thenReturn(oAuthClientAuthnContext);

            lenient().when(httpServletRequest.getParameter(anyString())).thenReturn(clientId);
            lenient().when(httpServletRequest.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT))
                    .thenReturn(oAuthClientAuthnContext);

            Response response;
            identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                    .thenReturn(TEST_URL);
            deviceFlowPersistenceFactory.when(
                    DeviceFlowPersistenceFactory::getInstance).thenReturn(this.deviceFlowPersistenceFactory);
            lenient().when(this.deviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
            lenient().when(deviceFlowDAO.checkClientIdExist(anyString())).thenReturn(status);

            lenient().when(httpServletRequest.getParameterNames()).thenReturn(new Enumeration<String>() {
                @Override
                public boolean hasMoreElements() {
                    return false;  // Return false to simulate no parameter names
                }

                @Override
                public String nextElement() {
                    return null;  // Return null as there's no next element
                }
            });

            response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                    httpServletResponse);
            Assert.assertEquals(response.getStatus(), expectedStatus);
        }
    }

    /**
     * A disabled application must be rejected before any device code is issued. Previously the endpoint replied
     * HTTP 200 with a device_code/user_code pair that could never be exchanged, and the rejection only surfaced
     * later, at the token endpoint.
     *
     * <p>The thrown {@link InvalidApplicationClientException} is rendered by the webapp-wide
     * InvalidRequestExceptionMapper as HTTP 401 invalid_client, matching the token endpoint's response.</p>
     */
    @Test(description = "Device authorization endpoint rejects a disabled application before issuing a device code")
    public void testDeviceAuthorizeForDisabledApplication() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class);
             MockedStatic<DeviceServiceFactory> deviceServiceFactory =
                     mockStatic(DeviceServiceFactory.class)) {

            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            mockEndpointUtil(endpointUtil);
            // DeviceServiceFactory holds its service in a static final field, so stub the accessor
            // to make sure the assertions below observe this test's mock.
            deviceServiceFactory.when(DeviceServiceFactory::getDeviceAuthService)
                    .thenReturn(deviceAuthService);
            mockServiceURLBuilder(serviceURLBuilder);
            mockDeviceFlowPersistence(deviceFlowPersistenceFactory, identityUtil, true);
            mockDeviceAuthorizeRequest(CLIENT_ID_VALUE, true);
            endpointUtil.when(() -> EndpointUtil.validateAppAccess(anyString()))
                    .thenThrow(new InvalidApplicationClientException(APPLICATION_DISABLED_MESSAGE));

            InvalidApplicationClientException exception = expectThrows(InvalidApplicationClientException.class,
                    () -> deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                            httpServletResponse));

            assertEquals(exception.getMessage(), APPLICATION_DISABLED_MESSAGE,
                    "Expected the same error the token endpoint returns for a disabled application.");

            // No device or user code may be generated or persisted for a disabled application.
            verify(deviceAuthService, never())
                    .generateDeviceResponse(any(), any(), anyLong(), any(), any());
        }
    }

    /**
     * Regression guard for the happy path: an enabled application must still receive a device code, and the
     * application access check must actually be performed for it.
     */
    @Test(description = "Device authorization endpoint still issues a device code for an enabled application")
    public void testDeviceAuthorizeForEnabledApplication() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class);
             MockedStatic<DeviceServiceFactory> deviceServiceFactory =
                     mockStatic(DeviceServiceFactory.class)) {

            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            mockEndpointUtil(endpointUtil);
            // DeviceServiceFactory holds its service in a static final field, so stub the accessor
            // to make sure the assertions below observe this test's mock.
            deviceServiceFactory.when(DeviceServiceFactory::getDeviceAuthService)
                    .thenReturn(deviceAuthService);
            mockServiceURLBuilder(serviceURLBuilder);
            mockDeviceFlowPersistence(deviceFlowPersistenceFactory, identityUtil, true);
            mockDeviceAuthorizeRequest(CLIENT_ID_VALUE, true);

            Response response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                    httpServletResponse);

            assertEquals(response.getStatus(), HttpServletResponse.SC_OK,
                    "An enabled application should still receive a device authorization response.");
            endpointUtil.verify(() -> EndpointUtil.validateAppAccess(CLIENT_ID_VALUE));
            verify(deviceAuthService).generateDeviceResponse(any(), any(), anyLong(), any(), any());
        }
    }

    /**
     * The application access check is guarded on a non-blank client id, mirroring the token endpoint, so a blank
     * client id must skip it rather than fail.
     */
    @Test(description = "Blank client id skips the application access validation without failing")
    public void testDeviceAuthorizeWithBlankClientId() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class)) {

            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            mockEndpointUtil(endpointUtil);
            mockServiceURLBuilder(serviceURLBuilder);
            mockDeviceFlowPersistence(deviceFlowPersistenceFactory, identityUtil, true);
            mockDeviceAuthorizeRequest(StringUtils.EMPTY, true);

            Response response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                    httpServletResponse);

            assertEquals(response.getStatus(), HttpServletResponse.SC_OK,
                    "A blank client id should fall through to the existing behaviour.");
            endpointUtil.verify(() -> EndpointUtil.validateAppAccess(anyString()), never());
        }
    }

    /**
     * A failure while resolving the application must surface as an error rather than silently issuing a
     * device code.
     */
    @Test(description = "Application access validation failure surfaces as an error, not a device code")
    public void testDeviceAuthorizeWhenApplicationAccessValidationFails() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class)) {

            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            mockEndpointUtil(endpointUtil);
            mockServiceURLBuilder(serviceURLBuilder);
            mockDeviceFlowPersistence(deviceFlowPersistenceFactory, identityUtil, true);
            mockDeviceAuthorizeRequest(CLIENT_ID_VALUE, true);
            endpointUtil.when(() -> EndpointUtil.validateAppAccess(anyString()))
                    .thenThrow(new OAuthSystemException("Error while retrieving service provider."));

            assertThrows(OAuthSystemException.class,
                    () -> deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                            httpServletResponse));

            verify(deviceAuthService, never())
                    .generateDeviceResponse(any(), any(), anyLong(), any(), any());
        }
    }

    /**
     * The application access check must not mask a client authentication failure: the credential error still
     * wins, and the application is never looked up.
     */
    @Test(description = "Client authentication failure is still reported ahead of the application access check")
    public void testDeviceAuthorizeWhenClientAuthenticationFails() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class)) {

            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            mockEndpointUtil(endpointUtil);
            mockServiceURLBuilder(serviceURLBuilder);
            mockDeviceFlowPersistence(deviceFlowPersistenceFactory, identityUtil, false);
            mockDeviceAuthorizeRequest(CLIENT_ID_VALUE, false);

            Response response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                    httpServletResponse);

            assertEquals(response.getStatus(), HttpServletResponse.SC_BAD_REQUEST,
                    "Client authentication failure should still be reported to the client.");
            endpointUtil.verify(() -> EndpointUtil.validateAppAccess(anyString()), never());
        }
    }

    /**
     * By default the endpoint utilities behave as they do for a valid, enabled application. Individual tests
     * override {@code validateAppAccess} to exercise the failure paths.
     */
    private void mockEndpointUtil(MockedStatic<EndpointUtil> endpointUtil) {

        endpointUtil.when(() -> EndpointUtil.validateParams(any(HttpServletRequest.class),
                any(MultivaluedMap.class))).thenReturn(true);
        endpointUtil.when(EndpointUtil::getRealmInfo).thenReturn("Basic realm=localhost");
    }

    /**
     * Stub the OAuth client authentication context carried on the request.
     */
    private void mockDeviceAuthorizeRequest(String clientId, boolean clientAuthenticated) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        oAuthClientAuthnContext.setAuthenticated(clientAuthenticated);
        lenient().when(request.getAttribute(anyString())).thenReturn(oAuthClientAuthnContext);
        lenient().when(httpServletRequest.getParameter(anyString())).thenReturn(clientId);
        lenient().when(httpServletRequest.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT))
                .thenReturn(oAuthClientAuthnContext);
        lenient().when(httpServletRequest.getParameterNames()).thenReturn(new Enumeration<String>() {
            @Override
            public boolean hasMoreElements() {

                return false;
            }

            @Override
            public String nextElement() {

                return null;
            }
        });
    }

    private void mockServiceURLBuilder(MockedStatic<ServiceURLBuilder> serviceURLBuilder)
            throws URLBuilderException {

        ServiceURLBuilder mockServiceURLBuilder = Mockito.mock(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
        ServiceURL mockServiceURL = Mockito.mock(ServiceURL.class);
        lenient().when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
        lenient().when(mockServiceURLBuilder.addParameter(anyString(), isNull())).thenReturn(mockServiceURLBuilder);
        lenient().when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
        lenient().when(mockServiceURL.getAbsolutePublicURL())
                .thenReturn("http://localhost:9443/authenticationendpoint/device.do");
    }

    private void mockDeviceFlowPersistence(MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactoryMock,
                                           MockedStatic<IdentityUtil> identityUtil, boolean clientIdExists)
            throws IdentityOAuth2Exception {

        identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn(TEST_URL);
        deviceFlowPersistenceFactoryMock.when(DeviceFlowPersistenceFactory::getInstance)
                .thenReturn(this.deviceFlowPersistenceFactory);
        lenient().when(this.deviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
        lenient().when(deviceFlowDAO.checkClientIdExist(anyString())).thenReturn(clientIdExists);
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        lenient().when(mockOAuthServerConfiguration.getClientSecretPersistenceProcessor())
                .thenReturn(tokenPersistenceProcessor);
        lenient().when(mockOAuthServerConfiguration.getDeviceCodeKeySet())
                .thenReturn("abcdefghijklmnopABCDEFGHIJ123456789");
        lenient().when(mockOAuthServerConfiguration.getDeviceCodeExpiryTime()).thenReturn(60000L);
        lenient().when(mockOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {

                return invocation.getArguments()[0];
            }
        });
    }

    private Object invokePrivateMethod(Object object, String methodName, Object... params) throws Exception {

        Class<?>[] paramTypes = new Class[params.length];
        for (int i = 0; i < params.length; i++) {
            paramTypes[i] = params[i].getClass();
        }
        Method method = object.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);

        try {
            return method.invoke(object, params);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getTargetException();
        }
    }
}
