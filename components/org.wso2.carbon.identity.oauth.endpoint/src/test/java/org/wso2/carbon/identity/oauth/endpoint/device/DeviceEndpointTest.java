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

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.junit.Assert;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;

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
    DeviceFlowDAO deviceFlowDAO;

    @Mock
    HttpServletRequest request;

    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String TEST_URL = "testURL";

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
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
        identityDatabaseUtil.close();
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
     * @throws OAuthSystemException If failed at device endpoint.
     */
    @Test(dataProvider = "dataValues")
    public void testDevice(String clientId, int expectedStatus, boolean status)
            throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                     mockStatic(DeviceFlowPersistenceFactory.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            DeviceEndpoint deviceEndpoint = spy(new DeviceEndpoint());
            mockOAuthServerConfiguration(oAuthServerConfiguration);

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
            DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
            deviceEndpoint.setDeviceAuthService(deviceAuthService);

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
            response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<>(),
                    httpServletResponse);
            Assert.assertEquals(expectedStatus, response.getStatus());
        }
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
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
