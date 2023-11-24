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

import com.nimbusds.jwt.SignedJWT;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.junit.Assert;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.CarbonUtils;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Use for unit tests in device end-point.
 */
@PrepareForTest({OAuth2Util.class, SessionDataCache.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class,
        EndpointUtil.class, FrameworkUtils.class, EndpointUtil.class, OpenIDConnectUserRPStore.class,
        CarbonOAuthAuthzRequest.class, IdentityTenantUtil.class, OAuthResponse.class, SignedJWT.class,
        OIDCSessionManagementUtil.class, CarbonUtils.class, SessionDataCache.class, IdentityUtil.class,
        DeviceFlowPersistenceFactory.class, HttpServletRequest.class, OAuthServerConfiguration.class,
        TokenPersistenceProcessor.class, ServiceURLBuilder.class, ServiceURL.class, LoggerUtils.class})
public class DeviceEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    private TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    DeviceFlowPersistenceFactory deviceFlowPersistenceFactory;

    @Mock
    DeviceFlowDAO deviceFlowDAO;

    @Mock
    HttpServletRequest request;

    @Mock
    DeviceAuthServiceImpl deviceAuthService;


    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String TEST_URL = "testURL";

    @BeforeMethod
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, Paths.get(System.getProperty("user.dir"),
                "src", "test", "resources").toString());
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    @DataProvider(name = "provideValues")
    public Object[][] provideValues() {

        long value1 = 1000;
        return new Object[][]{
                {value1}
        };
    }

    @Test(dataProvider = "provideValues")
    public void testStringValueInSeconds(long value) throws Exception {

        DeviceEndpoint deviceEndpoint = new DeviceEndpoint();
        String realValue = "1";
        assertEquals(WhiteboxImpl.invokeMethod(deviceEndpoint, "stringValueInSeconds", value),
                realValue);
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
        Response response = WhiteboxImpl.invokeMethod(deviceEndpoint, "handleErrorResponse", context);
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

        DeviceEndpoint deviceEndpoint = PowerMockito.spy(new DeviceEndpoint());
        mockOAuthServerConfiguration();
        mockStatic(ServiceURLBuilder.class);
        mockStatic(ServiceURL.class);

        ServiceURLBuilder mockServiceURLBuilder = Mockito.mock(ServiceURLBuilder.class);
        ServiceURL mockServiceURL = Mockito.mock(ServiceURL.class);
        when(ServiceURLBuilder.create()).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addParameter(anyString(), isNull())).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
        when(mockServiceURL.getAbsolutePublicURL())
                .thenReturn("http://localhost:9443/authenticationendpoint/device.do");

        mockStatic(HttpServletRequest.class);
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        oAuthClientAuthnContext.setAuthenticated(status);
        when(request.getAttribute(anyString())).thenReturn(oAuthClientAuthnContext);
        DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
        deviceEndpoint.setDeviceAuthService(deviceAuthService);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
        when(httpServletRequest.getParameter(anyString())).thenReturn(clientId);
        Response response;
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(TEST_URL);
        mockStatic(DeviceFlowPersistenceFactory.class);
        when(DeviceFlowPersistenceFactory.getInstance()).thenReturn(deviceFlowPersistenceFactory);
        when(deviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
        when(deviceFlowDAO.checkClientIdExist(anyString())).thenReturn(status);
        PowerMockito.when(deviceEndpoint, "getValidationObject", httpServletRequest)
                .thenReturn(oAuthClientAuthnContext);
        response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<String, String>(),
                httpServletResponse);
        Assert.assertEquals(expectedStatus, response.getStatus());
    }

    private void mockOAuthServerConfiguration() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(oAuthServerConfiguration.getDeviceCodeKeySet()).thenReturn("abcdefghijklmnopABCDEFGHIJ123456789");
        when(oAuthServerConfiguration.getDeviceCodeExpiryTime()).thenReturn(60000L);
        when(oAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {

                return invocation.getArguments()[0];
            }
        });
    }
}
