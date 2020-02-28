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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
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
        DeviceFlowPersistenceFactory.class, HttpServletRequest.class})
public class DeviceEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    DeviceFlowPersistenceFactory deviceFlowPersistenceFactory;

    @Mock
    DeviceFlowDAO deviceFlowDAO;

    @Mock
    HttpServletRequest request;

    @Mock
    DeviceAuthServiceImpl deviceAuthService;

    private DeviceEndpoint deviceEndpoint = new DeviceEndpoint();

    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String TEST_URL = "testURL";

    @BeforeTest
    public void setUp() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, Paths.get(System.getProperty("user.dir"),
                "src", "test", "resources").toString());
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
                {"testClientId", HttpServletResponse.SC_BAD_REQUEST, true}
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
            throws IdentityOAuth2Exception, OAuthSystemException {

        mockStatic(HttpServletRequest.class);
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        oAuthClientAuthnContext.setAuthenticated(true);
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
        response = deviceEndpoint.authorize(httpServletRequest, new MultivaluedHashMap<String, String>(),
                httpServletResponse);
        Assert.assertEquals(expectedStatus, response.getStatus());
    }
}
