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
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.IOException;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Use for unit tests in user authentication end-point.
 */
@PrepareForTest({OAuth2Util.class, SessionDataCache.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class,
        EndpointUtil.class, FrameworkUtils.class, EndpointUtil.class, OpenIDConnectUserRPStore.class,
        CarbonOAuthAuthzRequest.class, IdentityTenantUtil.class, OAuthResponse.class, SignedJWT.class,
        OIDCSessionManagementUtil.class, CarbonUtils.class, SessionDataCache.class, ServiceURLBuilder.class,
        ServiceURL.class, DeviceFlowPersistenceFactory.class, OAuth2AuthzEndpoint.class})
public class UserAuthenticationEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    DeviceFlowPersistenceFactory deviceFlowPersistenceFactory;

    @Mock
    DeviceFlowDAO deviceFlowDAO;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2AuthzEndpoint oAuth2AuthzEndpoint;

    @Mock
    Response response;

    @Mock
    UserAuthenticationEndpoint userAuthenticationEndpoint;

    @Mock
    ServiceURLBuilder serviceURLBuilder;

    @Mock
    ServiceURL serviceURL;

    private static final String TEST_USER_CODE = "testUserCode";
    private static final String TEST_URL = "testURL";
    private static final String PENDING = "PENDING";
    private static final String USED = "USED";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";

    private static final Date date = new Date();
    private static DeviceFlowDO deviceFlowDOAsNotExpired = new DeviceFlowDO();
    private static DeviceFlowDO deviceFlowDOAsExpired = new DeviceFlowDO();
    private static final String[] scopes = {"openid"};
    private static final String TEST_DEVICE_CODE = "testDeviceCode";

    @BeforeTest
    public void setUp() {

        deviceFlowDOAsNotExpired.setStatus(PENDING);
        deviceFlowDOAsNotExpired.setExpiryTime(new Timestamp(date.getTime() + 400000000));
        deviceFlowDOAsNotExpired.setDeviceCode(TEST_DEVICE_CODE);

        deviceFlowDOAsExpired.setStatus(PENDING);
        deviceFlowDOAsExpired.setExpiryTime(new Timestamp(date.getTime() - 400000000));
        deviceFlowDOAsExpired.setDeviceCode(TEST_DEVICE_CODE);

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
    }

    @DataProvider(name = "providePostParams")
    public Object[][] providePostParams() {

        return new Object[][]{
                {TEST_USER_CODE, null, 0, USED, TEST_URL},
                {null, null, 0, USED, null},
                {TEST_USER_CODE, CLIENT_ID_VALUE, HttpServletResponse.SC_ACCEPTED, PENDING, TEST_URL},
                {TEST_USER_CODE, CLIENT_ID_VALUE, HttpServletResponse.SC_ACCEPTED, PENDING, null}
        };
    }

    /**
     * Test device endpoint.
     *
     * @param userCode      User code of the user.
     * @param clientId      Consumer key of the application.
     * @param expectedValue Expected http status.
     * @param status        Status of user code.
     * @param uri           Redirection uri.
     * @throws Exception Error while testing device endpoint.
     */
    @Test(dataProvider = "providePostParams")
    public void testDeviceAuthorize(String userCode, String clientId, int expectedValue, String status, String uri)
            throws Exception {

        mockOAuthServerConfiguration();

        WhiteboxImpl.setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        mockStatic(DeviceFlowPersistenceFactory.class);
        when(DeviceFlowPersistenceFactory.getInstance()).thenReturn(deviceFlowPersistenceFactory);
        when(deviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
        when(deviceFlowDAO.getClientIdByUserCode(anyString())).thenReturn(clientId);
        when(deviceFlowDAO.getDetailsForUserCode(anyString())).thenReturn(deviceFlowDOAsNotExpired);
        when(deviceFlowDAO.getScopesForUserCode(anyString())).thenReturn(scopes);
        when(httpServletRequest.getParameter(anyString())).thenReturn(userCode);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        when(oAuthAppDO.getCallbackUrl()).thenReturn(uri);
        Response response1;
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(any(), any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
        when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);

        when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class), any(HttpServletResponse.class)))
                .thenReturn(response);
        DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
        userAuthenticationEndpoint = new UserAuthenticationEndpoint();
        userAuthenticationEndpoint.setDeviceAuthService(deviceAuthService);
        WhiteboxImpl.setInternalState(userAuthenticationEndpoint, OAuth2AuthzEndpoint.class, oAuth2AuthzEndpoint);
        response1 = userAuthenticationEndpoint.deviceAuthorize(httpServletRequest, httpServletResponse);
        if (expectedValue == HttpServletResponse.SC_ACCEPTED) {
            Assert.assertNotNull(response1);
        } else {
            Assert.assertNotNull(response1.getMetadata().get("Location").get(0).toString());
        }
    }

    /**
     * Mock oauth server configuration.
     *
     * @throws Exception Error while mocking oauth server configuration.
     */
    private void mockOAuthServerConfiguration() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(oAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {

                return invocation.getArguments()[0];
            }
        });
    }

    @DataProvider(name = "providePostParamsForURLBuilderExceptionPath")
    public Object[][] providePostParamsForURLBuilderExceptionPath() {

        return new Object[][]{
                {TEST_USER_CODE, null, HttpServletResponse.SC_ACCEPTED, PENDING, TEST_URL},
                {TEST_USER_CODE, CLIENT_ID_VALUE, HttpServletResponse.SC_ACCEPTED, PENDING, null}
        };
    }

    /**
     * Test device endpoint throwing URLBuilderException.
     *
     * @param userCode      User code of the user.
     * @param clientId      Consumer key of the application.
     * @param expectedValue Expected http status.
     * @param status        Status of user code.
     * @param uri           Redirection uri.
     * @throws Exception Error while testing device endpoint throwing URLBuilderException.
     */
    @Test(dataProvider = "providePostParamsForURLBuilderExceptionPath")
    public void testDeviceAuthorizeForURLBuilderExceptionPath(String userCode, String clientId, int expectedValue,
                                                              String status, String uri) throws Exception {

        mockOAuthServerConfiguration();

        WhiteboxImpl.setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        mockStatic(DeviceFlowPersistenceFactory.class);
        when(DeviceFlowPersistenceFactory.getInstance()).thenReturn(deviceFlowPersistenceFactory);
        when(deviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
        when(deviceFlowDAO.getClientIdByUserCode(anyString())).thenReturn(clientId);
        when(deviceFlowDAO.getDetailsForUserCode(anyString())).thenReturn(deviceFlowDOAsNotExpired);
        when(deviceFlowDAO.getScopesForUserCode(anyString())).thenReturn(scopes);
        when(httpServletRequest.getParameter(anyString())).thenReturn(userCode);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        when(oAuthAppDO.getCallbackUrl()).thenReturn(uri);
        Response response1;
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(any(), any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenThrow(new URLBuilderException("Throwing URLBuilderException."));
        when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);

        when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class), any(HttpServletResponse.class))).
                thenReturn(response);
        DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
        userAuthenticationEndpoint = new UserAuthenticationEndpoint();
        userAuthenticationEndpoint.setDeviceAuthService(deviceAuthService);
        WhiteboxImpl.setInternalState(userAuthenticationEndpoint, OAuth2AuthzEndpoint.class, oAuth2AuthzEndpoint);
        response1 = userAuthenticationEndpoint.deviceAuthorize(httpServletRequest, httpServletResponse);
        if (expectedValue == HttpServletResponse.SC_ACCEPTED) {
            Assert.assertNotNull(response1);
        } else {
            Assert.assertNull(response1);
        }
    }

    @DataProvider(name = "providePostParamsForIOExceptionPath")
    public Object[][] providePostParamsForIOExceptionPath() {

        return new Object[][]{
                {TEST_USER_CODE, null, HttpServletResponse.SC_ACCEPTED, PENDING, TEST_URL},
                {TEST_USER_CODE, CLIENT_ID_VALUE, HttpServletResponse.SC_ACCEPTED, PENDING, null}
        };
    }

    /**
     * Test device endpoint throwing IOException.
     *
     * @param userCode      User code of the user.
     * @param clientId      Consumer key of the application.
     * @param expectedValue Expected http status.
     * @param status        Status of user code.
     * @param uri           Redirection uri.
     * @throws Exception Error while testing device endpoint throwing IOException.
     */
    @Test(dataProvider = "providePostParamsForIOExceptionPath")
    public void testDeviceAuthorizeForIOExceptionPath(String userCode, String clientId, int expectedValue,
                                                      String status, String uri) throws Exception {

        mockOAuthServerConfiguration();

        WhiteboxImpl.setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        mockStatic(DeviceFlowPersistenceFactory.class);
        when(DeviceFlowPersistenceFactory.getInstance()).thenReturn(deviceFlowPersistenceFactory);
        when(deviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
        when(deviceFlowDAO.getClientIdByUserCode(anyString())).thenReturn(clientId);
        when(deviceFlowDAO.getDetailsForUserCode(anyString())).thenReturn(deviceFlowDOAsExpired);
        when(deviceFlowDAO.getScopesForUserCode(anyString())).thenReturn(scopes);
        when(httpServletRequest.getParameter(anyString())).thenReturn(userCode);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        when(oAuthAppDO.getCallbackUrl()).thenReturn(uri);
        Response response1;
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(any(), any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
        when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);
        Mockito.doThrow(new IOException("Throwing IOException.")).when(httpServletResponse).sendRedirect(TEST_URL);

        when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class), any(HttpServletResponse.class)))
                .thenReturn(response);
        DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
        userAuthenticationEndpoint = new UserAuthenticationEndpoint();
        userAuthenticationEndpoint.setDeviceAuthService(deviceAuthService);
        WhiteboxImpl.setInternalState(userAuthenticationEndpoint, OAuth2AuthzEndpoint.class, oAuth2AuthzEndpoint);
        response1 = userAuthenticationEndpoint.deviceAuthorize(httpServletRequest, httpServletResponse);
        if (expectedValue == HttpServletResponse.SC_ACCEPTED) {
            Assert.assertNotNull(response1);
        } else {
            Assert.assertNull(response1);
        }
    }
}
