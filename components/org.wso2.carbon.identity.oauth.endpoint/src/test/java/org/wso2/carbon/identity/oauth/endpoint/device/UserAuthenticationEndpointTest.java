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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Use for unit tests in user authentication end-point.
 */
@Listeners(MockitoTestNGListener.class)
public class UserAuthenticationEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    DeviceFlowPersistenceFactory mockDeviceFlowPersistenceFactory;

    @Mock
    DeviceFlowDAO deviceFlowDAO;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2AuthzEndpoint oAuth2AuthzEndpoint;

    @Mock
    Response response;

    @Mock
    UserAuthenticationEndpoint userAuthenticationEndpoint;

    @Mock
    ServiceURLBuilder mockServiceURLBuilder;

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
    private static final List<String> scopes = new ArrayList<>(Collections.singleton("openid"));
    private static final String TEST_DEVICE_CODE = "testDeviceCode";

    MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setUp() throws Exception {

        deviceFlowDOAsNotExpired.setStatus(PENDING);
        deviceFlowDOAsNotExpired.setExpiryTime(new Timestamp(date.getTime() + 400000000));
        deviceFlowDOAsNotExpired.setDeviceCode(TEST_DEVICE_CODE);
        deviceFlowDOAsNotExpired.setScopes(scopes);

        deviceFlowDOAsExpired.setStatus(PENDING);
        deviceFlowDOAsExpired.setExpiryTime(new Timestamp(date.getTime() - 400000000));
        deviceFlowDOAsExpired.setDeviceCode(TEST_DEVICE_CODE);
        deviceFlowDOAsExpired.setScopes(scopes);

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        initiateInMemoryH2();
    }

    @AfterClass
    public void tearDown() throws Exception {

        cleanData();
    }

    @BeforeMethod
    public void setUpBeforeMethod() {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        mockDatabase(identityDatabaseUtil);
    }

    @AfterMethod
    public void tearDownAfterMethod() {

        identityDatabaseUtil.close();
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

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);

            setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);

            try (MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                         mockStatic(DeviceFlowPersistenceFactory.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {

                deviceFlowPersistenceFactory.when(
                        DeviceFlowPersistenceFactory::getInstance).thenReturn(mockDeviceFlowPersistenceFactory);
                lenient().when(mockDeviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
                lenient().when(deviceFlowDAO.getClientIdByUserCode(anyString())).thenReturn(clientId);
                lenient().when(deviceFlowDAO.getDetailsForUserCode(anyString())).thenReturn(deviceFlowDOAsNotExpired);
                when(httpServletRequest.getParameter(anyString())).thenReturn(userCode);

                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
                lenient().when(oAuthAppDO.getCallbackUrl()).thenReturn(uri);
                Response response1;

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.addParameter(any(), any())).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
                lenient().when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);

                lenient().when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class),
                        any(HttpServletResponse.class))).thenReturn(response);
                DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
                userAuthenticationEndpoint = new UserAuthenticationEndpoint();
                userAuthenticationEndpoint.setDeviceAuthService(deviceAuthService);
                setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
                response1 = userAuthenticationEndpoint.deviceAuthorize(httpServletRequest, httpServletResponse);
                Assert.assertNotNull(response1);
            }
        }
    }

    /**
     * Mock oauth server configuration.
     *
     * @throws Exception Error while mocking oauth server configuration.
     */
    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        lenient().when(mockOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
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

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);

            setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);

            try (MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                         mockStatic(DeviceFlowPersistenceFactory.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {

                deviceFlowPersistenceFactory.when(
                        DeviceFlowPersistenceFactory::getInstance).thenReturn(mockDeviceFlowPersistenceFactory);
                when(mockDeviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
                lenient().when(deviceFlowDAO.getClientIdByUserCode(anyString())).thenReturn(clientId);
                when(deviceFlowDAO.getDetailsForUserCode(anyString())).thenReturn(deviceFlowDOAsNotExpired);
                when(httpServletRequest.getParameter(anyString())).thenReturn(userCode);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
                lenient().when(oAuthAppDO.getCallbackUrl()).thenReturn(uri);
                Response response1;

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.addParameter(any(), any())).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.build())
                        .thenThrow(new URLBuilderException("Throwing URLBuilderException."));
                lenient().when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);

                when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class),
                        any(HttpServletResponse.class))).
                        thenReturn(response);
                DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
                userAuthenticationEndpoint = new UserAuthenticationEndpoint();
                userAuthenticationEndpoint.setDeviceAuthService(deviceAuthService);
                setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
                response1 = userAuthenticationEndpoint.deviceAuthorize(httpServletRequest, httpServletResponse);
                if (expectedValue == HttpServletResponse.SC_ACCEPTED) {
                    Assert.assertNotNull(response1);
                } else {
                    Assert.assertNull(response1);
                }
            }
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

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);

            setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);

            try (MockedStatic<DeviceFlowPersistenceFactory> deviceFlowPersistenceFactory =
                         mockStatic(DeviceFlowPersistenceFactory.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {
                deviceFlowPersistenceFactory.when(
                        DeviceFlowPersistenceFactory::getInstance).thenReturn(mockDeviceFlowPersistenceFactory);
                when(mockDeviceFlowPersistenceFactory.getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
                lenient().when(deviceFlowDAO.getClientIdByUserCode(anyString())).thenReturn(clientId);
                when(deviceFlowDAO.getDetailsForUserCode(anyString())).thenReturn(deviceFlowDOAsExpired);
                when(httpServletRequest.getParameter(anyString())).thenReturn(userCode);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
                lenient().when(oAuthAppDO.getCallbackUrl()).thenReturn(uri);
                Response response1;
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
                when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);
                when(mockServiceURLBuilder.addParameter(any(), any())).thenReturn(mockServiceURLBuilder);
                when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
                when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);
                lenient().doThrow(new IOException("Throwing IOException.")).when(httpServletResponse)
                        .sendRedirect(TEST_URL);

                lenient().when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class),
                                any(HttpServletResponse.class))).thenReturn(response);
                DeviceAuthServiceImpl deviceAuthService = new DeviceAuthServiceImpl();
                userAuthenticationEndpoint = new UserAuthenticationEndpoint();
                userAuthenticationEndpoint.setDeviceAuthService(deviceAuthService);
                setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
                response1 = userAuthenticationEndpoint.deviceAuthorize(httpServletRequest, httpServletResponse);
                if (expectedValue == HttpServletResponse.SC_ACCEPTED) {
                    Assert.assertNotNull(response1);
                } else {
                    Assert.assertNull(response1);
                }
            }
        }
    }

    private void setInternalState(Object object, String fieldName, Object value)
            throws NoSuchFieldException, IllegalAccessException {

        // set internal state of an object using java reflection
        Field declaredField = object.getClass().getDeclaredField(fieldName);
        declaredField.setAccessible(true);
        declaredField.set(object, value);
    }
}
