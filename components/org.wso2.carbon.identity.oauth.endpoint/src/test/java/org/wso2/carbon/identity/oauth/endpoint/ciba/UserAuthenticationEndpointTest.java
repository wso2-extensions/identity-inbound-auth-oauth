/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthService;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Field;
import java.nio.file.Paths;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_AUTH_CODE_KEY;

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
    CibaDAOFactory mockCibaDAOFactory;

    @Mock
    CibaMgtDAO cibaMgtDAO;

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

    @Mock
    PrivilegedCarbonContext mockPrivilegedCarbonContext;

    private static final String TEST_AUTH_CODE_KEY = "testAuthCodeKey";
    private static final String TEST_URL = "testURL";

    private static CibaAuthCodeDO validCibaDOA = new CibaAuthCodeDO();
    private static CibaAuthCodeDO invalidCibaDOA = new CibaAuthCodeDO();

    @BeforeClass
    public void setUp() throws Exception {

        validCibaDOA.setAuthReqStatus(AuthReqStatus.REQUESTED);

        invalidCibaDOA.setAuthReqStatus(AuthReqStatus.EXPIRED);

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        initiateInMemoryH2();
    }

    @AfterClass
    public void tearDown() throws Exception {

        cleanData();
        PrivilegedCarbonContext.endTenantFlow();
    }

    /**
     * Test valid ciba auth request.
     *
     * @throws Exception Error while testing device endpoint.
     */
    @Test
    public void testCibaAuthValidRequest() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext
                     = mockStatic(PrivilegedCarbonContext.class)) {
            CibaAuthServiceImpl cibaAuthService = new CibaAuthServiceImpl();

            privilegedCarbonContext.when(
                    PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockPrivilegedCarbonContext);
            lenient().when(mockPrivilegedCarbonContext.getOSGiService(CibaAuthService.class, null))
                    .thenReturn(cibaAuthService);

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);

            try (MockedStatic<CibaDAOFactory> cibaDAOFactory =
                         mockStatic(CibaDAOFactory.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {

                cibaDAOFactory.when(
                        CibaDAOFactory::getInstance).thenReturn(mockCibaDAOFactory);
                lenient().when(mockCibaDAOFactory.getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);
                lenient().when(cibaMgtDAO.getCibaAuthCode(anyString())).thenReturn(validCibaDOA);
                when(httpServletRequest.getParameter(CIBA_AUTH_CODE_KEY)).thenReturn(TEST_AUTH_CODE_KEY);

                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);

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
                userAuthenticationEndpoint = new UserAuthenticationEndpoint();
                setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);
                Response response = userAuthenticationEndpoint.cibaAuth(httpServletRequest, httpServletResponse);
                Assert.assertNotNull(response);
            }
        }
    }

    /**
     * Test invalid ciba auth request.
     *
     * @throws Exception Error while testing device endpoint.
     */
    @Test
    public void testCibaAuthInValidRequest() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class)) {

            when(httpServletRequest.getParameter(CIBA_AUTH_CODE_KEY)).thenReturn(null);

            serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.addParameter(any(), any())).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
            lenient().when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);

            lenient().when(oAuth2AuthzEndpoint.authorize(any(CommonAuthRequestWrapper.class),
                    any(HttpServletResponse.class))).thenReturn(response);
            userAuthenticationEndpoint = new UserAuthenticationEndpoint();
            Response response = userAuthenticationEndpoint.cibaAuth(httpServletRequest, httpServletResponse);
            Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST, response.getStatus());
        }
    }

    /**
     * Test ciba auth AuthCodeKey request.
     *
     * @throws Exception Error while testing device endpoint.
     */
    @Test
    public void testCibaAuthExpiredAuthCodeKeyRequest() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext
                     = mockStatic(PrivilegedCarbonContext.class)) {
            CibaAuthServiceImpl cibaAuthService = new CibaAuthServiceImpl();

            privilegedCarbonContext.when(
                    PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockPrivilegedCarbonContext);
            lenient().when(mockPrivilegedCarbonContext.getOSGiService(CibaAuthService.class, null))
                    .thenReturn(cibaAuthService);

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            setInternalState(userAuthenticationEndpoint, "oAuth2AuthzEndpoint", oAuth2AuthzEndpoint);

            try (MockedStatic<CibaDAOFactory> cibaDAOFactory =
                         mockStatic(CibaDAOFactory.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {

                cibaDAOFactory.when(
                        CibaDAOFactory::getInstance).thenReturn(mockCibaDAOFactory);
                lenient().when(mockCibaDAOFactory.getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);
                lenient().when(cibaMgtDAO.getCibaAuthCode(anyString())).thenReturn(invalidCibaDOA);
                when(httpServletRequest.getParameter(CIBA_AUTH_CODE_KEY)).thenReturn(TEST_AUTH_CODE_KEY);

                serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.addParameter(any(), any())).thenReturn(mockServiceURLBuilder);
                lenient().when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
                lenient().when(serviceURL.getAbsolutePublicURL()).thenReturn(TEST_URL);

                userAuthenticationEndpoint = new UserAuthenticationEndpoint();
                Response response = userAuthenticationEndpoint.cibaAuth(httpServletRequest, httpServletResponse);
                Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST, response.getStatus());
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
