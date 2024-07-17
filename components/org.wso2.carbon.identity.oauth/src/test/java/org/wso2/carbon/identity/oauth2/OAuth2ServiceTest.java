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

package org.wso2.carbon.identity.oauth2;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAOImpl;
import org.wso2.carbon.identity.oauth2.device.response.DeviceFlowResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.AssertJUnit.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.RESPONSE_TYPE_DEVICE;
import static org.wso2.carbon.identity.openidconnect.model.Constants.REDIRECT_URI;
import static org.wso2.carbon.identity.openidconnect.model.Constants.RESPONSE_TYPE;

/**
 * This class tests the OAuth2Service class.
 */
@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class OAuth2ServiceTest {

    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;

    @Mock
    private AuthorizationHandlerManager mockAuthorizationHandlerManager;

    @Mock
    private OAuth2AuthorizeRespDTO mockedOAuth2AuthorizeRespDTO;

    @Mock
    private OAuthAppDAO oAuthAppDAO;

    @Mock
    private AuthenticatedUser authenticatedUser;

    @Mock
    private OAuthEventInterceptor oAuthEventInterceptorProxy;

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    private OAuthComponentServiceHolder mockOAuthComponentServiceHolder;

    @Mock
    private OAuthCache mockOAuthCache;

    @Mock
    private HttpServletRequest mockHttpServletRequest;

    private OAuth2Service oAuth2Service;
    private static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";
    private MockedStatic<LoggerUtils> loggerUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        oAuth2Service = new OAuth2Service();
        setPrivateField(OAuthServerConfiguration.getInstance(), "timeStampSkewInSeconds", 3600L);
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
    }

    /**
     * DataProvider: grantType, callbackUrl, tenantDomain, callbackURI
     */
    @DataProvider(name = "ValidateClientInfoDataProvider")
    public Object[][] validateClientDataProvider() {

        return new Object[][]{
                {UUID.randomUUID().toString(), "dummyGrantType", "dummyCallBackUrl", "carbon.super", -1234, null},
                {UUID.randomUUID().toString(), "dummyGrantType", "regexp=dummyCallBackUrl", "carbon.super", -1234,
                        "dummyCallBackUrl"},
                {UUID.randomUUID().toString(), "dummyGrantType", "dummyCallBackUrl", "carbon.super", -1234,
                        "dummyCallBackUrl"}
        };
    }

    @Test
    public void testAuthorize() throws Exception {

        try (MockedStatic<AuthorizationHandlerManager> authorizationHandlerManager = mockStatic(
                AuthorizationHandlerManager.class)) {
            authorizationHandlerManager.when(
                    AuthorizationHandlerManager::getInstance).thenReturn(this.mockAuthorizationHandlerManager);
            when(this.mockAuthorizationHandlerManager.handleAuthorization((OAuth2AuthorizeReqDTO) any())).
                    thenReturn(mockedOAuth2AuthorizeRespDTO);
            OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
            assertNotNull(oAuth2AuthorizeRespDTO);
        }
    }

    @Test
    public void testAuthorizeWithException() throws IdentityOAuth2Exception {

        try (MockedStatic<AuthorizationHandlerManager> authorizationHandlerManager = mockStatic(
                AuthorizationHandlerManager.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
            String callbackUrl = "dummyCallBackUrl";
            when(oAuth2AuthorizeReqDTO.getCallbackUrl()).thenReturn(callbackUrl);
            authorizationHandlerManager.when(AuthorizationHandlerManager::getInstance)
                    .thenThrow(new IdentityOAuth2Exception
                            ("Error while creating AuthorizationHandlerManager instance"));
            OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
            assertNotNull(oAuth2AuthorizeRespDTO);
        }
    }

    @Test(dataProvider = "ValidateClientInfoDataProvider")
    public void testValidateClientInfo(String clientId, String grantType, String callbackUrl, String tenantDomain,
                                       int tenantId, String callbackURI) throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            getOAuthAppDO(clientId, grantType, callbackUrl, tenantDomain, tenantId, identityTenantUtil, oAuth2Util);
            when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
            when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackURI);
            when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
            OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                    validateClientInfo(mockHttpServletRequest);
            assertNotNull(oAuth2ClientValidationResponseDTO);
            assertTrue(oAuth2ClientValidationResponseDTO.isValidClient());
        }
    }

    @Test
    public void testValidateClientInfoWithInvalidCallbackURL() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            String clientId = UUID.randomUUID().toString();
            getOAuthAppDO(clientId, "dummyGrantType", "dummyCallBackUrl", "carbon.super", -1234, identityTenantUtil,
                    oAuth2Util);
            when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
            when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallBackURI");
            when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
            OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                    validateClientInfo(mockHttpServletRequest);
            assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CALLBACK);
        }
    }

    /**
     * DataProvider: registered callback URI, callback URI, valid
     */
    @DataProvider(name = "ValidateCallbackURIDataProvider")
    public Object[][] validateLoopbackCallbackURIDataProvider() {

        return new Object[][]{
                // Regular redirect URL registered.
                {"https://sampleapp.com/callback", "https://sampleapp.com/callback", true},
                {"https://sampleapp.com/callback", "https://127.0.0.1:8080/callback", false},

                // Loopback redirect URL registered.
                {"https://127.0.0.1:8080/callback", "https://127.0.0.1:8081/callback", true},
                {"https://127.0.0.1:8080/anothercallback", "https://127.0.0.1:8080/callback", false},
                {"https://127.0.0.1:8080/callback", "https://localhost:8080/callback", false},
                {"https://127.0.0.1:8080/callback", "https://sampleapp.com/callback", false},

                // Simple regex based registered callback URI with loopback URL.
                {"regexp=(https://((sampleapp.com)|(127.0.0.1:8000))(/callback))",
                        "https://sampleapp.com/callback", true},
                {"regexp=(https://((sampleapp.com)|(127.0.0.1:8000))(/callback))",
                        "https://127.0.0.1:8001/callback", true},
                {"regexp=(https://((sampleapp.com)|(127.0.0.1:8000))(/callback))",
                        "https://127.0.0.1:8001/callback", true},

                // Regex with dynamic query values.
                {"regexp=https://127.0.0.1:8090\\?id=(.*)", "https://127.0.0.1:8080?id=hg7", true},
                {"regexp=https://127.0.0.1:8090/callbak\\?id=(.*)", "https://127.0.0.1:8080?id=hg7", false},

                // Regex with a range of port numbers.
                {"regexp=((https://127.0.0.1:)([8][0]{2}[0-7])(/callback))", "https://127.0.0.1:8089/callback", false},
                {"regexp=((https://127.0.0.1:)([8][0]{2}[0-7])(/callback))", "https://127.0.0.1:8007/callback", false},
                {"regexp=(((https://127.0.0.1)|((https://sampleapp.com:)([8][0]{2}[0-7])))(/callback))",
                        "https://127.0.0.1:10000/callback", true},
                {"regexp=(((https://127.0.0.1)|((https://127.0.0.2:)([8][0]{2}[0-7])))(/callback))",
                        "https://127.0.0.2:8007/callback", true},
                {"regexp=((https://127.0.0.2:)([8][0]{2}[0-7])(/callback))", "https://127.0.0.2:8089/callback", false},
                {"regexp=((https://127.0.0.2:)([8][0]{2}[0-7])(/callback))", "https://127.0.0.2:8007/callback", true},
        };
    }

    @Test(dataProvider = "ValidateCallbackURIDataProvider")
    public void testValidateLoopbackCallbackURI(String registeredCallbackURI, String callbackURI, boolean valid)
            throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            String clientId = UUID.randomUUID().toString();
            getOAuthAppDO(clientId, "dummyGrantType", registeredCallbackURI, "carbon.super", -1234, identityTenantUtil,
                    oAuth2Util);
            when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
            when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackURI);
            when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
            OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                    validateClientInfo(mockHttpServletRequest);
            if (!valid) {
                assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CALLBACK);
            } else {
                assertNotEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CALLBACK);
            }
        }
    }

    @Test
    public void testValidateClientInfoWithDeviceResponseType() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            String clientId = UUID.randomUUID().toString();
            getOAuthAppDO(clientId, "dummyGrantType", null, "carbon.super", -1234, identityTenantUtil, oAuth2Util);
            OAuth2ServiceComponentHolder.getInstance().addResponseTypeRequestValidator(
                    new DeviceFlowResponseTypeRequestValidator());
            when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
            when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(null);
            when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn(RESPONSE_TYPE_DEVICE);
            OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                    validateClientInfo(mockHttpServletRequest);
            assertNotNull(oAuth2ClientValidationResponseDTO);
            assertTrue(oAuth2ClientValidationResponseDTO.isValidClient());
        }
    }

    @Test
    public void testValidateClientInfoWithEmptyGrantTypes() throws Exception {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
                frameworkUtils.when(FrameworkUtils::getLoginTenantDomainFromContext).thenReturn("dummyTenantDomain");
                getOAuthAppDO(clientId, null, "dummyCallbackUrl", "dummyTenantDomain", 1, identityTenantUtil,
                        oAuth2Util);
                when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
                when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallBackUrl");
                when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
                OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                        validateClientInfo(mockHttpServletRequest);
                ;
                assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            }
        }
    }

    @Test(dataProvider = "ValidateClientInfoDataProvider")
    public void testValidateHybridFlowValidRequest(String clientId, String grantType,
                                                   String callbackUrl, String tenantDomain,
                                                   int tenantId, String callbackURI) throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            OAuthAppDO oAuthAppDO = getOAuthAppDO(clientId, grantType, callbackUrl, tenantDomain,
                    tenantId, identityTenantUtil, oAuth2Util);
            oAuthAppDO.setHybridFlowEnabled(true);
            oAuthAppDO.setHybridFlowResponseType("code token");
            when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
            when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackURI);
            when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code token");
            OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                    validateClientInfo(mockHttpServletRequest);
            assertNotNull(oAuth2ClientValidationResponseDTO);
            assertTrue(oAuth2ClientValidationResponseDTO.isValidClient());
        }
    }

    private OAuthAppDO getOAuthAppDO(String clientId, String grantType, String callbackUrl, String tenantDomain,
                                     int tenantId, MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                     MockedStatic<OAuth2Util> oAuth2Util)
            throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(tenantId);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(tenantId)).thenReturn(tenantDomain);
        identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(tenantId);
        lenient().when(authenticatedUser.getTenantDomain()).thenReturn(tenantDomain);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes(grantType);
        oAuthAppDO.setApplicationName("dummyName");
        oAuthAppDO.setState("ACTIVE");
        oAuthAppDO.setCallbackUrl(callbackUrl);
        oAuthAppDO.setAppOwner(new AuthenticatedUser());
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(clientId)).thenReturn(oAuthAppDO);
        return oAuthAppDO;
    }

    @Test
    public void testValidateClientInfoWithInvalidClientId() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(null, -1234)).thenReturn(null);
                    })) {
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(-1234);
                when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(null);
                when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallbackUrI");
                when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
                OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                        validateClientInfo(mockHttpServletRequest);
                assertNotNull(oAuth2ClientValidationResponseDTO);
                assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), "invalid_client");
                assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
            }
        }
    }

    @DataProvider(name = "InvalidAppStatDataProvider")
    public Object[][] invalidAppStateDataProvider() {

        return new Object[][]{
                {null},
                {"dummyAppState"}
        };
    }

    @Test(dataProvider = "InvalidAppStatDataProvider")
    public void testValidateClientInfoWithInvalidAppState(String appState) throws Exception {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            frameworkUtils.when(FrameworkUtils::getLoginTenantDomainFromContext).thenReturn("dummyTenantDomain");
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                OAuthAppDO oAuthAppDO =
                        getOAuthAppDO(clientId, "dummyGrantType", "dummyCallbackUrl", "dummyTenantDomain", 1,
                                identityTenantUtil, oAuth2Util);
                oAuthAppDO.setState(appState);
                AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
                when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
                when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallbackUrI");
                when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
                OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                        validateClientInfo(mockHttpServletRequest);
                assertNotNull(oAuth2ClientValidationResponseDTO);
                assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CLIENT);
                assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
            }
        }
    }

    @Test
    public void testInvalidOAuthClientException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, 1)).thenThrow
                                (new InvalidOAuthClientException(
                                        "Cannot find an application associated with the given consumer key"));
                    })) {
                String callbackUrI = "dummyCallBackURI";

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(1)).thenReturn("test.tenant");
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

                when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
                when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackUrI);
                when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
                OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                        validateClientInfo(mockHttpServletRequest);
                assertNotNull(oAuth2ClientValidationResponseDTO);
                assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CLIENT);
                assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
            }
        }
    }

    @Test
    public void testIdentityOAuth2Exception() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, 1)).thenThrow
                                (new IdentityOAuth2Exception("Error while retrieving the app information"));
                    })) {
                String callbackUrI = "dummyCallBackURI";
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(1)).thenReturn("test.tenant");
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

                when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
                when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackUrI);
                when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
                OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                        validateClientInfo(mockHttpServletRequest);
                assertNotNull(oAuth2ClientValidationResponseDTO);
                assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.SERVER_ERROR);
                assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
            }
        }
    }

    @Test
    public void testIssueAccessToken() throws IdentityException {

        try (MockedStatic<AccessTokenIssuer> accessTokenIssuer = mockStatic(AccessTokenIssuer.class)) {
            OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
            AccessTokenIssuer mockAccessTokenIssuer = mock(AccessTokenIssuer.class);
            accessTokenIssuer.when(AccessTokenIssuer::getInstance).thenReturn(mockAccessTokenIssuer);
            when(mockAccessTokenIssuer.issue(any(OAuth2AccessTokenReqDTO.class))).thenReturn(tokenRespDTO);
            assertNotNull(oAuth2Service.issueAccessToken(new OAuth2AccessTokenReqDTO()));
        }
    }

    /**
     * DataProvider: Exceptions,ErrorMsg
     */
    @DataProvider(name = "ExceptionForIssueAccessToken")
    public Object[][] createExceptions() {

        return new Object[][]{
                {new IdentityOAuth2Exception(""), "server_error"},
                {new InvalidOAuthClientException(""), "invalid_client"},
                {new IdentityOAuth2ClientException("access_denied", ""), "access_denied"}
        };
    }

    @Test(dataProvider = "ExceptionForIssueAccessToken")
    public void testExceptionForIssueAccesstoken(Object exception, String errorMsg) throws IdentityException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AccessTokenIssuer> accessTokenIssuer = mockStatic(AccessTokenIssuer.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
            AccessTokenIssuer mockAccessTokenIssuer = mock(AccessTokenIssuer.class);
            accessTokenIssuer.when(AccessTokenIssuer::getInstance).thenReturn(mockAccessTokenIssuer);
            when(mockAccessTokenIssuer.issue(any(OAuth2AccessTokenReqDTO.class)))
                    .thenThrow((Exception) exception);
            assertEquals(oAuth2Service.issueAccessToken(new OAuth2AccessTokenReqDTO())
                    .getErrorCode(), errorMsg);
        }
    }

    @Test
    public void testIsPKCESupportEnabled() {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            oAuth2Util.when(OAuth2Util::isPKCESupportEnabled).thenReturn(true);
            assertTrue(oAuth2Service.isPKCESupportEnabled());
        }
    }

    /**
     * DataProvider: grantType, token state
     */
    @DataProvider(name = "RefreshTokenWithDifferentFlows")
    public Object[][] createRefreshtoken() {

        return new Object[][]{
                {GrantType.REFRESH_TOKEN.toString(), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE},
                {GrantType.REFRESH_TOKEN.toString(), null},
                {null, null},
                {GrantType.REFRESH_TOKEN.toString(), OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED},
        };
    }

    @Test(dataProvider = "RefreshTokenWithDifferentFlows")
    public void testRevokeTokenByOAuthClientWithRefreshToken(String grantType, String tokenState) throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class);) {
            setUpRevokeToken(oAuthComponentServiceHolder, oAuth2Util, oAuthUtil);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
            RefreshTokenValidationDataDO refreshTokenValidationDataDO = new RefreshTokenValidationDataDO();
            refreshTokenValidationDataDO.setGrantType(GrantType.REFRESH_TOKEN.toString());
            refreshTokenValidationDataDO.setAccessToken("testAccessToken");
            refreshTokenValidationDataDO.setAuthorizedUser(authenticatedUser);
            refreshTokenValidationDataDO.setScope(new String[]{"test"});
            refreshTokenValidationDataDO.setRefreshTokenState(tokenState);
            refreshTokenValidationDataDO.setTokenBindingReference("dummyReference");

            OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory = OAuthTokenPersistenceFactory.getInstance();
            TokenManagementDAOImpl mockTokenManagementDAOImpl = mock(TokenManagementDAOImpl.class);
            setPrivateField(oAuthTokenPersistenceFactory, "managementDAO", mockTokenManagementDAOImpl);
            AccessTokenDAOImpl mockAccessTokenDAOImpl = mock(AccessTokenDAOImpl.class);
            setPrivateField(oAuthTokenPersistenceFactory, "tokenDAO", mockAccessTokenDAOImpl);
            when(mockTokenManagementDAOImpl.validateRefreshToken(any(), any()))
                    .thenReturn(refreshTokenValidationDataDO);

            OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
            revokeRequestDTO.setConsumerKey("testConsumerKey");
            revokeRequestDTO.setToken("testToken");
            revokeRequestDTO.setTokenType(grantType);
            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(true);
            oAuthClientAuthnContext.setErrorCode("dummyErrorCode");
            revokeRequestDTO.setOauthClientAuthnContext(oAuthClientAuthnContext);
            assertFalse(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError());
        }
    }

    @Test
    public void testRevokeTokenByOAuthClientWithAccessToken() throws Exception {

        try (MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class)) {
            setUpRevokeToken(oAuthComponentServiceHolder, oAuth2Util, oAuthUtil);
            AccessTokenDO accessTokenDO = getAccessToken();
            TokenBinding tokenBinding = new TokenBinding();
            tokenBinding.setBindingReference("dummyReference");
            accessTokenDO.setTokenBinding(tokenBinding);
            when(OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);

            OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory = OAuthTokenPersistenceFactory.getInstance();
            TokenManagementDAOImpl mockTokenManagementDAOImpl = mock(TokenManagementDAOImpl.class);
            setPrivateField(oAuthTokenPersistenceFactory, "managementDAO", mockTokenManagementDAOImpl);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            setPrivateField(oAuthTokenPersistenceFactory, "tokenDAO", mockAccessTokenDAO);

            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);

            OAuthRevocationRequestDTO revokeRequestDTO = getOAuthRevocationRequestDTO();
            oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO);
            assertFalse(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError());
        }
    }

    private OAuthRevocationRequestDTO getOAuthRevocationRequestDTO() {

        OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
        revokeRequestDTO.setConsumerKey("testConsumerKey");
        revokeRequestDTO.setToken("testToken");
        revokeRequestDTO.setTokenType(GrantType.CLIENT_CREDENTIALS.toString());

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setErrorCode("dummyErrorCode");
        revokeRequestDTO.setOauthClientAuthnContext(oAuthClientAuthnContext);
        return revokeRequestDTO;
    }

    @Test
    public void testRevokeTokenByOAuthClientWithAccessTokenWithInvalidBinding() throws Exception {

        try (MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class)) {
            setUpRevokeToken(oAuthComponentServiceHolder, oAuth2Util, oAuthUtil);
            AccessTokenDO accessTokenDO = getAccessToken();
            when(OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);

            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setTokenBindingValidationEnabled(true);
            when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);

            OAuthRevocationRequestDTO revokeRequestDTO = getOAuthRevocationRequestDTO();
            OAuthRevocationResponseDTO oAuthRevocationResponseDTO = oAuth2Service
                    .revokeTokenByOAuthClient(revokeRequestDTO);
            assertNotNull(oAuthRevocationResponseDTO);
            assertEquals(oAuthRevocationResponseDTO.getErrorMsg(),
                    "Valid token binding value not present in the request.");
        }
    }

    @Test
    public void testRevokeTokenByOAuthClientWithEmptyConsumerKeyAndToken() throws Exception {

        try (MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class)) {
            setUpRevokeToken(oAuthComponentServiceHolder, oAuth2Util, oAuthUtil);
            OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
            revokeRequestDTO.setOauthClientAuthnContext(new OAuthClientAuthnContext());
            assertTrue(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError());
        }
    }

    private AccessTokenDO getAccessToken() {

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("testConsumerKey");
        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokenDO.setAccessToken("dummyAccessToken");
        return accessTokenDO;
    }

    /**
     * DataProvider: ErrorMsg, Enable to set Details on revokeRequest,
     * Enable to throw Identity Exception,
     * Enable to throw InvalidOAuthClientException.
     * Enable unauthorized client error
     */
    @DataProvider(name = "ExceptionforRevokeTokenByOAuthClient")
    public Object[][] createRevokeTokenException() {

        return new Object[][]{
                {"Error occurred while revoking authorization grant for applications", true, true, false, false},
                {"Invalid revocation request", false, false, false, false},
                {"Unauthorized Client", true, false, true, false},
                {"Unauthorized Client", true, false, false, true},
        };
    }

    @Test(dataProvider = "ExceptionforRevokeTokenByOAuthClient")
    public void testIdentityOAuth2ExceptionForRevokeTokenByOAuthClient(
            String errorMsg, boolean setDetails, boolean throwIdentityException,
            boolean throwInvalidOAuthClientException, boolean failClientAuthentication) throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class);
             MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class)) {
            setUpRevokeToken(oAuthComponentServiceHolder, oAuth2Util, oAuthUtil);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setConsumerKey("testConsumerKey");
            accessTokenDO.setAuthzUser(authenticatedUser);
            accessTokenDO.setGrantType(GrantType.CLIENT_CREDENTIALS.toString());

            OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();

            if (setDetails) {
                revokeRequestDTO.setConsumerKey("testConsumerKey");
                revokeRequestDTO.setToken("testToken");
            }
            revokeRequestDTO.setTokenType(GrantType.CLIENT_CREDENTIALS.toString());
            if (throwIdentityException) {
                lenient().doThrow(new IdentityOAuth2Exception("")).when(oAuthEventInterceptorProxy)
                        .onPreTokenRevocationByClient(any(OAuthRevocationRequestDTO.class), anyMap());
            }
            if (throwInvalidOAuthClientException) {
                when(OAuth2Util.findAccessToken(any(), anyBoolean())).
                        thenAnswer(invocation -> {
                            throw new InvalidOAuthClientException("InvalidOAuthClientException");
                        });
            }
            if (failClientAuthentication) {
                when(OAuth2Util.findAccessToken(any(), anyBoolean()))
                        .thenReturn(new AccessTokenDO());
            } else {
                OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
                oAuthClientAuthnContext.setErrorMessage(errorMsg);
                oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

                revokeRequestDTO.setOauthClientAuthnContext(oAuthClientAuthnContext);
            }
            lenient().when(mockOAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(this.mockOAuthCache);
            assertEquals(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).getErrorMsg(), errorMsg);
        }
    }

    @Test
    public void testIdentityExceptionForRevokeTokenByOAuthClient() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class);) {
            setUpRevokeToken(oAuthComponentServiceHolder, oAuth2Util, oAuthUtil);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
            AccessTokenDO accessTokenDO = getAccessToken();
            TokenBinding tokenBinding = new TokenBinding();
            tokenBinding.setBindingReference("dummyReference");
            accessTokenDO.setTokenBinding(tokenBinding);
            when(OAuth2Util.findAccessToken(anyString(), anyBoolean())).
                    thenAnswer(invocation -> {
                        throw new IdentityException("IdentityException");
                    });
            OAuthRevocationRequestDTO revokeRequestDTO = getOAuthRevocationRequestDTO();

            OAuthRevocationResponseDTO oAuthRevocationResponseDTO = oAuth2Service
                    .revokeTokenByOAuthClient(revokeRequestDTO);
            assertEquals(oAuthRevocationResponseDTO.getErrorMsg(),
                    "Error occurred while revoking authorization grant for applications");
        }
    }

    /**
     * DataProvider: map,claims array,supported claim array, size of expected out put,username
     */
    @DataProvider(name = "provideUserClaims")
    public Object[][] createUserClaims() {

        Map<String, String> testMap1 = new HashMap<>();
        testMap1.put("http://wso2.org/claims/emailaddress", "test@wso2.com");
        testMap1.put("http://wso2.org/claims/givenname", "testFirstName");
        testMap1.put("http://wso2.org/claims/lastname", "testLastName");

        Map<String, String> testMap2 = new HashMap<>();
        return new Object[][]{
                {testMap1, new String[]{"openid"}, new String[]{"test"}, 9, "testUser"},
                {testMap1, new String[]{"openid"}, new String[]{"test"}, 0, null},
                {testMap2, new String[]{"openid"}, new String[]{}, 1, "testUser"},
                {testMap2, new String[]{}, new String[]{"test"}, 0, "testUser"},
        };
    }

    @Test(dataProvider = "provideUserClaims")
    public void testGetUserClaims(Object map, String[] claims, String[] supClaims,
                                  int arraySize, String username) throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class)) {
            OAuth2TokenValidationResponseDTO respDTO = mock(OAuth2TokenValidationResponseDTO.class);
            when(respDTO.getAuthorizedUser()).thenReturn(username);
            lenient().when(respDTO.getScope()).thenReturn(claims);

            try (MockedConstruction<OAuth2TokenValidationService> mockedConstruction = Mockito.mockConstruction(
                    OAuth2TokenValidationService.class,
                    (mock, context) -> {
                        when(mock.validate(any(OAuth2TokenValidationRequestDTO.class))).thenReturn(respDTO);
                    })) {
                multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn("testTenant");
                multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString()))
                        .thenReturn("testUser");

                UserStoreManager userStoreManager = mock(UserStoreManager.class);
                lenient().when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString()))
                        .thenReturn((Map) map);
                UserRealm testRealm = mock(UserRealm.class);
                lenient().when(testRealm.getUserStoreManager()).thenReturn(userStoreManager);
                identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), anyString()))
                        .thenReturn(testRealm);

                setPrivateField(OAuthServerConfiguration.getInstance(), "supportedClaims", supClaims);
                assertEquals(oAuth2Service.getUserClaims("test").length, arraySize);
            }

        }
    }

    @Test
    public void testExceptionForGetUserClaims() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class)) {
            OAuth2TokenValidationResponseDTO respDTO = mock(OAuth2TokenValidationResponseDTO.class);
            when(respDTO.getAuthorizedUser()).thenReturn("testUser");
            when(respDTO.getScope()).thenReturn(new String[]{"openid"});

            try (MockedConstruction<OAuth2TokenValidationService> mockedConstruction = Mockito.mockConstruction(
                    OAuth2TokenValidationService.class,
                    (mock, context) -> {
                        when(mock.validate(any(OAuth2TokenValidationRequestDTO.class))).thenReturn(respDTO);
                    })) {

                multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn("testTenant");
                multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString()))
                        .thenReturn("testUser");

                identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), anyString()))
                        .thenThrow(new IdentityException(""));
                assertEquals(oAuth2Service.getUserClaims("test").length, 1);
            }
        }
    }

    private void setUpRevokeToken(MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder,
                                  MockedStatic<OAuth2Util> oAuth2Util, MockedStatic<OAuthUtil> oAuthUtil)
            throws Exception {

        lenient().when(oAuthEventInterceptorProxy.isEnabled()).thenReturn(true);
        lenient().doNothing().when(oAuthEventInterceptorProxy).onPostTokenRevocationByClient
                (nullable(OAuthRevocationRequestDTO.class), nullable(OAuthRevocationResponseDTO.class),
                        nullable(AccessTokenDO.class), nullable(RefreshTokenValidationDataDO.class),
                        nullable(HashMap.class));

        when(mockOAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(oAuthEventInterceptorProxy);
        oAuthComponentServiceHolder.when(
                OAuthComponentServiceHolder::getInstance).thenReturn(mockOAuthComponentServiceHolder);
        lenient().when(authenticatedUser.toString()).thenReturn("testAuthenticatedUser");

        oAuth2Util.when(() -> OAuth2Util.authenticateClient(anyString(), anyString())).thenReturn(true);
        oAuth2Util.when(() -> OAuth2Util.buildScopeString(any(String[].class))).thenReturn("test");

        oAuthUtil.when(() -> OAuthUtil.clearOAuthCache(anyString())).thenAnswer((Answer<Void>) invocation -> null);
        oAuthUtil.when(() -> OAuthUtil.clearOAuthCache(anyString(), any(User.class)))
                .thenAnswer((Answer<Void>) invocation -> null);
        oAuthUtil.when(() -> OAuthUtil.clearOAuthCache(anyString(), any(User.class), anyString()))
                .thenAnswer((Answer<Void>) invocation -> null);
        oAuthUtil.when(() -> OAuthUtil.clearOAuthCache(anyString(), any(User.class), anyString(), anyString()))
                .thenAnswer((Answer<Void>) invocation -> null);
    }

    @Test
    public void testGetOauthApplicationState() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            String id = "clientId1";
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setState("ACTIVE");
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(id, 1)).thenReturn(oAuthAppDO);
                    })) {
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(1)).thenReturn("test.tenant");
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);
                assertEquals(oAuth2Service.getOauthApplicationState(id), "ACTIVE");
            }
        }
    }

    @Test
    public void testGetOauthApplicationStateWithIdentityOAuth2Exception() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(1)).thenReturn("test.tenant");

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(anyString(), anyInt())).thenThrow(IdentityOAuth2Exception.class);
                    })) {

                assertNull(oAuth2Service.getOauthApplicationState(clientId));
            }

        }
    }

    @Test
    public void testGetOauthApplicationStateWithInvalidOAuthClientException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(1)).thenReturn("test.tenant");

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(anyString(), anyInt())).thenThrow(
                                InvalidOAuthClientException.class);
                    })) {

                assertNull(oAuth2Service.getOauthApplicationState(clientId));
            }
        }
    }

    @Test
    public void testGetSupportedTokenBinders() throws Exception {

        setPrivateField(OAuth2ServiceComponentHolder.getInstance(), "tokenBinders", new ArrayList<>());
        assertNotNull(oAuth2Service.getSupportedTokenBinders());
    }

    @Test
    public void testHandleUserConsentDenial() throws Exception {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        when(getResponseHander(oAuth2Parameters).handleUserConsentDenial(oAuth2Parameters)).thenReturn(null);
        assertNull(oAuth2Service.handleUserConsentDenial(oAuth2Parameters));
    }

    @Test
    public void testHandleUserConsentDenialWithException() throws Exception {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        when(getResponseHander(oAuth2Parameters).handleUserConsentDenial(oAuth2Parameters)).
                thenAnswer(invocation -> {
                    throw new IdentityOAuth2Exception("IdentityOAuth2Exception");
                });

        assertNull(oAuth2Service.handleUserConsentDenial(oAuth2Parameters));
    }

    @Test
    public void testHandleAuthenticationFailure() throws Exception {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        when(getResponseHander(oAuth2Parameters).handleAuthenticationFailure(oAuth2Parameters)).thenReturn(null);
        assertNull(oAuth2Service.handleAuthenticationFailure(oAuth2Parameters));
    }

    @Test
    public void testHandleAuthenticationFailureWithException() throws Exception {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        when(getResponseHander(oAuth2Parameters).handleAuthenticationFailure(oAuth2Parameters)).
                thenAnswer(invocation -> {
                    throw new IdentityOAuth2Exception("IdentityOAuth2Exception");
                });

        assertNull(oAuth2Service.handleAuthenticationFailure(oAuth2Parameters));
    }

    private ResponseTypeHandler getResponseHander(OAuth2Parameters oAuth2Parameters) throws Exception {

        oAuth2Parameters.setResponseType("dummyResponseType");
        Map<String, ResponseTypeHandler> testMap = new HashMap<>();
        ResponseTypeHandler mockResponseTypeHander = mock(ResponseTypeHandler.class);
        testMap.put("dummyResponseType", mockResponseTypeHander);
        setPrivateField(AuthorizationHandlerManager.getInstance(), "responseHandlers", testMap);
        return mockResponseTypeHander;
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

}
