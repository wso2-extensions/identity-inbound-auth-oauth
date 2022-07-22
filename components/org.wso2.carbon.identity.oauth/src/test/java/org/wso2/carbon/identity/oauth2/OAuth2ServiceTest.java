/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth2;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.Whitebox;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
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
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
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
@WithCarbonHome
@PrepareForTest({
        OAuth2Util.class,
        AuthorizationHandlerManager.class,
        OAuth2Service.class,
        IdentityTenantUtil.class,
        OAuthServerConfiguration.class,
        AccessTokenIssuer.class,
        OAuthComponentServiceHolder.class,
        OAuthUtil.class,
        OAuthCache.class,
        AppInfoCache.class,
        MultitenantUtils.class,
        LoggerUtils.class
})
public class OAuth2ServiceTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;

    @Mock
    private AuthorizationHandlerManager authorizationHandlerManager;

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
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;

    @Mock
    private OAuthCache oAuthCache;

    @Mock
    private HttpServletRequest mockHttpServletRequest;

    private OAuth2Service oAuth2Service;
    private static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";

    @BeforeMethod
    public void setUp() {

        oAuth2Service = new OAuth2Service();
        WhiteboxImpl.setInternalState(OAuthServerConfiguration.getInstance(), "timeStampSkewInSeconds", 3600L);
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    /**
     * DataProvider: grantType, callbackUrl, tenantDomain, callbackURI
     */
    @DataProvider(name = "ValidateClientInfoDataProvider")
    public Object[][] validateClientDataProvider() {

        return new Object[][]{
                {UUID.randomUUID().toString(), "dummyGrantType", "dummyCallBackUrl", "carbon.super", null},
                {UUID.randomUUID().toString(), "dummyGrantType", "regexp=dummyCallBackUrl", "carbon.super",
                        "dummyCallBackUrl"},
                {UUID.randomUUID().toString(), "dummyGrantType", "dummyCallBackUrl", "carbon.super", "dummyCallBackUrl"}
        };
    }

    @Test
    public void testAuthorize() throws Exception {

        mockStatic(AuthorizationHandlerManager.class);
        when(AuthorizationHandlerManager.getInstance()).thenReturn(authorizationHandlerManager);
        when(authorizationHandlerManager.handleAuthorization((OAuth2AuthorizeReqDTO) anyObject())).
                thenReturn(mockedOAuth2AuthorizeRespDTO);
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(300L);
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
        assertNotNull(oAuth2AuthorizeRespDTO);
    }

    @Test
    public void testAuthorizeWithException() throws IdentityOAuth2Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        String callbackUrl = "dummyCallBackUrl";
        mockStatic(AuthorizationHandlerManager.class);
        when(oAuth2AuthorizeReqDTO.getCallbackUrl()).thenReturn(callbackUrl);
        when(AuthorizationHandlerManager.getInstance()).thenThrow(new IdentityOAuth2Exception
                ("Error while creating AuthorizationHandlerManager instance"));
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
        assertNotNull(oAuth2AuthorizeRespDTO);
    }

    @Test(dataProvider = "ValidateClientInfoDataProvider")
    public void testValidateClientInfo(String clientId, String grantType, String callbackUrl, String tenantDomain,
                                       String callbackURI) throws Exception {

        OAuthAppDO oAuthAppDO = getOAuthAppDO(clientId, grantType, callbackUrl, tenantDomain);
        when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
        when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackURI);
        when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(mockHttpServletRequest);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertTrue(oAuth2ClientValidationResponseDTO.isValidClient());
    }

    @Test
    public void testValidateClientInfoWithInvalidCallbackURL() throws Exception {

        String clientId = UUID.randomUUID().toString();
        getOAuthAppDO(clientId, "dummyGrantType", "dummyCallBackUrl", "carbon.super");
        when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
        when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallBackURI");
        when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(mockHttpServletRequest);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CALLBACK);
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

        String clientId = UUID.randomUUID().toString();
        getOAuthAppDO(clientId, "dummyGrantType", registeredCallbackURI, "carbon.super");
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

    @Test
    public void testValidateClientInfoWithDeviceResponseType() throws Exception {

        String clientId = UUID.randomUUID().toString();
        getOAuthAppDO(clientId, "dummyGrantType", null, "carbon.super");
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

    @Test
    public void testValidateClientInfoWithEmptyGrantTypes() throws Exception {

        getOAuthAppDO(clientId, null, "dummyCallbackUrl", "dummyTenantDomain");
        when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
        when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallBackUrl");
        when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(mockHttpServletRequest);;
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    private OAuthAppDO getOAuthAppDO(String clientId, String grantType, String callbackUrl, String tenantDomain)
            throws Exception {

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes(grantType);
        oAuthAppDO.setApplicationName("dummyName");
        oAuthAppDO.setState("ACTIVE");
        oAuthAppDO.setCallbackUrl(callbackUrl);
        oAuthAppDO.setAppOwner(new AuthenticatedUser());
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
        when(oAuthAppDAO.getAppInformation(clientId)).thenReturn(oAuthAppDO);
        when(authenticatedUser.getTenantDomain()).thenReturn(tenantDomain);
        return oAuthAppDO;
    }

    @Test
    public void testValidateClientInfoWithInvalidClientId() throws Exception {

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        when(oAuthAppDAO.getAppInformation(null)).thenReturn(null);
        when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(null);
        when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn("dummyCallbackUrI");
        when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(mockHttpServletRequest);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), "invalid_client");
        assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
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

        OAuthAppDO oAuthAppDO = getOAuthAppDO(clientId, "dummyGrantType", "dummyCallbackUrl",
                "dummyTenantDomain");
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

    @Test
    public void testInvalidOAuthClientException() throws Exception {

        String callbackUrI = "dummyCallBackURI";
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenThrow
                (new InvalidOAuthClientException("Cannot find an application associated with the given consumer key"));
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
        when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackUrI);
        when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(mockHttpServletRequest);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_CLIENT);
        assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
    }

    @Test
    public void testIdentityOAuth2Exception() throws Exception {

        String callbackUrI = "dummyCallBackURI";
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenThrow
                (new IdentityOAuth2Exception("Error while retrieving the app information"));
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        when(mockHttpServletRequest.getParameter(CLIENT_ID)).thenReturn(clientId);
        when(mockHttpServletRequest.getParameter(REDIRECT_URI)).thenReturn(callbackUrI);
        when(mockHttpServletRequest.getParameter(RESPONSE_TYPE)).thenReturn("code");
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(mockHttpServletRequest);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), OAuth2ErrorCodes.SERVER_ERROR);
        assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
    }

    @Test
    public void testIssueAccessToken() throws IdentityException {

        OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
        AccessTokenIssuer accessTokenIssuer = mock(AccessTokenIssuer.class);
        mockStatic(AccessTokenIssuer.class);
        when(AccessTokenIssuer.getInstance()).thenReturn(accessTokenIssuer);
        when(accessTokenIssuer.issue(any(OAuth2AccessTokenReqDTO.class))).thenReturn(tokenRespDTO);
        assertNotNull(oAuth2Service.issueAccessToken(new OAuth2AccessTokenReqDTO()));
    }

    /**
     * DataProvider: Exceptions,ErrorMsg
     */
    @DataProvider(name = "ExceptionForIssueAccessToken")
    public Object[][] createExceptions() {

        return new Object[][]{
                {new IdentityOAuth2Exception(""), "server_error"},
                {new InvalidOAuthClientException(""), "invalid_client"},
        };
    }

    @Test(dataProvider = "ExceptionForIssueAccessToken")
    public void testExceptionForIssueAccesstoken(Object exception, String errorMsg) throws IdentityException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        AccessTokenIssuer accessTokenIssuer = mock(AccessTokenIssuer.class);
        mockStatic(AccessTokenIssuer.class);
        when(AccessTokenIssuer.getInstance()).thenReturn(accessTokenIssuer);
        when(accessTokenIssuer.issue(any(OAuth2AccessTokenReqDTO.class)))
                .thenThrow((Exception) exception);
        assertEquals(oAuth2Service.issueAccessToken(new OAuth2AccessTokenReqDTO())
                .getErrorCode(), errorMsg);
    }

    @Test
    public void testIsPKCESupportEnabled() {

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isPKCESupportEnabled()).thenReturn(true);
        assertTrue(oAuth2Service.isPKCESupportEnabled());
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

        setUpRevokeToken();
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        RefreshTokenValidationDataDO refreshTokenValidationDataDO = new RefreshTokenValidationDataDO();
        refreshTokenValidationDataDO.setGrantType(GrantType.REFRESH_TOKEN.toString());
        refreshTokenValidationDataDO.setAccessToken("testAccessToken");
        refreshTokenValidationDataDO.setAuthorizedUser(authenticatedUser);
        refreshTokenValidationDataDO.setScope(new String[]{"test"});
        refreshTokenValidationDataDO.setRefreshTokenState(tokenState);
        refreshTokenValidationDataDO.setTokenBindingReference("dummyReference");

        OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory = OAuthTokenPersistenceFactory.getInstance();
        TokenManagementDAOImpl mockTokenManagementDAOImpl = mock(TokenManagementDAOImpl.class);
        Whitebox.setInternalState(oAuthTokenPersistenceFactory, "managementDAO", mockTokenManagementDAOImpl);
        AccessTokenDAOImpl mockAccessTokenDAOImpl = mock(AccessTokenDAOImpl.class);
        Whitebox.setInternalState(oAuthTokenPersistenceFactory, "tokenDAO", mockAccessTokenDAOImpl);
        when(mockTokenManagementDAOImpl.validateRefreshToken(anyObject(), anyObject()))
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

    @Test
    public void testRevokeTokenByOAuthClientWithAccessToken() throws Exception {

        setUpRevokeToken();
        AccessTokenDO accessTokenDO = getAccessToken();
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingReference("dummyReference");
        accessTokenDO.setTokenBinding(tokenBinding);
        when(OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);

        OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory = OAuthTokenPersistenceFactory.getInstance();
        TokenManagementDAOImpl mockTokenManagementDAOImpl = mock(TokenManagementDAOImpl.class);
        Whitebox.setInternalState(oAuthTokenPersistenceFactory, "managementDAO", mockTokenManagementDAOImpl);
        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        Whitebox.setInternalState(oAuthTokenPersistenceFactory, "tokenDAO", mockAccessTokenDAO);
        when(mockAccessTokenDAO.getAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);

        OAuthRevocationRequestDTO revokeRequestDTO = getOAuthRevocationRequestDTO();
        oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO);
        assertFalse(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError());
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

        setUpRevokeToken();
        AccessTokenDO accessTokenDO = getAccessToken();
        when(OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setTokenBindingValidationEnabled(true);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);

        OAuthRevocationRequestDTO revokeRequestDTO = getOAuthRevocationRequestDTO();
        OAuthRevocationResponseDTO oAuthRevocationResponseDTO = oAuth2Service
                .revokeTokenByOAuthClient(revokeRequestDTO);
        assertNotNull(oAuthRevocationResponseDTO);
        assertEquals(oAuthRevocationResponseDTO.getErrorMsg(), "Valid token binding value not present in the request.");
    }

    @Test
    public void testRevokeTokenByOAuthClientWithEmptyConsumerKeyAndToken() throws Exception {

        setUpRevokeToken();
        OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
        revokeRequestDTO.setOauthClientAuthnContext(new OAuthClientAuthnContext());
        assertEquals(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError(), true);
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

        setUpRevokeToken();
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
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
            doThrow(new IdentityOAuth2Exception("")).when(oAuthEventInterceptorProxy)
                    .onPreTokenRevocationByClient(any(OAuthRevocationRequestDTO.class), anyMap());
        }
        if (throwInvalidOAuthClientException) {
            when(OAuth2Util.findAccessToken(anyObject(), anyBoolean()))
                    .thenThrow(InvalidOAuthClientException.class);
        }
        if (failClientAuthentication) {
            when(OAuth2Util.findAccessToken(anyObject(), anyBoolean()))
                    .thenReturn(new AccessTokenDO());
        } else {
            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setErrorMessage(errorMsg);
            oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

            revokeRequestDTO.setOauthClientAuthnContext(oAuthClientAuthnContext);
        }
        when(oAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);
        assertEquals(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).getErrorMsg(), errorMsg);
    }

    @Test
    public void testIdentityExceptionForRevokeTokenByOAuthClient() throws Exception {

        setUpRevokeToken();
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        AccessTokenDO accessTokenDO = getAccessToken();
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingReference("dummyReference");
        accessTokenDO.setTokenBinding(tokenBinding);
        when(OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenThrow(IdentityException.class);
        OAuthRevocationRequestDTO revokeRequestDTO = getOAuthRevocationRequestDTO();

        OAuthRevocationResponseDTO oAuthRevocationResponseDTO = oAuth2Service
                .revokeTokenByOAuthClient(revokeRequestDTO);
        assertEquals(oAuthRevocationResponseDTO.getErrorMsg(),
                "Error occurred while revoking authorization grant for applications");
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

        OAuth2TokenValidationResponseDTO respDTO = mock(OAuth2TokenValidationResponseDTO.class);
        when(respDTO.getAuthorizedUser()).thenReturn(username);
        when(respDTO.getScope()).thenReturn(claims);

        OAuth2TokenValidationService oAuth2TokenValidationService = mock(OAuth2TokenValidationService.class);
        when(oAuth2TokenValidationService.validate(any(OAuth2TokenValidationRequestDTO.class))).thenReturn(respDTO);
        whenNew(OAuth2TokenValidationService.class).withAnyArguments().thenReturn(oAuth2TokenValidationService);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn("testTenant");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("testUser");

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn((Map) map);
        UserRealm testRealm = mock(UserRealm.class);
        when(testRealm.getUserStoreManager()).thenReturn(userStoreManager);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getRealm(anyString(), anyString())).thenReturn(testRealm);

        WhiteboxImpl.setInternalState(OAuthServerConfiguration.getInstance(), "supportedClaims", supClaims);
        assertEquals(oAuth2Service.getUserClaims("test").length, arraySize);
    }

    @Test
    public void testExceptionForGetUserClaims() throws Exception {

        OAuth2TokenValidationResponseDTO respDTO = mock(OAuth2TokenValidationResponseDTO.class);
        when(respDTO.getAuthorizedUser()).thenReturn("testUser");
        when(respDTO.getScope()).thenReturn(new String[]{"openid"});

        OAuth2TokenValidationService oAuth2TokenValidationService = mock(OAuth2TokenValidationService.class);
        when(oAuth2TokenValidationService.validate(any(OAuth2TokenValidationRequestDTO.class))).thenReturn(respDTO);
        whenNew(OAuth2TokenValidationService.class).withAnyArguments().thenReturn(oAuth2TokenValidationService);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn("testTenant");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("testUser");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getRealm(anyString(), anyString())).thenThrow(new IdentityException(""));
        assertEquals(oAuth2Service.getUserClaims("test").length, 1);
    }

    private void setUpRevokeToken() throws Exception {

        when(oAuthEventInterceptorProxy.isEnabled()).thenReturn(true);
        doNothing().when(oAuthEventInterceptorProxy).onPostTokenRevocationByClient
                (any(OAuthRevocationRequestDTO.class), any(OAuthRevocationResponseDTO.class), any(AccessTokenDO.class),
                        any(RefreshTokenValidationDataDO.class), any(HashMap.class));

        when(oAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(oAuthEventInterceptorProxy);
        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);
        when(authenticatedUser.toString()).thenReturn("testAuthenticatedUser");

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.authenticateClient(anyString(), anyString())).thenReturn(true);
        when(OAuth2Util.buildScopeString(any(String[].class))).thenReturn("test");

        mockStatic(OAuthUtil.class);
        doNothing().when(OAuthUtil.class, "clearOAuthCache", anyString());
        doNothing().when(OAuthUtil.class, "clearOAuthCache", anyString(), anyString());
        doNothing().when(OAuthUtil.class, "clearOAuthCache", anyString(), anyString(), anyString());
    }

    @Test
    public void testGetOauthApplicationState() throws Exception {

        String id = "clientId1";
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setState("ACTIVE");
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(id)).thenReturn(oAuthAppDO);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        assertEquals(oAuth2Service.getOauthApplicationState(id), "ACTIVE");
    }

    @Test
    public void testGetOauthApplicationStateWithIdentityOAuth2Exception() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
        whenNew(OAuthAppDAO.class).withNoArguments().thenThrow(IdentityOAuth2Exception.class);
        assertNull(oAuth2Service.getOauthApplicationState(clientId));
    }

    @Test
    public void testGetOauthApplicationStateWithInvalidOAuthClientException() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        whenNew(OAuthAppDAO.class).withNoArguments().thenThrow(InvalidOAuthClientException.class);
        assertNull(oAuth2Service.getOauthApplicationState(clientId));
    }

    @Test
    public void testGetSupportedTokenBinders() {

        WhiteboxImpl.setInternalState(OAuth2ServiceComponentHolder.getInstance(), "tokenBinders", new ArrayList<>());
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
        when(getResponseHander(oAuth2Parameters).handleUserConsentDenial(oAuth2Parameters))
                .thenThrow(IdentityOAuth2Exception.class);
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
        when(getResponseHander(oAuth2Parameters).handleAuthenticationFailure(oAuth2Parameters))
                .thenThrow(IdentityOAuth2Exception.class);
        assertNull(oAuth2Service.handleAuthenticationFailure(oAuth2Parameters));
    }

    private ResponseTypeHandler getResponseHander(OAuth2Parameters oAuth2Parameters) throws Exception {

        oAuth2Parameters.setResponseType("dummyResponseType");
        Map<String, ResponseTypeHandler> testMap = new HashMap<>();
        ResponseTypeHandler mockResponseTypeHander = mock(ResponseTypeHandler.class);
        testMap.put("dummyResponseType", mockResponseTypeHander);
        WhiteboxImpl.setInternalState(AuthorizationHandlerManager.getInstance(), "responseHandlers", testMap);
        return mockResponseTypeHander;
    }

}
