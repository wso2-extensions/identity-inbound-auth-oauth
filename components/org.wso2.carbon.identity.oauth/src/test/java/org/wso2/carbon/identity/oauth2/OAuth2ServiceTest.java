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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

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
import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;

/**
 * This class tests the OAuth2Service class.
 */
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
        MultitenantUtils.class
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
    private OAuthAppDO oAuthAppDO;

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

    private OAuth2Service oAuth2Service;
    private static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";
    private TokenPersistenceProcessor persistenceProcessor = new PlainTextPersistenceProcessor();

    @BeforeMethod
    public void setUp() {
        oAuth2Service = new OAuth2Service();
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    /**
     * DataProvider: grantType, callbackUrl, tenantDomain, callbackURI
     */
    @DataProvider(name = "ValidateClientInfoDataProvider")
    public Object[][] validateClientDataProvider() {
        return new Object[][]{
                {null, null, null, null},
                {"dummyGrantType", "dummyCallBackUrl", "carbon.super", null},
                {"dummyGrantType", "dummyCallBackUrl", "carbon.super", "dummyCallBackURI"},
                {"dummyGrantType", "regexp=dummyCallBackUrl", "carbon.super", "dummyCallBackURI"},
                {"dummyGrantType", "regexp=dummyCallBackUrl", "carbon.super", "dummyCallBackUrl"},
                {"dummyGrantType", "dummyCallBackUrl", "carbon.super", "dummyCallBackUrl"}
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
        String callbackUrl = "dummyCallBackUrl";
        mockStatic(AuthorizationHandlerManager.class);
        when(oAuth2AuthorizeReqDTO.getCallbackUrl()).thenReturn(callbackUrl);
        when(AuthorizationHandlerManager.getInstance()).thenThrow(new IdentityOAuth2Exception
                ("Error while creating AuthorizationHandlerManager instance"));
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
        assertNotNull(oAuth2AuthorizeRespDTO);
    }

    @Test(dataProvider = "ValidateClientInfoDataProvider")
    public void testValidateClientInfo(String grantType, String callbackUrl, String tenantDomain, String callbackURI)
            throws Exception {
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenReturn(oAuthAppDO);
        when(oAuthAppDO.getGrantTypes()).thenReturn(grantType);
        when(oAuthAppDO.getCallbackUrl()).thenReturn(callbackUrl);
        when(oAuthAppDO.getUser()).thenReturn(authenticatedUser);
        when(authenticatedUser.getTenantDomain()).thenReturn(tenantDomain);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(clientId, callbackURI);
        assertNotNull(oAuth2ClientValidationResponseDTO);
    }

    @Test
    public void testInvalidOAuthClientException() throws Exception {
        String callbackUrI = "dummyCallBackURI";
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenThrow
                (new InvalidOAuthClientException("Cannot find an application associated with the given consumer key"));
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(clientId, callbackUrI);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), "invalid_client");
        assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
    }

    @Test
    public void testIdentityOAuth2Exception() throws Exception {
        String callbackUrI = "dummyCallBackURI";
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenThrow
                (new IdentityOAuth2Exception("Error while retrieving the app information"));
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(clientId, callbackUrI);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), "server_error");
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
    @DataProvider(name = "ExceptionforIssueAccessToken")
    public Object[][] createExceptions() {
        return new Object[][]{
                {new IdentityOAuth2Exception(""), "server_error"},
                {new InvalidOAuthClientException(""), "invalid_client"},
        };
    }

    @Test(dataProvider = "ExceptionforIssueAccessToken")
    public void testExceptionForIssueAccesstoken(Object exception, String errorMsg) throws IdentityException {
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
                {null, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE},
                {GrantType.REFRESH_TOKEN.toString(), OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED},
        };
    }

    @Test(dataProvider = "RefreshTokenWithDifferentFlows")
    public void testRevokeTokenByOAuthClientWithRefreshToken(String grantType, String tokenState) throws Exception {
        setUpRevokeToken();
        RefreshTokenValidationDataDO refreshTokenValidationDataDO = new RefreshTokenValidationDataDO();
        refreshTokenValidationDataDO.setGrantType(GrantType.REFRESH_TOKEN.toString());
        refreshTokenValidationDataDO.setAccessToken("testAccessToken");
        refreshTokenValidationDataDO.setAuthorizedUser(authenticatedUser);
        refreshTokenValidationDataDO.setScope(new String[]{"test"});
        refreshTokenValidationDataDO.setRefreshTokenState(tokenState);

        TokenMgtDAO tokenMgtDAO = mock(TokenMgtDAO.class);
        when(tokenMgtDAO.validateRefreshToken(anyString(), anyString())).thenReturn(refreshTokenValidationDataDO);
        whenNew(TokenMgtDAO.class).withAnyArguments().thenReturn(tokenMgtDAO);
        doNothing().when(tokenMgtDAO).revokeTokens(any(String[].class));

        when(oAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(null);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);

        OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
        revokeRequestDTO.setConsumerKey("testConsumerKey");
        revokeRequestDTO.setToken("testToken");
        revokeRequestDTO.setTokenType(grantType);
        assertFalse(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError());
    }

    @Test
    public void testRevokeTokenByOAuthClientWithAccesstoken() throws Exception {
        setUpRevokeToken();
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.toString()).thenReturn("testAuthenticatedUser");

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("testConsumerKey");
        accessTokenDO.setAuthzUser(authenticatedUser);

        TokenMgtDAO tokenMgtDAO = mock(TokenMgtDAO.class);
        doNothing().when(tokenMgtDAO).revokeTokens(any(String[].class));
        when(tokenMgtDAO.retrieveAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);
        whenNew(TokenMgtDAO.class).withAnyArguments().thenReturn(tokenMgtDAO);

        OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
        revokeRequestDTO.setConsumerKey("testConsumerKey");
        revokeRequestDTO.setToken("testToken");
        revokeRequestDTO.setTokenType(GrantType.CLIENT_CREDENTIALS.toString());

        when(oAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);
        oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO);
        assertFalse(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).isError());
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
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("testConsumerKey");
        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokenDO.setGrantType(GrantType.CLIENT_CREDENTIALS.toString());
        if (throwIdentityException) {
            doThrow(new IdentityOAuth2Exception("")).when(oAuthEventInterceptorProxy)
                    .onPreTokenRevocationByClient(any(OAuthRevocationRequestDTO.class), anyMap());
        }
        if (throwInvalidOAuthClientException) {
            when(OAuth2Util.authenticateClient(anyString(), anyString()))
                    .thenThrow(new InvalidOAuthClientException(" "));
        }
        if (failClientAuthentication) {
            when(OAuth2Util.authenticateClient(anyString(), anyString()))
                    .thenReturn(false);
        }
        TokenMgtDAO tokenMgtDAO = mock(TokenMgtDAO.class);
        doNothing().when(tokenMgtDAO).revokeTokens(any(String[].class));
        when(tokenMgtDAO.retrieveAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);
        whenNew(TokenMgtDAO.class).withAnyArguments().thenReturn(tokenMgtDAO);
        OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
        if (setDetails) {
            revokeRequestDTO.setConsumerKey("testConsumerKey");
            revokeRequestDTO.setToken("testToken");
        }
        revokeRequestDTO.setTokenType(GrantType.REFRESH_TOKEN.toString());

        when(oAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);
        assertEquals(oAuth2Service.revokeTokenByOAuthClient(revokeRequestDTO).getErrorMsg(), errorMsg);
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

        when(oAuthServerConfiguration.getSupportedClaims()).thenReturn(supClaims);
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

        mockStatic(OAuthServerConfiguration.class);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(persistenceProcessor);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        when(oAuthServerConfiguration.isRevokeResponseHeadersEnabled()).thenReturn(true);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.authenticateClient(anyString(), anyString())).thenReturn(true);
        when(OAuth2Util.buildScopeString(any(String[].class))).thenReturn("test");

        mockStatic(OAuthUtil.class);
        doNothing().when(OAuthUtil.class, "clearOAuthCache", anyString());
        doNothing().when(OAuthUtil.class, "clearOAuthCache", anyString(), anyString());
        doNothing().when(OAuthUtil.class, "clearOAuthCache", anyString(), anyString(), anyString());
    }

}
