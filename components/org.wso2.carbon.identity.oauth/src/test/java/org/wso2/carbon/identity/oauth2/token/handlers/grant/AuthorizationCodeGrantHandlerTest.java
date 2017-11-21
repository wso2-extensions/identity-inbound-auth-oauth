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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * This class defines unit test for AuthorizationCodeGrantHandler class
 */
@PrepareForTest({LogFactory.class, OAuthServerConfiguration.class, AuthorizationCodeGrantHandler.class,
        AppInfoCache.class, OAuth2Util.class, IdentityUtil.class, OAuthCache.class})
public class AuthorizationCodeGrantHandlerTest extends PowerMockTestCase {

    public static final String CLIENT_ID_VALUE = "clientIdValue";
    public static final String INVALID_CLIENT = "invalidClient";
    OAuthServerConfiguration oAuthServerConfiguration;
    AuthorizationCodeGrantHandler authorizationCodeGrantHandler;
    Log log;
    TokenMgtDAO tokenMgtDAO;

    @BeforeTest()
    public void setUp() {

        log = mock(Log.class);
        mockStatic(LogFactory.class);
        when(LogFactory.getLog(AuthorizationCodeGrantHandler.class)).thenReturn(log);
        when(LogFactory.getLog(AbstractAuthorizationGrantHandler.class)).thenReturn(log);

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        authorizationCodeGrantHandler = spy(new AuthorizationCodeGrantHandler());
    }

    @DataProvider(name = "BuildTokenRequestMessageContext")
    public Object[][] buildTokenRequestMessageContext() {

        OAuthTokenReqMessageContext messageContext1 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        messageContext1.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");

        OAuthTokenReqMessageContext messageContext2 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        messageContext2.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        messageContext2.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl");

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        WhiteboxImpl.setInternalState(authzCodeDO1, "authorizedUser", authenticatedUser);
        WhiteboxImpl.setInternalState(authzCodeDO1, "callbackUrl", "callBackUrl");

        AuthzCodeDO authzCodeDO2 = new AuthzCodeDO();

        return new Object[][] {
                {messageContext1, authzCodeDO2, false, true, System.currentTimeMillis() + 250000L, true},
                {messageContext2, authzCodeDO1, true, false, System.currentTimeMillis() + 250000L, true},
        };
    }

    @Test(dataProvider = "BuildTokenRequestMessageContext")
    public void testValidateGrant(Object tokenRequestMessageContext, Object authzCode, boolean cacheEnabled,
                                  boolean debugEnabled, long timestamp, boolean expectedResult)
            throws Exception {

        AuthzCodeDO authzCodeDO = (AuthzCodeDO) authzCode;
        mockStatic(OAuthCache.class);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "cacheEnabled", cacheEnabled);
        OAuthCache oAuthCache = mock(OAuthCache.class);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);

        if (cacheEnabled) {
            WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "oauthCache", oAuthCache);
        }
        OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;
        when(log.isDebugEnabled()).thenReturn(debugEnabled);

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        TokenPersistenceProcessor tokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(anyString())).thenReturn(oAuthAppDO);

        mockStatic(IdentityUtil.class);
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);
        doNothing().when(appInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

        tokenMgtDAO = mock(TokenMgtDAO.class);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "tokenMgtDAO", tokenMgtDAO);
        if (authzCodeDO != null) {
            WhiteboxImpl.setInternalState(authzCodeDO, "issuedTime", new Timestamp(timestamp));
        }
        when(tokenMgtDAO.validateAuthorizationCode(anyString(), anyString())).thenReturn(authzCodeDO);

        assertEquals(expectedResult,authorizationCodeGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @DataProvider(name = "buildErrorTokenRequestMessageContext")
    public Object[][] buildErrorTokenRequestMessageContext() {

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext1 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        oAuthTokenReqMessageContext1.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        oAuthTokenReqMessageContext1.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl2");

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext2 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        oAuthTokenReqMessageContext2.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        oAuthTokenReqMessageContext2.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl");

        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        authzCodeDO1.setState(OAuthConstants.AuthorizationCodeState.INACTIVE);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("user");
        WhiteboxImpl.setInternalState(authzCodeDO1, "authorizedUser", authenticatedUser);
        WhiteboxImpl.setInternalState(authzCodeDO1, "callbackUrl", "callBackUrl");
        WhiteboxImpl.setInternalState(authzCodeDO1, "state", "INACTIVE");

        AuthzCodeDO authzCodeDO2 = new AuthzCodeDO();
        WhiteboxImpl.setInternalState(authzCodeDO2, "authorizedUser", authenticatedUser);
        WhiteboxImpl.setInternalState(authzCodeDO2, "callbackUrl", "callBackUrl");
        WhiteboxImpl.setInternalState(authzCodeDO2, "validityPeriod", 3000000L);

        return new Object[][] {
                {oAuthTokenReqMessageContext1, null, CLIENT_ID_VALUE, true, 1000L, "Invalid authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO1, CLIENT_ID_VALUE, true, 1000L, "Inactive authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO2, CLIENT_ID_VALUE, true, 1000L, "Expired authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO2, CLIENT_ID_VALUE, true, System.currentTimeMillis(), "Callback url mismatch"},
                {oAuthTokenReqMessageContext2, authzCodeDO2, CLIENT_ID_VALUE, false, System.currentTimeMillis(), "PKCE validation failed"},
                {oAuthTokenReqMessageContext2, authzCodeDO2, INVALID_CLIENT, true, System.currentTimeMillis(), "Error while retrieving app information"},
        };
    }

    @Test(dataProvider = "buildErrorTokenRequestMessageContext")
    public void testValidateGrantException(Object tokenRequestMessageContext, Object authzCode, String clientId,
                                           boolean pkceValid, long timestamp, String expectedError) throws Exception {

        AuthzCodeDO authzCodeDO = (AuthzCodeDO) authzCode;
        mockStatic(OAuthCache.class);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "cacheEnabled", true);
        OAuthCache oAuthCache = mock(OAuthCache.class);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);

        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "oauthCache", oAuthCache);
        OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;
        when(log.isDebugEnabled()).thenReturn(true);

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        TokenPersistenceProcessor tokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(CLIENT_ID_VALUE)).thenReturn(oAuthAppDO);
        when(oAuthAppDAO.getAppInformation(INVALID_CLIENT)).thenThrow(new InvalidOAuthClientException("Error"));

        mockStatic(IdentityUtil.class);
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);
        doNothing().when(appInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

        tokenMgtDAO = mock(TokenMgtDAO.class);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "tokenMgtDAO", tokenMgtDAO);
        if (authzCodeDO != null) {
            WhiteboxImpl.setInternalState(authzCodeDO, "issuedTime", new Timestamp(timestamp));
            WhiteboxImpl.setInternalState(authzCodeDO, "consumerKey", clientId);
        }
        when(tokenMgtDAO.validateAuthorizationCode(anyString(), anyString())).thenReturn(authzCodeDO);

        spy(OAuth2Util.class);
        doReturn(pkceValid).when(OAuth2Util.class, "validatePKCE", anyString(), anyString(), anyString(),
                any(OAuthAppDO.class));
        try {
            authorizationCodeGrantHandler.validateGrant(tokReqMsgCtx);
            fail("Expected exception not thrown");
        } catch (IdentityOAuth2Exception e) {
            assertTrue(e.getMessage().contains(expectedError), "Expected error message with '" + expectedError + "'");
        }
    }

    @DataProvider(name = "BuildTokenMsgCtxForIssue")
    public Object[][] buildTokenMsgCtxForIssue() {

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        oAuthTokenReqMessageContext.setAuthorizedUser(new AuthenticatedUser());
        oAuthTokenReqMessageContext.getAuthorizedUser().setUserName("user");
        oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().setGrantType("grant");
        return new Object[][] {
            {oAuthTokenReqMessageContext, false, false},
            {oAuthTokenReqMessageContext, false, true},
            {oAuthTokenReqMessageContext, true, false},
            {oAuthTokenReqMessageContext, true, true}
        };
    }

    @Test(dataProvider = "BuildTokenMsgCtxForIssue")
    public void testIssue(Object tokenRequestMessageContext, boolean enableCache, boolean debugEnabled)
            throws IdentityOAuth2Exception, InvalidOAuthClientException, OAuthSystemException {

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "cacheEnabled", enableCache);
        OAuthCache oAuthCache = mock(OAuthCache.class);
        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);

        if (enableCache) {
            WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "oauthCache", oAuthCache);
        }
        OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;
        when(log.isDebugEnabled()).thenReturn(debugEnabled);

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        tokenMgtDAO = mock(TokenMgtDAO.class);
        OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuer.class);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "tokenMgtDAO", tokenMgtDAO);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "oauthIssuerImpl", oauthTokenIssuer);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        when(tokenMgtDAO.retrieveLatestAccessToken(anyString(), any(AuthenticatedUser.class), anyString(), anyString(),
                anyBoolean())).thenReturn(accessTokenDO);

        OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        when(oauthTokenIssuer.accessToken(tokReqMsgCtx)).thenReturn(StringUtils.EMPTY);

        assertNotNull(authorizationCodeGrantHandler.issue(tokReqMsgCtx));

    }

    @Test
    public void testAuthorizeAccessDelegation() throws IdentityOAuth2Exception {

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        assertTrue(authorizationCodeGrantHandler.authorizeAccessDelegation(new OAuthTokenReqMessageContext
                (new OAuth2AccessTokenReqDTO())));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testStoreAccessToken() throws IdentityException {

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        tokenMgtDAO = mock(TokenMgtDAO.class);
        WhiteboxImpl.setInternalState(authorizationCodeGrantHandler, "tokenMgtDAO", tokenMgtDAO);
        doNothing().when(tokenMgtDAO).storeAccessToken(anyString(), anyString(), any(AccessTokenDO.class),
                any(AccessTokenDO.class), anyString());
        doThrow(new IdentityException(TestConstants.ERROR)).when(tokenMgtDAO).storeAccessToken(anyString(), anyString(),
                any(AccessTokenDO.class), any(AccessTokenDO.class), anyString());
        authorizationCodeGrantHandler.storeAccessToken(new OAuth2AccessTokenReqDTO(), TestConstants.USERSTORE_DOMAIN,
                new AccessTokenDO(), TestConstants.NEW_ACCESS_TOKEN, new AccessTokenDO());
    }

    @Test
    public void testIssueRefreshToken() throws IdentityOAuth2Exception {

        mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getValueForIsRefreshTokenAllowed(OAuthConstants.GrantTypes.AUTHORIZATION_CODE)).
                thenReturn(true, false);

        assertTrue(authorizationCodeGrantHandler.issueRefreshToken());

        assertFalse(authorizationCodeGrantHandler.issueRefreshToken());
    }
}
