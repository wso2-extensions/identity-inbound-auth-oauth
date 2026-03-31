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
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
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
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * This class defines unit test for AuthorizationCodeGrantHandler class
 */
@WithCarbonHome
public class AuthorizationCodeGrantHandlerTest {

    public static final String CLIENT_ID_VALUE = "clientIdValue";
    public static final String INVALID_CLIENT = "invalidClient";
    OAuthServerConfiguration mockOAuthServerConfiguration;
    AuthorizationCodeGrantHandler authorizationCodeGrantHandler;

    @BeforeTest()
    public void setUp() {
    }

    @DataProvider(name = "BuildTokenRequestMessageContext")
    public Object[][] buildTokenRequestMessageContext() throws Exception {

        OAuthTokenReqMessageContext messageContext1 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        messageContext1.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");

        OAuthTokenReqMessageContext messageContext2 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        messageContext2.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        messageContext2.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl");

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        setPrivateField(authzCodeDO1, "authorizedUser", authenticatedUser);
        setPrivateField(authzCodeDO1, "callbackUrl", "callBackUrl");

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

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            setPrivateField(authorizationCodeGrantHandler, "cacheEnabled", cacheEnabled);
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            if (cacheEnabled) {
                setPrivateField(authorizationCodeGrantHandler, "oauthCache", mockOAuthCache);
            }
            OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;

            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            TokenPersistenceProcessor tokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);

            OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
//            whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
            when(oAuthAppDAO.getAppInformation(anyString())).thenReturn(oAuthAppDO);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            doNothing().when(mockAppInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

            assertEquals(authorizationCodeGrantHandler.validateGrant(tokReqMsgCtx), expectedResult);
        }
    }

    @DataProvider(name = "buildErrorTokenRequestMessageContext")
    public Object[][] buildErrorTokenRequestMessageContext() throws Exception {

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
        setPrivateField(authzCodeDO1, "authorizedUser", authenticatedUser);
        setPrivateField(authzCodeDO1, "callbackUrl", "callBackUrl");
        setPrivateField(authzCodeDO1, "state", "INACTIVE");

        AuthzCodeDO authzCodeDO2 = new AuthzCodeDO();
        setPrivateField(authzCodeDO2, "authorizedUser", authenticatedUser);
        setPrivateField(authzCodeDO2, "callbackUrl", "callBackUrl");
        setPrivateField(authzCodeDO2, "validityPeriod", 3000000L);

        return new Object[][]{
                {oAuthTokenReqMessageContext1, null, CLIENT_ID_VALUE, true, 1000L, "Invalid authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO1, CLIENT_ID_VALUE, true, 1000L,
                        "Inactive authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO2, CLIENT_ID_VALUE, true, 1000L,
                        "Expired authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO2, CLIENT_ID_VALUE, true, System.currentTimeMillis(),
                        "Callback url mismatch"},
                {oAuthTokenReqMessageContext2, authzCodeDO2, CLIENT_ID_VALUE, false, System.currentTimeMillis(),
                        "PKCE validation failed"},
                {oAuthTokenReqMessageContext2, authzCodeDO2, INVALID_CLIENT, true, System.currentTimeMillis(),
                        "Error while retrieving app information"},
        };
    }

    @Test(dataProvider = "buildErrorTokenRequestMessageContext")
    public void testValidateGrantException(Object tokenRequestMessageContext, Object authzCode, String clientId,
                                           boolean pkceValid, long timestamp, String expectedError) throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class);) {
            setPrivateField(authorizationCodeGrantHandler, "cacheEnabled", true);
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            setPrivateField(authorizationCodeGrantHandler, "oauthCache", mockOAuthCache);
            OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;

            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            TokenPersistenceProcessor tokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);

            OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
//            whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
            when(oAuthAppDAO.getAppInformation(CLIENT_ID_VALUE)).thenReturn(oAuthAppDO);
            when(oAuthAppDAO.getAppInformation(INVALID_CLIENT)).thenThrow(new InvalidOAuthClientException("Error"));

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            doNothing().when(mockAppInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

//            spy(OAuth2Util.class);
//            doReturn(pkceValid).when(OAuth2Util.class, "validatePKCE", anyString(), anyString(), anyString(),
//                    any(OAuthAppDO.class));
            try {
                authorizationCodeGrantHandler.validateGrant(tokReqMsgCtx);
                fail("Expected exception not thrown");
            } catch (IdentityOAuth2Exception e) {
                assertTrue(e.getMessage().contains(expectedError),
                        "Expected error message with '" + expectedError + "'");
            }
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
            throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            setPrivateField(authorizationCodeGrantHandler, "cacheEnabled", enableCache);
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            if (enableCache) {
                setPrivateField(authorizationCodeGrantHandler, "oauthCache", mockOAuthCache);
            }
            OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;

            OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuer.class);
            setPrivateField(authorizationCodeGrantHandler, "oauthIssuerImpl", oauthTokenIssuer);

            OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
            when(oauthTokenIssuer.accessToken(tokReqMsgCtx)).thenReturn(StringUtils.EMPTY);

            assertNotNull(authorizationCodeGrantHandler.issue(tokReqMsgCtx));
        }

    }

    @Test
    public void testAuthorizeAccessDelegation() throws IdentityOAuth2Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            assertTrue(authorizationCodeGrantHandler.authorizeAccessDelegation(new OAuthTokenReqMessageContext
                    (new OAuth2AccessTokenReqDTO())));
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testStoreAccessToken() throws IdentityException {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            authorizationCodeGrantHandler.storeAccessToken(new OAuth2AccessTokenReqDTO(),
                    TestConstants.USERSTORE_DOMAIN,
                    new AccessTokenDO(), TestConstants.NEW_ACCESS_TOKEN, new AccessTokenDO());
        }
    }

    @Test
    public void testIssueRefreshToken() throws IdentityOAuth2Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getValueForIsRefreshTokenAllowed(
                    OAuthConstants.GrantTypes.AUTHORIZATION_CODE)).
                    thenReturn(true, false);

            assertTrue(authorizationCodeGrantHandler.issueRefreshToken());

            assertFalse(authorizationCodeGrantHandler.issueRefreshToken());
        }
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }
}
