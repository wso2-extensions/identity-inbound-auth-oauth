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

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth.config.OAuthCallbackHandlerMetaData;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doCallRealMethod;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_REVOKED;

@PrepareForTest({OAuth2Util.class, IdentityUtil.class, OAuthServerConfiguration.class, OAuthCache.class})
public class AbstractAuthorizationGrantHandlerTest extends PowerMockIdentityBaseTest {

    private static final String DEFAULT_CALLBACK_HANDLER_CLASS_NAME =
            "org.wso2.carbon.identity.oauth.callback.DefaultCallbackHandler";
    private static final String PASSWORD_GRANT = "password";

    @Mock
    private AbstractAuthorizationGrantHandler handler;
    @Mock
    private OAuthTokenReqMessageContext tokReqMsgCtx;
    @Mock
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    @Mock
    private OAuthAppDO oAuthAppDO;
    @Mock
    private TokenMgtDAO tokenMgtDAO;
    @Mock
    private OAuthCallbackManager oAuthCallbackManager;
    @Mock
    private OAuthServerConfiguration serverConfiguration;
    @Mock
    private OAuthCache oAuthCache;
    @Mock
    private OauthTokenIssuer oauthIssuer;
    @Mock
    private AccessTokenDO cacheEntry;
    @Mock
    private AccessTokenDO accessTokenDO;
    @Mock
    private RefreshGrantHandler refreshGrantHandler;
    @Mock
    private AuthenticatedUser authenticatedUser;

    private static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";
    private static final String tokenId = "435fgd3535343535353453453453";

    @BeforeMethod
    public void setUp() {
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() {
        Mockito.reset(handler, tokReqMsgCtx, oAuth2AccessTokenReqDTO, oAuthAppDO, tokenMgtDAO, oAuthCallbackManager,
                serverConfiguration, oAuthCache, oauthIssuer, cacheEntry, accessTokenDO, refreshGrantHandler, authenticatedUser);
    }

    @DataProvider(name = "IssueDataProvider")
    public Object[][] issueDataProvider() {
        return new Object[][]{
                {true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, true, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, false, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false},
                {false, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {false, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false},
                {true, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false},

                {true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {true, true, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {true, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {true, false, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, true},
                {false, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {false, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, true},
                {true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, true},
                {true, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {true, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, true},
        };
    }

    @Test(dataProvider = "IssueDataProvider")
    public void testIssue(boolean cacheEnabled,
                          boolean cacheEntryAvailable,
                          long cachedTokenValidity,
                          long cachedRefreshTokenValidity,
                          long dbTokenValidity,
                          long dbRefreshTokenValidity,
                          boolean dbEntryAvailable,
                          String dbTokenState,
                          boolean tokenLoggable) throws Exception {

        Field field = AbstractAuthorizationGrantHandler.class.getDeclaredField("tokenMgtDAO");
        field.setAccessible(true);
        field.set(handler, tokenMgtDAO);
        field.setAccessible(false);

        field = AbstractAuthorizationGrantHandler.class.getDeclaredField("callbackManager");
        field.setAccessible(true);
        field.set(handler, oAuthCallbackManager);
        field.setAccessible(false);

        field = AbstractAuthorizationGrantHandler.class.getDeclaredField("oauthCache");
        field.setAccessible(true);
        field.set(handler, oAuthCache);
        field.setAccessible(false);

        field = AbstractAuthorizationGrantHandler.class.getDeclaredField("cacheEnabled");
        field.setAccessible(true);
        field.set(handler, cacheEnabled);
        field.setAccessible(false);

        field = AbstractAuthorizationGrantHandler.class.getDeclaredField("oauthIssuerImpl");
        field.setAccessible(true);
        field.set(handler, oauthIssuer);
        field.setAccessible(false);

        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);
        when(oAuthCache.isEnabled()).thenReturn(false);
        when(oAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(cacheEntry);

        String accessToken = "654564654646456456456456487987";
        when(cacheEntry.getAccessToken()).thenReturn(accessToken);
        when(cacheEntry.getTokenId()).thenReturn(tokenId);
        when(cacheEntry.getValidityPeriod()).thenReturn(cachedTokenValidity);
        when(cacheEntry.getValidityPeriodInMillis()).thenReturn(cachedTokenValidity * 1000);
        when(cacheEntry.getRefreshTokenValidityPeriodInMillis()).thenReturn(cachedRefreshTokenValidity);
        if (cachedRefreshTokenValidity > 0) {
            when(cacheEntry.getRefreshTokenIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (60 * 1000)));
        } else {
            when(cacheEntry.getRefreshTokenIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (1000 * 60 * 1000)));
        }
        if (cachedTokenValidity > 0) {
            when(cacheEntry.getIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (1000)));
        } else {
            when(cacheEntry.getIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (10 * 60 * 1000)));
        }

        when(serverConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);

        Map<String, AuthorizationGrantHandler> supportedGrantTypes = new HashMap<>();
        supportedGrantTypes.put("refresh_token", refreshGrantHandler);
        when(serverConfiguration.getSupportedGrantTypes()).thenReturn(supportedGrantTypes);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);

        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(tokReqMsgCtx.getScope()).thenReturn(new String[]{"scope1", "scope2"});
        when(tokReqMsgCtx.getAuthorizedUser()).thenReturn(authenticatedUser);

        when(authenticatedUser.toString()).thenReturn("randomUser");

        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(clientId);
        when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn(PASSWORD_GRANT);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(any(String.class))).thenReturn(oAuthAppDO);
        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(false);
        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(false);

        when(OAuth2Util.buildScopeString(any(String[].class))).thenCallRealMethod();
        when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenCallRealMethod();
        when(OAuth2Util.getTokenExpireTimeMillis(any(AccessTokenDO.class))).thenCallRealMethod();
        when(OAuth2Util.getRefreshTokenExpireTimeMillis(any(AccessTokenDO.class))).thenCallRealMethod();
        when(OAuth2Util.getAccessTokenExpireMillis(any(AccessTokenDO.class))).thenCallRealMethod();

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(any(String.class))).thenReturn(false);
        when(IdentityUtil.isTokenLoggable(anyString())).thenReturn(tokenLoggable);

        when(oauthIssuer.accessToken(any(OAuthTokenReqMessageContext.class))).thenReturn(accessToken);

        if (dbEntryAvailable) {
            when(tokenMgtDAO.retrieveLatestAccessToken(anyString(), any(AuthenticatedUser.class), anyString(),
                    anyString(), anyBoolean())).thenReturn(accessTokenDO);
        } else {
            when(tokenMgtDAO.retrieveLatestAccessToken(anyString(), any(AuthenticatedUser.class), anyString(),
                    anyString(), anyBoolean())).thenReturn(null);
        }
        when(accessTokenDO.getTokenState()).thenReturn(dbTokenState);
        when(accessTokenDO.getValidityPeriod()).thenReturn(dbTokenValidity);
        when(accessTokenDO.getValidityPeriodInMillis()).thenReturn(dbTokenValidity * 1000);
        when(accessTokenDO.getRefreshTokenValidityPeriodInMillis()).thenReturn(dbRefreshTokenValidity);
        if (dbRefreshTokenValidity > 0) {
            when(accessTokenDO.getRefreshTokenIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (60 * 1000)));
        } else {
            when(accessTokenDO.getRefreshTokenIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (1000 * 60 * 1000)));
        }
        if (dbTokenValidity > 0) {
            when(accessTokenDO.getIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (1000)));
        } else {
            when(accessTokenDO.getIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (10 * 60 * 1000)));
        }
        when(accessTokenDO.getAccessToken()).thenReturn(accessToken);

        doCallRealMethod().when(handler).issue(any(OAuthTokenReqMessageContext.class));
        OAuth2AccessTokenRespDTO tokenRespDTO = handler.issue(tokReqMsgCtx);
        assertEquals(tokenRespDTO.getAccessToken(), accessToken, "Returned access token is not as expected.");
    }

    @DataProvider(name = "AuthorizeAccessDelegationDataProvider")
    public Object[][] buildAuthorizeAccessDelegationDataProvider() {
        return new Object[][]{
                {GrantType.SAML20_BEARER.toString()},
                {GrantType.IWA_NTLM.toString()},
                {PASSWORD_GRANT}
        };
    }

    @Test(dataProvider = "AuthorizeAccessDelegationDataProvider")
    public void testAuthorizeAccessDelegation(String grantType) throws Exception {
        Set<OAuthCallbackHandlerMetaData> callbackHandlerMetaData = new HashSet<>();
        callbackHandlerMetaData.add(new OAuthCallbackHandlerMetaData(DEFAULT_CALLBACK_HANDLER_CLASS_NAME, null, 1));
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
        when(serverConfiguration.getCallbackHandlerMetaData()).thenReturn(callbackHandlerMetaData);

        OAuthCallbackManager oAuthCallbackManager = new OAuthCallbackManager();
        Field field = AbstractAuthorizationGrantHandler.class.getDeclaredField("callbackManager");
        field.setAccessible(true);
        field.set(handler, oAuthCallbackManager);
        field.setAccessible(false);

        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(clientId);
        when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn(grantType);

        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(tokReqMsgCtx.getAuthorizedUser()).thenReturn(authenticatedUser);

        when(authenticatedUser.toString()).thenReturn("randomUser");
        doCallRealMethod().when(handler).authorizeAccessDelegation(any(OAuthTokenReqMessageContext.class));
        boolean result = handler.authorizeAccessDelegation(tokReqMsgCtx);
        assertTrue(result);
    }

    @DataProvider(name = "IsAuthorizedClientDataProvider")
    public Object[][] buildIsAuthorizedClient() {
        return new Object[][]{
                {true, GrantType.SAML20_BEARER.toString() + " " + GrantType.IWA_NTLM.toString() + " " + PASSWORD_GRANT,
                        PASSWORD_GRANT, true},
                {true, GrantType.SAML20_BEARER.toString() + " " + GrantType.IWA_NTLM.toString(), PASSWORD_GRANT, false},
                {true, null, PASSWORD_GRANT, false},
                {false, null, PASSWORD_GRANT, false},
        };
    }

    @Test(dataProvider = "IsAuthorizedClientDataProvider")
    public void testIsAuthorizedClient(boolean oAuthAppDOAvailable, String grantTypes, String grantType, boolean
            result) throws Exception {
        if (oAuthAppDOAvailable) {
            when(tokReqMsgCtx.getProperty("OAuthAppDO")).thenReturn(oAuthAppDO);
        } else {
            when(tokReqMsgCtx.getProperty("OAuthAppDO")).thenReturn(null);
        }
        when(oAuthAppDO.getGrantTypes()).thenReturn(grantTypes);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn(grantType);

        doCallRealMethod().when(handler).isAuthorizedClient(any(OAuthTokenReqMessageContext.class));
        assertEquals(handler.isAuthorizedClient(tokReqMsgCtx), result);
    }
}
