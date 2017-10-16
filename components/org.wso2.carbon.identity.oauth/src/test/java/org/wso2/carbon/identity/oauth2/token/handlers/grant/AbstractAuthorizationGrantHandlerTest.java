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

import org.apache.commons.logging.Log;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doCallRealMethod;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_REVOKED;

@PrepareForTest({OAuth2Util.class, IdentityUtil.class, OAuthServerConfiguration.class, OAuthCache.class})
public class AbstractAuthorizationGrantHandlerTest {

    @Mock
    private Log log;
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

    private String accessToken = "654564654646456456456456487987";
    static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";
    static final String tokeId = "435fgd3535343535353453453453";

    @DataProvider(name = "IssueDataProvider")
    public Object[][] buildScopeString() {
        return new Object[][]{
                {true, true, false, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, true, false, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, true, false, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, false, false, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {false, false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {false, false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false},
                {false, false, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {false, false, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false},
                {true, false, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false},

                {true, true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, true, true, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, true, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {true, false, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false},
                {false, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {false, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false},
                {false, false, true, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {false, false, true, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false},
                {true, false, true, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false},
                {true, false, true, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false},

                {true, true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {true, true, true, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {true, true, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {true, false, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true},
                {false, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {false, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, true},
                {false, false, true, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {false, false, true, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, true},
                {true, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {true, false, true, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, true},
                {true, false, true, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, true},
                {true, false, true, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, true},
        };
    }

    @Test(dataProvider = "IssueDataProvider")
    public void testIssue(boolean cacheEnabled, boolean cacheEntryAvailable, boolean debugEnabled, long
            cachedTokenValidity, long cachedRefreshTokenValidity, long dbTokenValidity, long dbRefreshTokenValidity,
                          boolean dbEntryAvailable, String dbTokenState, boolean tokenLoggable)
            throws Exception {

        when(log.isDebugEnabled()).thenReturn(debugEnabled);
        doNothing().when(log).debug(any());
        doNothing().when(log).debug(any(), any(Throwable.class));

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

        field = AbstractAuthorizationGrantHandler.class.getDeclaredField("log");
        field.setAccessible(true);
        field.set(handler, log);
        field.setAccessible(false);

        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCache);
        when(oAuthCache.isEnabled()).thenReturn(false);
        when(oAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(cacheEntry);

        when(cacheEntry.getAccessToken()).thenReturn(accessToken);
        when(cacheEntry.getTokenId()).thenReturn(tokeId);

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
        when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn("password");

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.buildScopeString(any(String[].class))).thenReturn("scope1 scope2");
        when(OAuth2Util.getAppInformationByClientId(any(String.class))).thenReturn(oAuthAppDO);
        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(false);
        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(false);
        when(OAuth2Util.getTokenExpireTimeMillis(cacheEntry)).thenReturn(cachedTokenValidity);
        when(OAuth2Util.getRefreshTokenExpireTimeMillis(cacheEntry)).thenReturn(cachedRefreshTokenValidity);
        when(OAuth2Util.getTokenExpireTimeMillis(accessTokenDO)).thenReturn(dbTokenValidity);
        when(OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO)).thenReturn(dbRefreshTokenValidity);

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
        if (dbRefreshTokenValidity > 0) {
            when(accessTokenDO.getRefreshTokenIssuedTime()).thenReturn(new Timestamp(System.currentTimeMillis() -
                    (460 * 60 * 1000)));
        } else {
            when(accessTokenDO.getRefreshTokenIssuedTime()).thenReturn(null);
        }
        when(accessTokenDO.getAccessToken()).thenReturn(accessToken);

        doCallRealMethod().when(handler).issue(any(OAuthTokenReqMessageContext.class));
        OAuth2AccessTokenRespDTO tokenRespDTO = handler.issue(tokReqMsgCtx);
        Assert.assertEquals(tokenRespDTO.getAccessToken(), accessToken, "Returned access token is not as expected.");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}