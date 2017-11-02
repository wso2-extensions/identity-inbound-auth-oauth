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

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.File;
import java.lang.reflect.Field;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;

/**
 * Unit test covering TokenResponseTypeHandler class
 */
@PrepareForTest({OAuthComponentServiceHolder.class, IdentityUtil.class, OAuthEventInterceptor.class, OAuth2Util.class,
        IdentityTenantUtil.class})
public class TokenResponseTypeHandlerTest extends PowerMockIdentityBaseTest {
    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty("carbon.home", System.getProperty("user.dir")
                + File.separator + "target");
        PowerMockito.mockStatic(IdentityUtil.class);
        PowerMockito.when(IdentityUtil.getIdentityConfigDirPath())
                .thenReturn(System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources" + File.separator + "conf");

        OAuthComponentServiceHolder oAuthComponentServiceHolder
                = PowerMockito.mock(OAuthComponentServiceHolder.class);
        OAuthEventInterceptor interceptor = PowerMockito.mock(OAuthEventInterceptor.class);
        OAuthServerConfiguration oAuthServerConfiguration = PowerMockito.mock(OAuthServerConfiguration.class);
        PowerMockito.when(oAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(interceptor);

        RealmService realmService = PowerMockito.mock(RealmService.class);
        TenantManager manager = PowerMockito.mock(TenantManager.class);
        PowerMockito.when(realmService.getTenantManager()).thenReturn(manager);

        PowerMockito.when(manager.getTenantId(anyString())).thenReturn(-1);

        Field relamServiceObj = IdentityTenantUtil.class.getDeclaredField("realmService");
        relamServiceObj.setAccessible(true);
        relamServiceObj.set(null, realmService);

        Field f1 = OAuthComponentServiceHolder.class.getDeclaredField("instance");
        f1.setAccessible(true);
        f1.set(null, oAuthComponentServiceHolder);

        Field oAuthCallbackHandlerRegistry =
                OAuthServerConfiguration.class.getDeclaredField("instance");
        oAuthCallbackHandlerRegistry.setAccessible(true);
        oAuthCallbackHandlerRegistry.set(null, null);

        Field oAuthServerConfigInstance =
                OAuthServerConfiguration.class.getDeclaredField("instance");
        oAuthServerConfigInstance.setAccessible(true);
        oAuthServerConfigInstance.set(null, oAuthServerConfiguration);

        AuthorizationGrantCache authorizationGrantCache =
                PowerMockito.mock(AuthorizationGrantCache.class);

        Field authorizationGrantCacheInstance =
                AuthorizationGrantCache.class.getDeclaredField("instance");
        authorizationGrantCacheInstance.setAccessible(true);
        authorizationGrantCacheInstance.set(null, authorizationGrantCache);
    }

    @Test
    public void testIssue() throws Exception {
        TokenResponseTypeHandler tokenResponseTypeHandler = new TokenResponseTypeHandler();
        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();

        authorizationReqDTO.setCallbackUrl("https://localhost:8000/callback");
        authorizationReqDTO.setConsumerKey("SDSDSDS23131231");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PTEST");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        OAuthAuthzReqMessageContext authAuthzReqMessageContext
                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext
                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        TokenMgtDAO tokenMgtDAO = PowerMockito.mock(TokenMgtDAO.class);

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken("abcdefghijklmn");
        accessTokenDO.setAuthzUser(authenticatedUser);

        PowerMockito.when(tokenMgtDAO.retrieveLatestAccessToken(
                "SDSDSDS23131231", authenticatedUser,
                null, null, false)).thenReturn(accessTokenDO);

        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util
                .getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);

        PowerMockito.when(OAuth2Util
                .isOIDCAuthzRequest(new String[]{"scope1", "scope2",
                        OAuthConstants.Scope.OPENID})).thenReturn(true);

        Object baseClass = tokenResponseTypeHandler;
        Field f2 = baseClass.getClass().getSuperclass().getDeclaredField("tokenMgtDAO");
        f2.setAccessible(true);
        f2.set(baseClass, tokenMgtDAO);

        Field cachenabledField = baseClass.getClass().getSuperclass()
                .getDeclaredField("cacheEnabled");
        cachenabledField.setAccessible(true);
        cachenabledField.set(baseClass, Boolean.TRUE);

        PowerMockito.when(tokenMgtDAO.retrieveLatestAccessToken(anyString(),
                eq(authenticatedUser), anyString(), anyString(), anyBoolean())).thenReturn(accessTokenDO);

        OauthTokenIssuer oAuthIssuer = PowerMockito.mock(OauthTokenIssuer.class);

        Field f3 = baseClass.getClass().getSuperclass().getDeclaredField("oauthIssuerImpl");
        f3.setAccessible(true);
        f3.set(baseClass, oAuthIssuer);

        PowerMockito.when(oAuthIssuer.accessToken(authAuthzReqMessageContext)).thenReturn("1234567890");
        PowerMockito.when(oAuthIssuer.refreshToken(authAuthzReqMessageContext)).thenReturn("1234567890");

        OAuth2AuthorizeRespDTO auth2AuthorizeReqDTO = tokenResponseTypeHandler.
                issue(authAuthzReqMessageContext);
        Assert.assertEquals(auth2AuthorizeReqDTO.getAccessToken().toString(),
                "1234567890", "No expected access token returned");
    }
}
