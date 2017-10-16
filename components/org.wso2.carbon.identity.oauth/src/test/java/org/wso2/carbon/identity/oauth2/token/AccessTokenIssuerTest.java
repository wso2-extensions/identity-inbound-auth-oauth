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

package org.wso2.carbon.identity.oauth2.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.handlers.clientauth.BasicAuthClientAuthHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.clientauth.ClientAuthenticationHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, LogFactory.class})
public class AccessTokenIssuerTest {

    @Mock
    private Log log;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private OAuthAppDO mockOAuthAppDO;
    @Mock
    private PasswordGrantHandler passwordGrantHandler;
    @Mock
    private OAuth2AccessTokenRespDTO mockOAuth2AccessTokenRespDTO;
    @Mock
    private BasicAuthClientAuthHandler basicAuthClientAuthHandler;
    @Mock
    private OAuth2AccessTokenReqDTO tokenReqDTO;

    @DataProvider(name = "AccessTokenIssue")
    public Object[][] accessTokenIssue() {
        return new Object[][]{
                {"carbon.super", true, true, true, true, true, true, true, true, false},
                {"carbon.super", true, true, false, true, true, true, true, false, false},
                {"carbon.super", true, true, true, false, true, true, true, false, false},
                {"carbon.super", true, true, true, true, false, true, true, false, false},
                {"carbon.super", true, true, true, true, true, false, true, false, false},
                {"carbon.super", true, true, true, true, true, true, true, true, true},
                {"carbon.super", true, true, false, true, true, true, true, false, true},
                {"carbon.super", true, true, true, false, true, true, true, false, true},
                {"carbon.super", true, true, true, true, false, true, true, false, true},
                {"carbon.super", true, true, true, true, true, false, true, false, true}
        };
    }

    @Test(dataProvider = "AccessTokenIssue")
    public void testIssue(String tenant, boolean isOfTypeApplicationUser, boolean isAuthorizedClient, boolean
            validateGrant, boolean authorizeAccessDelegation, boolean validateScope, boolean authenticateClient,
                          boolean canAuthenticate, boolean success, boolean debugEnabled) throws IdentityException {

        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(LogFactory.class);
        when(LogFactory.getLog(any(Class.class))).thenReturn(log);

        when(log.isDebugEnabled()).thenReturn(debugEnabled);
        doNothing().when(log).debug(any());
        doNothing().when(log).debug(any(), any(Throwable.class));

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(mockOAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(any(OAuthAppDO.class))).thenReturn(tenant);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        Map<String, AuthorizationGrantHandler> authzGrantHandlers = new Hashtable<>();

        when(passwordGrantHandler.isOfTypeApplicationUser()).thenReturn(isOfTypeApplicationUser);
        when(passwordGrantHandler.isAuthorizedClient(any(OAuthTokenReqMessageContext.class))).thenReturn
                (isAuthorizedClient);
        when(passwordGrantHandler.validateGrant(any(OAuthTokenReqMessageContext.class))).thenReturn(validateGrant);
        when(passwordGrantHandler.authorizeAccessDelegation(any(OAuthTokenReqMessageContext.class))).thenReturn
                (authorizeAccessDelegation);
        when(passwordGrantHandler.validateScope(any(OAuthTokenReqMessageContext.class))).thenReturn(validateScope);


        doNothing().when(mockOAuth2AccessTokenRespDTO).setCallbackURI(anyString());
        doNothing().when(mockOAuth2AccessTokenRespDTO).setAuthorizedScopes(anyString());

        when(passwordGrantHandler.issue(any(OAuthTokenReqMessageContext.class))).thenReturn
                (mockOAuth2AccessTokenRespDTO);
        authzGrantHandlers.put("password", passwordGrantHandler);

        when(oAuthServerConfiguration.getSupportedGrantTypes()).thenReturn(authzGrantHandlers);

        List<ClientAuthenticationHandler> clientAuthenticationHandlers = new ArrayList<>();
        when(basicAuthClientAuthHandler.authenticateClient(any(OAuthTokenReqMessageContext.class))).thenReturn
                (authenticateClient);
        when(basicAuthClientAuthHandler.canAuthenticate(any(OAuthTokenReqMessageContext.class))).thenReturn
                (canAuthenticate);
        clientAuthenticationHandlers.add(basicAuthClientAuthHandler);

        when(oAuthServerConfiguration.getSupportedClientAuthHandlers()).thenReturn(clientAuthenticationHandlers);

        AccessTokenIssuer tokenIssuer = AccessTokenIssuer.getInstance();

        when(tokenReqDTO.getGrantType()).thenReturn("password");

        OAuth2AccessTokenRespDTO tokenRespDTO = tokenIssuer.issue(tokenReqDTO);
        Assert.assertEquals(tokenRespDTO.isError(), !success);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
