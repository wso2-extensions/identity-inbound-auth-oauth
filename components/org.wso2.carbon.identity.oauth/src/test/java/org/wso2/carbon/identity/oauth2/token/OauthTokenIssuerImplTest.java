/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.token;

import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.issuer.UUIDValueGenerator;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({OAuthServerConfiguration.class,OAuth2Util.class})
public class OauthTokenIssuerImplTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    private OauthTokenIssuerImpl accessTokenIssuer;

    @Mock
    private OAuthAuthzReqMessageContext authAuthzReqMessageContext;

    @Mock
    private OAuthTokenReqMessageContext tokenReqMessageContext;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getOAuthTokenGenerator())
                .thenReturn(new OAuthIssuerImpl(new UUIDValueGenerator()));

        accessTokenIssuer = new OauthTokenIssuerImpl();
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.checkTB(any(OAuthTokenReqMessageContext.class),anyString())).thenReturn("");
        when(OAuth2Util.checkTB(any(OAuthAuthzReqMessageContext.class),anyString())).thenReturn("");

    }

    @Test
    public void testAccessToken() throws Exception {
        assertNotNull(UUID.fromString(accessTokenIssuer.accessToken(authAuthzReqMessageContext)));
    }

    @Test
    public void testRefreshToken() throws Exception {
        assertNotNull(UUID.fromString(accessTokenIssuer.refreshToken(authAuthzReqMessageContext)));
    }

    @Test
    public void testAuthorizationCode() throws Exception {
        assertNotNull(UUID.fromString(accessTokenIssuer.authorizationCode(authAuthzReqMessageContext)));
    }

    @Test
    public void testAccessToken1() throws Exception {
        assertNotNull(UUID.fromString(accessTokenIssuer.accessToken(tokenReqMessageContext)));
    }

    @Test
    public void testRefreshToken1() throws Exception {
        assertNotNull(UUID.fromString(accessTokenIssuer.refreshToken(tokenReqMessageContext)));
    }

}