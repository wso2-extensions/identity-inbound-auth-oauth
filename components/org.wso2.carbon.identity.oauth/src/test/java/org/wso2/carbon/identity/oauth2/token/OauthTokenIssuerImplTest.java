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
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;

import java.util.UUID;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertNotNull;

public class OauthTokenIssuerImplTest {

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    private OauthTokenIssuerImpl accessTokenIssuer;

    @Mock
    private OAuthAuthzReqMessageContext authAuthzReqMessageContext;

    @Mock
    private OAuthTokenReqMessageContext tokenReqMessageContext;

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.getOAuthTokenGenerator())
                .thenReturn(new OAuthIssuerImpl(new UUIDValueGenerator()));

        accessTokenIssuer = new OauthTokenIssuerImpl();
    }

    @AfterMethod
    public void tearDown() {
        oAuthServerConfiguration.close();
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
