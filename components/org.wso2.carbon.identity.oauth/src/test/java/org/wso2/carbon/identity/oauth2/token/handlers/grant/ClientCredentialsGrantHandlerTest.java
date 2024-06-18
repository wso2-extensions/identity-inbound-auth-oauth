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
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Test class for ClientCredentialsGrantHandler test cases.
 */
@WithCarbonHome
public class ClientCredentialsGrantHandlerTest {

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    private ClientCredentialsGrantHandler clientCredentialsGrantHandler;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
    }

    @AfterMethod
    public void tearDown() {

        oAuthServerConfiguration.close();
    }

    @Test
    public void testValidateGrant() throws Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId("clientId");
        tokenReqDTO.setRefreshToken("refreshToken");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        clientCredentialsGrantHandler = new ClientCredentialsGrantHandler();
        clientCredentialsGrantHandler.init();
        Boolean result = clientCredentialsGrantHandler.validateGrant(tokenReqMessageContext);
        assertTrue(result, "Grant validation should be successful.");
    }

    @Test
    public void testIsOfTypeApplicationUser() throws Exception {

        clientCredentialsGrantHandler = new ClientCredentialsGrantHandler();
        clientCredentialsGrantHandler.init();
        assertFalse(clientCredentialsGrantHandler.isOfTypeApplicationUser());
    }

    @Test
    public void testIssueRefreshToken() throws IdentityOAuth2Exception {

        when(mockOAuthServerConfiguration.getValueForIsRefreshTokenAllowed(anyString())).thenReturn(true);
        clientCredentialsGrantHandler = new ClientCredentialsGrantHandler();
        clientCredentialsGrantHandler.init();
        assertTrue(clientCredentialsGrantHandler.issueRefreshToken(), "Refresh token issuance failed.");
    }
}
