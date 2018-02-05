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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Test class for ClientCredentialsGrantHandler test cases.
 */
@PrepareForTest({OAuthServerConfiguration.class, AbstractAuthorizationGrantHandler.class})
public class ClientCredentialsGrantHandlerTest extends PowerMockIdentityBaseTest {

    @Mock
    private TokenMgtDAO mockTokenMgtDAO;

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    private ClientCredentialsGrantHandler clientCredentialsGrantHandler;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        mockStatic(OAuthServerConfiguration.class);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(mockTokenMgtDAO);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
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
