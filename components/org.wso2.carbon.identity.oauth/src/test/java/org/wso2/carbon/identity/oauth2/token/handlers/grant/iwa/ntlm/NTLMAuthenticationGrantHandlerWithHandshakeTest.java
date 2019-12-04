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

package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuthServerConfiguration.class})
public class NTLMAuthenticationGrantHandlerWithHandshakeTest {

    private static final String TOKEN = "c2Fkc2Fkc2FzYWQzMmQzMmQzMmUyM2UzMmUzMjIzZTMyZTMyZTMyZDI=";

    @Mock
    private OAuthServerConfiguration serverConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        MockitoAnnotations.initMocks(this);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
    }

    @Test
    public void testGetNLTMMessageType() throws Exception {


    }

    @DataProvider
    public Object[][] getValidateGrantData() {
        return new Object[][]{
                {null}, {TOKEN}
        };
    }

    @Test(dataProvider = "getValidateGrantData")
    public void testValidateGrant(String token) throws Exception {
        NTLMAuthenticationGrantHandlerWithHandshake ntlmAuthenticationGrantHandlerWithHandshake = new
                NTLMAuthenticationGrantHandlerWithHandshake();
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setWindowsToken(token);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext =
                new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        ntlmAuthenticationGrantHandlerWithHandshake.validateGrant(oAuthTokenReqMessageContext);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}
