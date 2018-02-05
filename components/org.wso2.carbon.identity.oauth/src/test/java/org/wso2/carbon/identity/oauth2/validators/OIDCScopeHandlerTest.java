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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
public class OIDCScopeHandlerTest {

    private OIDCScopeHandler oidcScopeHandler;

    @BeforeMethod
    public void setUp() throws Exception {
        oidcScopeHandler = new OIDCScopeHandler();
    }

    @DataProvider(name = "ValidateScopeData")
    public Object[][] validateScopeData() {
        return new Object[][]{
                // grantType
                {GrantType.AUTHORIZATION_CODE.toString()},
                {"testGrantType"},
                {"idTokenNotAllowedGrantType"}
        };
    }

    @Test(dataProvider = "ValidateScopeData")
    public void testValidateScope(String grantType) throws Exception {
        String[] scopeArray = new String[]{"scope1", "scope2", "scope3"};
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        accessToken.setIdentifier("testAccessToken");
        accessToken.setTokenType("bearer");
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setGrantType(grantType);
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setScope(scopeArray);

        assertTrue(oidcScopeHandler.validateScope(tokReqMsgCtx));
    }

    @DataProvider(name = "CanHandleData")
    public Object[][] canHandleData() {
        String[] scopeArray1 = new String[]{"scope1", "scope2", "scope3"};
        String[] scopeArray2 = new String[]{OAuthConstants.Scope.OPENID, "scope2", "scope3"};

        return new Object[][]{
                // scopes
                // expected result
                {scopeArray1, false},
                {scopeArray2, true}
        };
    }

    @Test(dataProvider = "CanHandleData")
    public void testCanHandle(String[] scopes, boolean expectedResult) throws Exception {
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setScope(scopes);

        assertEquals(oidcScopeHandler.canHandle(tokReqMsgCtx), expectedResult);
    }

}
