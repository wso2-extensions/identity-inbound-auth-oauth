/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWSAlgorithm;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.common.testng.WithRegistry;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

@WithCarbonHome
@WithRegistry
@WithRealmService
public class OpenIDConnectSystemClaimImplTest {

    private static final String AUTHORIZATION_CODE = "testAuthorizationCode";
    private static final String EMPTY_VALUE = null;
    private static final String ACCESS_TOKEN = TestConstants.ACCESS_TOKEN;
    private static final String AT_HASH = OAuthConstants.OIDCClaims.AT_HASH;
    private static final String C_HASH = OAuthConstants.OIDCClaims.C_HASH;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private OAuthTokenReqMessageContext oAuthTokenReqMessageContext;
    private OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO;
    private OpenIDConnectSystemClaimImpl openIDConnectSystemClaim;
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;
    private OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO;

    @BeforeClass
    public void setUp() throws Exception {

        oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        oAuth2AccessTokenRespDTO = new OAuth2AccessTokenRespDTO();
        oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
        oAuthAuthzReqMessageContext = new OAuthAuthzReqMessageContext(oAuth2AuthorizeReqDTO);
        oAuth2AuthorizeRespDTO = new OAuth2AuthorizeRespDTO();
        openIDConnectSystemClaim = new OpenIDConnectSystemClaimImpl();
    }

    @DataProvider(name = "getAuthzAdditionalClaims")
    public Object[][] getAuthzAdditionalClaims() throws Exception {

        return new Object[][] {
                {"code", AUTHORIZATION_CODE, ACCESS_TOKEN, getHashValue(AUTHORIZATION_CODE), EMPTY_VALUE},
                {"token", AUTHORIZATION_CODE, ACCESS_TOKEN, EMPTY_VALUE, getHashValue(ACCESS_TOKEN)},
                {"id_token", AUTHORIZATION_CODE, ACCESS_TOKEN, EMPTY_VALUE, EMPTY_VALUE}
        };
    }

    @Test(dataProvider = "getAuthzAdditionalClaims")
    public void testAuthzGetAdditionalClaims(String responseType,
                                             String authorizationCode, String accessToken,
                                             String authorizationHashCode, String hashAccessToken) throws Exception {

        oAuth2AuthorizeRespDTO.setAuthorizationCode(authorizationCode);
        oAuth2AuthorizeReqDTO.setResponseType(responseType);
        oAuth2AuthorizeRespDTO.setAccessToken(accessToken);
        Map<String, Object> claims = openIDConnectSystemClaim.getAdditionalClaims(oAuthAuthzReqMessageContext,
                oAuth2AuthorizeRespDTO);
        Assert.assertEquals(claims.get(AT_HASH), hashAccessToken);
        Assert.assertEquals(claims.get(C_HASH), authorizationHashCode);
    }

    @DataProvider(name = "getAdditionalClaims")
    public Object[][] getAdditionalClaims() throws Exception {

        return new Object[][] {
                {AUTHORIZATION_CODE, ACCESS_TOKEN, getHashValue(AUTHORIZATION_CODE), getHashValue(ACCESS_TOKEN)},
                {EMPTY_VALUE, "accessToken", EMPTY_VALUE, getHashValue("accessToken")}
        };
    }

    @Test(dataProvider = "getAdditionalClaims")
    public void testGetAdditionalClaims(String authorizationCode, String accessToken,
                                        String authorizationHashCode, String hashAccessToken) throws Exception {

        oAuth2AccessTokenReqDTO.setAuthorizationCode(authorizationCode);
        oAuth2AccessTokenRespDTO.setAccessToken(accessToken);
        Map<String, Object> claims = openIDConnectSystemClaim.getAdditionalClaims(oAuthTokenReqMessageContext,
                oAuth2AccessTokenRespDTO);
        Assert.assertEquals(claims.get(AT_HASH), hashAccessToken);
        Assert.assertEquals(claims.get(C_HASH), authorizationHashCode);
    }

    @DataProvider(name = "getAtHashClaim")
    public Object[][] getAtHashClaim() throws Exception {

        return new Object[][] {
                {"id_token", EMPTY_VALUE, ACCESS_TOKEN, EMPTY_VALUE},
                {"code id_token", AUTHORIZATION_CODE, ACCESS_TOKEN, EMPTY_VALUE},
                {"code id_token token", AUTHORIZATION_CODE, ACCESS_TOKEN, getHashValue(ACCESS_TOKEN)},
        };
    }

    @Test(dataProvider = "getAtHashClaim")
    public void testSetAtHashClaim(String responseType, String authorizationCode,
                                       String accessToken, String hashAccessToken) throws Exception {

        oAuth2AuthorizeRespDTO.setAuthorizationCode(authorizationCode);
        oAuth2AuthorizeReqDTO.setResponseType(responseType);
        oAuth2AuthorizeRespDTO.setAccessToken(accessToken);
        Map<String, Object> claims = openIDConnectSystemClaim.getAdditionalClaims(oAuthAuthzReqMessageContext,
                oAuth2AuthorizeRespDTO);
        Assert.assertEquals(claims.get(AT_HASH), hashAccessToken);
    }

    @Test
    public void testStateHashClaim() throws Exception {

        String state = "testState";
        oAuth2AuthorizeReqDTO.setState(state);
        oAuth2AuthorizeReqDTO.setResponseType("code");
        Map<String, Object> claims = openIDConnectSystemClaim.getAdditionalClaims(oAuthAuthzReqMessageContext,
                oAuth2AuthorizeRespDTO);
        Assert.assertEquals(claims.get(OAuthConstants.OIDCClaims.S_HASH), getHashValue(state));
    }

    private String getHashValue(String value) throws Exception {

        String signatureAlgorithm = "SHA256withRSA";
        JWSAlgorithm algorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm);
        setPrivateField(openIDConnectSystemClaim, "signatureAlgorithm", algorithm);
        String hashValue = (String) invokePrivateMethod(openIDConnectSystemClaim, "getHashValue", value);
        return hashValue;
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

    private Object invokePrivateMethod(Object object, String methodName, Object... params) throws Exception {

        Class<?>[] paramTypes = new Class[params.length];
        for (int i = 0; i < params.length; i++) {
            paramTypes[i] = params[i].getClass();
        }
        Method method = object.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(object, params);
    }
}
