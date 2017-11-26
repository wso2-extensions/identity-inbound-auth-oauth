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
package org.wso2.carbon.identity.oauth2.tokenBinding;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.utils.xml.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

/**
 * This class tests the TokenBindingHandler class.
 */
@PrepareForTest({OAuth2Util.class,
        OAuthServerConfiguration.class,
        TokenBindingHandler.class
})
public class TokenBindingHandlerTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    private OAuthAppDO authAppDO;

    @Mock
    private OAuthAppDAO authAppDAO;


    public String delimiter = "&#%";

    @BeforeMethod
    public void setUp() throws Exception {
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(authAppDO.isTbMandatory()).thenReturn(false);
        whenNew(OAuthAppDO.class).withNoArguments().thenReturn(authAppDO);
        when(authAppDAO.getAppInformation(anyString())).thenReturn(authAppDO);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(authAppDAO);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(authAppDO);
    }

    /**
     * DataProvider: PKCECodeChallenge, CodeVerifier, OAuthorizationCode,ExpectedValue
     */
    @DataProvider(name = "provideAuthorizationCode")
    public Object[][] createAuthorizationCode() {
        String PKCECodeChallenge = OAuthConstants.OAUTH_PKCE_REFERRED_TB_CHALLENGE;
        String codeVerifier1 = "Test";
        String codeVerifier2 = "ErrorTest";
        String oauthorizationCode = bindToken("Test", "test");

        return new Object[][]{
                {PKCECodeChallenge, null, oauthorizationCode, false},
                {PKCECodeChallenge, codeVerifier1, oauthorizationCode, true},
                {PKCECodeChallenge, codeVerifier2, oauthorizationCode, false},
        };
    }

    @Test(dataProvider = "provideAuthorizationCode")
    public void testValidateAuthorizationCode(String codeChallenge, String codeVerifier, String oauthCode, boolean
            expectedValue)
            throws
            Exception {
        TokenBindingHandler tokenBindingHandler = new TokenBindingHandler();
        boolean actualValue = tokenBindingHandler.validateAuthorizationCode(codeChallenge, codeVerifier, oauthCode);
        assertEquals(actualValue, expectedValue);
    }

    /**
     * DataProvider: RefreshToken, ExpectedHashValue
     */
    @DataProvider(name = "provideAccessToken")
    public Object[][] createAccessToken() {
        String refreshToken0Token0 = "1234-56";
        String refreshToken1 = bindToken("Test", "test");
        String refreshToken2 = bindToken("Test1", "test");
        String refreshToken3 = bindToken("Test12", "test");
        String refreshToken4 = new String(Base64.encodeBase64((refreshToken1 + ":" + "assertion").getBytes(Charsets.UTF_8)));

        String hash1 = hashOfString("Test");
        String hash2 = hashOfString("Test1");
        String hash3 = hashOfString("Test12");

        return new Object[][]{
                {refreshToken0Token0, null},
                {refreshToken1, hash1},
                {refreshToken2, hash2},
                {refreshToken3, hash3},
                {refreshToken4, hash1},
        };
    }

    @Test(dataProvider = "provideAccessToken")
    public void testValidateAccessToken(String refreshToken, String expectedValue) throws Exception {
        TokenBindingHandler tokenBindingHandler = new TokenBindingHandler();
        AccessTokenDO refreshTokenDO = new AccessTokenDO();
        refreshTokenDO.setAccessToken(refreshToken);
        String actualValue = tokenBindingHandler.validateAccessToken(refreshTokenDO);
        assertEquals(actualValue, expectedValue);
    }

    @DataProvider(name = "provideTokenBindingContext")
    public Object[][] createTokenBindingContext() {
        String refreshToken1 = bindToken("Test", "test");

        HttpRequestHeader httpRequestHeader = new HttpRequestHeader(OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME,
                "Test");
        HttpRequestHeader[] httpRequestHeaders = new HttpRequestHeader[1];
        httpRequestHeaders[0] = httpRequestHeader;

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setHttpRequestHeaders(httpRequestHeaders);
        oAuth2AccessTokenReqDTO.setRefreshToken(refreshToken1);
        oAuth2AccessTokenReqDTO.setClientId("testID");

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);


        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
        oAuth2AuthorizeReqDTO.setHttpRequestHeaders(httpRequestHeaders);

        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = new OAuthAuthzReqMessageContext(oAuth2AuthorizeReqDTO);

        String normalToken = "NormalToken";

        TokenBindingContext tokenBindingContext1 = new TokenBindingContext();
        tokenBindingContext1.setTokenBindingType(OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        tokenBindingContext1.setTokReqMsgCtx(tokReqMsgCtx);
        tokenBindingContext1.setNormalToken(normalToken);

        TokenBindingContext tokenBindingContext2 = new TokenBindingContext();
        tokenBindingContext2.setTokenBindingType(OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        tokenBindingContext2.setOauthAuthzMsgCtx(oAuthAuthzReqMessageContext);
        tokenBindingContext2.setNormalToken(normalToken);

        return new Object[][]{
                {tokenBindingContext1},
                {tokenBindingContext2},
        };
    }

    @Test(dataProvider = "provideTokenBindingContext")
    public void testDoTokenBinding(Object tokenBindingContext) throws Exception {
        TokenBindingHandler tokenBindingHandler = new TokenBindingHandler();
        tokenBindingHandler.settBSupportEnabled(true);
        tokenBindingHandler.doTokenBinding((TokenBindingContext) tokenBindingContext);
    }

    /**
     * DataProvider: OAuthTokenReqMessageContext, UsernameAssertionEnabled, ExpectedValue
     */
    @DataProvider(name = "provideRefreshToken")
    public Object[][] createRefreshToken() {
        String refreshToken1 = bindToken("Test", "test");
        String refreshToken2 = bindToken("Test1", "test");
        String refreshToken3 = new String(Base64.encodeBase64((refreshToken1 + ":" + "assertion").getBytes(Charsets.UTF_8)));

        HttpRequestHeader httpRequestHeader = new HttpRequestHeader(OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME,
                "Test");
        HttpRequestHeader[] httpRequestHeaders = new HttpRequestHeader[1];
        httpRequestHeaders[0] = httpRequestHeader;

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setHttpRequestHeaders(httpRequestHeaders);
        oAuth2AccessTokenReqDTO.setRefreshToken(refreshToken1);
        oAuth2AccessTokenReqDTO.setClientId("testID");

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO1 = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO1.setHttpRequestHeaders(httpRequestHeaders);
        oAuth2AccessTokenReqDTO1.setRefreshToken(refreshToken2);
        oAuth2AccessTokenReqDTO1.setClientId("testID");

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO2 = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO2.setHttpRequestHeaders(httpRequestHeaders);
        oAuth2AccessTokenReqDTO2.setRefreshToken(refreshToken3);
        oAuth2AccessTokenReqDTO2.setClientId("testID");

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        OAuthTokenReqMessageContext tokReqMsgCtx1 = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO1);
        OAuthTokenReqMessageContext tokReqMsgCtx2 = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO2);

        return new Object[][]{
                {tokReqMsgCtx, false, true},
                {tokReqMsgCtx1, false, false},
                {tokReqMsgCtx2, true, true},
        };
    }

    @Test(dataProvider = "provideRefreshToken")
    public void testValidateRefreshToken(Object oAuthTokenReqMessageContext,
                                         boolean usernameAssertionEnabled, boolean expectedValue) throws Exception {
        if (usernameAssertionEnabled) {
            when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(true);
        } else {
            when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(false);
        }
        TokenBindingHandler tokenBindingHandler = new TokenBindingHandler();
        tokenBindingHandler.settBSupportEnabled(true);
        boolean actualValue = tokenBindingHandler.validateRefreshToken((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext);

        assertEquals(actualValue, expectedValue);
    }

    /**
     * DataProvider: HTTPHeaders, TokenBindingType, ExpectedValue
     */
    @DataProvider(name = "provideHTTPHeaders")
    public Object[][] createHTTPHeaders() {
        HttpRequestHeader httpRequestHeader = new HttpRequestHeader(OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME,
                "Test");
        HttpRequestHeader[] httpRequestHeaders = new HttpRequestHeader[1];
        httpRequestHeaders[0] = httpRequestHeader;
        HttpRequestHeader httpRequestHeader1 = new HttpRequestHeader(OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME,
                "");
        HttpRequestHeader[] httpRequestHeaders1 = new HttpRequestHeader[1];
        httpRequestHeaders1[0] = httpRequestHeader1;

        return new Object[][]{
                {null, null, null},
                {httpRequestHeaders, OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME, "Test"},
                {httpRequestHeaders, "testHeader", null},
                {httpRequestHeaders1, OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME, ""},
        };
    }

    @Test(dataProvider = "provideHTTPHeaders")
    public void testCheckTokenBindingHeader(Object httpRequestHeaders, String headerName, String expectedValue) throws
            Exception {

        TokenBindingHandler tokenBindingHandler = new TokenBindingHandler();
        String actualValue = tokenBindingHandler.checkTokenBindingHeader((HttpRequestHeader[]) httpRequestHeaders,
                headerName);
        assertEquals(actualValue, expectedValue);
    }

    private String hashOfString(String tokenBindingID) {
        String hashValue = "";
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(tokenBindingID.getBytes(StandardCharsets.US_ASCII));
            //Trim the base64 string to remove trailing CR LF characters.
            hashValue = new String(Base64.encodeBase64URLSafe(hash),
                    StandardCharsets.UTF_8).trim();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return hashValue;
    }

    private String bindToken(String tokenBindingID, String token) {
        if (!StringUtils.isEmpty(tokenBindingID)) {
            String newToken = hashOfString(tokenBindingID) + delimiter + token;
            return new String(Base64.encodeBase64(newToken.getBytes(Charsets.UTF_8)));
        }
        return token;
    }

}
