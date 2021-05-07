/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.common.testng.WithRegistry;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@WithCarbonHome
@WithRegistry
@WithRealmService
public class OpenIDConnectSystemClaimImplTest extends PowerMockTestCase {

    private static final String AUTHORIZATION_CODE = "testAuthorizationCode";
    private static final String EMPTY_VALUE = null;
    private static final String ACCESS_TOKEN = TestConstants.ACCESS_TOKEN;
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
                {"code", AUTHORIZATION_CODE, ACCESS_TOKEN, getHashValue(AUTHORIZATION_CODE),
                        getHashValue(ACCESS_TOKEN)},
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
        Assert.assertEquals(claims.get("at_hash"), hashAccessToken);
        Assert.assertEquals(claims.get("c_hash"), authorizationHashCode);
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
        Assert.assertEquals(claims.get("at_hash"), hashAccessToken);
        Assert.assertEquals(claims.get("c_hash"), authorizationHashCode);
    }
    
    private String getHashValue(String value) throws IdentityOAuth2Exception {

        String signatureAlgorithm = "SHA256withRSA";
        String digAlg = OAuth2Util.mapDigestAlgorithm
                (OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm));
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(digAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception("Error creating the hash value. Invalid Digest Algorithm: " + digAlg);
        }

        md.update(value.getBytes(Charsets.UTF_8));
        byte[] digest = md.digest();
        int leftHalfBytes = 16;
        if ("SHA-384".equals(digAlg)) {
            leftHalfBytes = 24;
        } else if ("SHA-512".equals(digAlg)) {
            leftHalfBytes = 32;
        }
        byte[] leftmost = new byte[leftHalfBytes];
        System.arraycopy(digest, 0, leftmost, 0, leftHalfBytes);
        return new String(Base64.encodeBase64URLSafe(leftmost), Charsets.UTF_8);
    }
}
