/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth2.authz;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import static org.testng.Assert.assertEquals;
import java.lang.String;

public class OAuthAuthzReqMessageContextTest {
    OAuth2AuthorizeReqDTO authorizationReqDTON = new OAuth2AuthorizeReqDTO();

    private OAuthAuthzReqMessageContext oauthAuthzReqMessageContext;
    private OAuth2AuthorizeReqDTO authorizationReqDTO;

    @BeforeTest
    public void setUp() {
        OAuth2AuthorizeReqDTO authorizationReqDTON = new OAuth2AuthorizeReqDTO();
        oauthAuthzReqMessageContext = new OAuthAuthzReqMessageContext(authorizationReqDTON);
        this.authorizationReqDTO = authorizationReqDTON;
    }

    @Test
    public void testSetAuthorizationReqDTO() throws Exception {
        OAuth2AuthorizeReqDTO authorizationReqDTON = new OAuth2AuthorizeReqDTO();
        authorizationReqDTON.setEssentialClaims("https://www.wso2.org/name");
        assertEquals(authorizationReqDTON.getEssentialClaims(),
                "https://www.wso2.org/name" , "Valid claim value.");

        authorizationReqDTON.setConsumerKey("0289");
        assertEquals(authorizationReqDTON.getConsumerKey(),
                "0289" , "Valid consumer key.");
    }

    @Test
    public void testGetApprovedScope() throws Exception {
        String[] approvedScope = {"scope1", "scope2"};

        oauthAuthzReqMessageContext.setApprovedScope(approvedScope);
        assertEquals(oauthAuthzReqMessageContext.getApprovedScope(),
                approvedScope , "Valid Scope.");
    }

    @Test
    public void testSetApprovedScope() throws Exception {
       String[] approvedScope = {"scope1", "scope2"};

        oauthAuthzReqMessageContext.setApprovedScope(approvedScope);
        assertEquals(oauthAuthzReqMessageContext.getApprovedScope(),
                approvedScope , "Valid Scope.");
    }

    @Test
    public void testGetValidityPeriod() throws Exception {
        oauthAuthzReqMessageContext.setValidityPeriod(120);
        assertEquals(oauthAuthzReqMessageContext.getValidityPeriod(),
                120, "Valid validity period.");
    }

    @Test
    public void testSetValidityPeriod() throws Exception {
        oauthAuthzReqMessageContext.setValidityPeriod(120);
        assertEquals(oauthAuthzReqMessageContext.getValidityPeriod(),
                120, "Valid validity period.");
    }

    @Test
    public void testAddProperty() throws Exception {
        oauthAuthzReqMessageContext.addProperty(authorizationReqDTON,2);
        assertEquals(oauthAuthzReqMessageContext.getProperty(authorizationReqDTON),
                2 , "Valid property value.");
    }

    @Test
    public void testGetProperty() throws Exception {
        oauthAuthzReqMessageContext.addProperty(authorizationReqDTON,2);
        assertEquals(oauthAuthzReqMessageContext.getProperty(authorizationReqDTON),
                2 , "Valid property value.");
    }

    @Test
    public void testSetRefreshTokenvalidityPeriod() throws Exception {
        oauthAuthzReqMessageContext.setRefreshTokenvalidityPeriod(100);
        assertEquals(oauthAuthzReqMessageContext.getRefreshTokenvalidityPeriod(),
                100 , "Valid refresh token validity period.");
    }

    @Test
    public void testGetAccessTokenIssuedTime() throws Exception {
        oauthAuthzReqMessageContext.setAccessTokenIssuedTime(10);
        assertEquals(oauthAuthzReqMessageContext.getAccessTokenIssuedTime(),
                10 , "Valid access token issued time.");
    }

    @Test
    public void testSetAccessTokenIssuedTime() throws Exception {
        oauthAuthzReqMessageContext.setAccessTokenIssuedTime(10);
        assertEquals(oauthAuthzReqMessageContext.getAccessTokenIssuedTime(),
                10 , "Valid access token issued time.");
    }

    @Test
    public void testGetRefreshTokenIssuedTime() throws Exception {
        oauthAuthzReqMessageContext.setRefreshTokenIssuedTime(10);
        assertEquals(oauthAuthzReqMessageContext.getRefreshTokenIssuedTime(),
                10 , "Valid refresh token issued time.");
    }

    @Test
    public void testSetRefreshTokenIssuedTime() throws Exception {
        oauthAuthzReqMessageContext.setRefreshTokenIssuedTime(10);
        assertEquals(oauthAuthzReqMessageContext.getRefreshTokenIssuedTime(),
                10 , "Valid refresh token issued time.");
    }

    @Test
    public void testGetCodeIssuedTime() throws Exception {
        oauthAuthzReqMessageContext.setCodeIssuedTime(10);
        assertEquals(oauthAuthzReqMessageContext.getCodeIssuedTime(),
                10 , "Valid code issued time.");
    }

    @Test
    public void testSetCodeIssuedTime() throws Exception {
        oauthAuthzReqMessageContext.setCodeIssuedTime(10);
        assertEquals(oauthAuthzReqMessageContext.getCodeIssuedTime(),
                10 , "Valid code issued time.");
    }
}
