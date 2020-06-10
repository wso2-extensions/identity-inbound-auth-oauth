/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

/**
 * Unit test covering NoneResponseTypeHandler class.
 */
public class NoneResponseTypeHandlerTest {

    @DataProvider(name = "CommonDataProvider")
    public Object[][] commonDataProvider() {

        return new Object[][]{
                {"https://localhost:8000/callback1"},
                {"https://localhost:8000/callback2"}
        };
    }

    @Test(dataProvider = "CommonDataProvider")
    public void testIssue(String callBackUri) throws Exception {

        NoneResponseTypeHandler noneResponseTypeHandler = new NoneResponseTypeHandler();

        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        authorizationReqDTO.setCallbackUrl(callBackUri);
        authorizationReqDTO.setConsumerKey("SDSDSDS23131231");
        authorizationReqDTO.setResponseType(OAuthConstants.NONE);

        OAuthAuthzReqMessageContext messageContext = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        messageContext.setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});

        OAuth2AuthorizeRespDTO auth2AuthorizeReqDTO = noneResponseTypeHandler.issue(messageContext);
        // In the "response_type = none", none of the code, id token or the access token is returned. The user-agent
        // is redirected to the given call back uri.
        Assert.assertNull(auth2AuthorizeReqDTO.getAccessToken());
        Assert.assertNull(auth2AuthorizeReqDTO.getAuthorizationCode());
        Assert.assertNull(auth2AuthorizeReqDTO.getIdToken());
        Assert.assertEquals(auth2AuthorizeReqDTO.getCallbackURI(), callBackUri);
    }
}
