/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.token;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.rar.utils.AuthorizationDetailsBaseTest;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Test class for {@link AccessTokenResponseRARHandler}.
 */
public class AccessTokenResponseRARHandlerTest extends AuthorizationDetailsBaseTest {

    private AccessTokenResponseRARHandler uut;

    @BeforeClass
    public void setUp() {
        this.uut = new AccessTokenResponseRARHandler();
    }

    @Test
    public void shouldReturnAuthorizationDetails_ifRichAuthorizationRequest() throws IdentityOAuth2Exception {

        assertAuthorizationDetailsPresent(uut.getAdditionalTokenResponseAttributes(tokenReqMessageContext));
    }

    @Test
    public void shouldReturnEmpty_ifNotRichAuthorizationRequest() throws IdentityOAuth2Exception {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        assertAuthorizationDetailsMissing(uut.getAdditionalTokenResponseAttributes(messageContext));
    }
}
