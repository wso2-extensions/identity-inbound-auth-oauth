/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.dto;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class OAuth2TokenValidationResponseDTOTest {

    @Test
    public void testAuthorizationContextTokenTwoArgConstructor() {

        OAuth2TokenValidationResponseDTO responseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken token =
                responseDTO.new AuthorizationContextToken("Bearer", "test-token-string");

        assertEquals(token.getTokenType(), "Bearer");
        assertEquals(token.getTokenString(), "test-token-string");
        assertNull(token.getAccessTokenDO());
    }

    @Test
    public void testAuthorizationContextTokenThreeArgConstructor() {

        OAuth2TokenValidationResponseDTO responseDTO = new OAuth2TokenValidationResponseDTO();
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setTokenId("test-token-id");

        OAuth2TokenValidationResponseDTO.AuthorizationContextToken token =
                responseDTO.new AuthorizationContextToken("Bearer", "test-token-string", accessTokenDO);

        assertEquals(token.getTokenType(), "Bearer");
        assertEquals(token.getTokenString(), "test-token-string");
        assertNotNull(token.getAccessTokenDO());
        assertEquals(token.getAccessTokenDO().getTokenId(), "test-token-id");
    }

    @Test
    public void testAuthorizationContextTokenWithNullAccessTokenDO() {

        OAuth2TokenValidationResponseDTO responseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken token =
                responseDTO.new AuthorizationContextToken("Bearer", "test-token-string", null);

        assertEquals(token.getTokenType(), "Bearer");
        assertEquals(token.getTokenString(), "test-token-string");
        assertNull(token.getAccessTokenDO());
    }
}
