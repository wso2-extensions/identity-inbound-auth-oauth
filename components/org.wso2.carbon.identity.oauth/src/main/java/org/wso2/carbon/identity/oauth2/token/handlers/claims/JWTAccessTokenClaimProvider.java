/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

/**
 * Adds new claims into JWT Access Tokens.
 */
public interface JWTAccessTokenClaimProvider {

    /**
     * Returns map of additional claims to be included in JWT Access Tokens issued in OAuth2 authorize flow.
     *
     * @param context
     * @return
     * @throws IdentityOAuth2Exception
     */
    Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context) throws IdentityOAuth2Exception;

    /**
     * Returns map of Additional claims to be included in JWT Access Tokens issued in the OAuth2 token flow.
     *
     * @param context
     * @return map of id token claims
     * @throws IdentityOAuth2Exception
     */
    Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context) throws IdentityOAuth2Exception;
}
