/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

public interface OAuthClientAuthenticator extends IdentityHandler {

    /**
     * Authenticate OAuth2 Client.
     *
     * @param request                 Incoming HttpServletRequest.
     * @param bodyParams                 Body parameter content of the incoming HttpRequest
     * @param oAuthClientAuthnContext OAuth2 Client Authenticaion Context
     * @return Client authentication status. True if the client authentication is success. Else false.
     * @throws OAuthClientAuthnException
     */
    boolean authenticateClient(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException;

    /**
     * Returns whether the incoming reqeust can be handled by the particular authenticator.
     *
     * @param request                 Incoming HttpServletRequest.
     * @param bodyParams                 Content of the body parameters.
     * @param oAuthClientAuthnContext OAuth Client Authentication context.
     * @return Whether the OAuth client can be authenticated or not by this authenticator.
     */
    boolean canAuthenticate(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext);

    /**
     * Extracts the OAuth client id from the incoming request.
     *
     * @param request                 HttpServletRequest which is the incoming request.
     * @param bodyParams                 Body parameter content of the incoming request.
     * @param oAuthClientAuthnContext OAuth Client Authentication Context.
     * @return Client ID
     * @throws OAuthClientAuthnException
     */
    String getClientId(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException;
}
