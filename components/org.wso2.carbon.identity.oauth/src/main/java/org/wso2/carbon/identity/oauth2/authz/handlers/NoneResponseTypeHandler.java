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

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

/**
 * Handles requests with response_type=none as defined in the spec https://openid
 * .net/specs/oauth-v2-multiple-response-types-1_0.html#none.
 * When supplied as the response_type parameter in an OAuth 2.0 Authorization Request, Authorization Code, Access
 * Token, Access Token Type, or ID Token is not sent in the successful response. If a redirect_uri is supplied, the
 * User Agent is redirected there after granting or denying access. If the state parameter is present, it is added to
 * the response as well.
 */
public class NoneResponseTypeHandler extends AbstractResponseTypeHandler {

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        return initResponse(oauthAuthzMsgCtx);
    }
}
