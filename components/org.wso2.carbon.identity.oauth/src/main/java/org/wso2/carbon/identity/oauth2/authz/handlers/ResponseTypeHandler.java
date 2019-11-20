/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

public interface ResponseTypeHandler {

    public void init()
            throws IdentityOAuth2Exception;

    public boolean validateAccessDelegation(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception;

    public boolean validateScope(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception;

    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception;

    /**
     * check whether client has authorization to get access token from provided grant type
     * @param tokReqMsgCtx
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean isAuthorizedClient(OAuthAuthzReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception;


    /**
     * Handles user consent denial at responseType level.
     *
     * @param oAuth2Parameters OAuth parameters.
     * @return OAuthErrorDTO Authorization Failure Data Transfer Object.
     * @throws IdentityOAuth2Exception
     */
    default OAuthErrorDTO handleUserConsentDenial(OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        return null;
    }

    /**
     * Handles authentication failures at responseType level.
     *
     * @param oAuth2Parameters OAuth parameters.
     * @return OAuthErrorDTO Authorization Failure Data Transfer Object.
     * @throws IdentityOAuth2Exception
     */
    default OAuthErrorDTO handleAuthenticationFailure(OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        return null;
    }
}
