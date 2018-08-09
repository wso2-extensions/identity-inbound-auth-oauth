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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.util.ResponseTypeHandlerUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;

/**
 * CodeResponseTypeHandler class generates an authorization code.
 */
public class CodeResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CodeResponseTypeHandler.class);

    /**
     * Issue an authorization code and return the OAuth2AuthorizeRespDTO.
     * First the respDTO must be initialized using initResponse method in abstract class.
     *
     * @param oauthAuthzMsgCtx
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        AuthzCodeDO authorizationCode = ResponseTypeHandlerUtil.generateAuthorizationCode(oauthAuthzMsgCtx, cacheEnabled);
        String sessionDataKey = oauthAuthzMsgCtx.getAuthorizationReqDTO().getSessionDataKey();

        if (log.isDebugEnabled()) {
            log.debug("Issued code: " + authorizationCode + " for the session data key: " + sessionDataKey);
        }
        // Trigger an event to update request_object_reference table.
        OAuth2TokenUtil.postIssueCode(authorizationCode.getAuthzCodeId(), sessionDataKey);
        return buildResponseDTO(oauthAuthzMsgCtx, authorizationCode);
    }

    private OAuth2AuthorizeRespDTO buildResponseDTO(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AuthzCodeDO authzCodeDO)
            throws IdentityOAuth2Exception {
        // Initializing the response.
        OAuth2AuthorizeRespDTO respDTO = initResponse(oauthAuthzMsgCtx);
        // Add authorization code details to the response.
        return ResponseTypeHandlerUtil.buildAuthorizationCodeResponseDTO(respDTO, authzCodeDO);
    }

}
