/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.message.types.ResponseType;

import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.util.ResponseTypeHandlerUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;

/**
 * HybridResponseTypeHandler class will handle the response when response_type parameter is equal to
 * code token
 * code id_token
 * code id_token token.
 */
public class HybridResponseTypeHandler extends AbstractResponseTypeHandler {

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String responseType = authorizationReqDTO.getResponseType();

        // Initializing the response.
        OAuth2AuthorizeRespDTO respDTO = initResponse(oauthAuthzMsgCtx);

        // Generating authorization code and generating response for authorization code flow.
        if (isAuthorizationCodeIssued(responseType)) {
            AuthzCodeDO authzCodeDO = ResponseTypeHandlerUtil.generateAuthorizationCode(oauthAuthzMsgCtx, cacheEnabled);
            String sessionDataKey = oauthAuthzMsgCtx.getAuthorizationReqDTO().getSessionDataKey();
            // Trigger an event to update request_object_reference table.
            OAuth2TokenUtil.postIssueCode(authzCodeDO.getAuthzCodeId(), sessionDataKey);
            ResponseTypeHandlerUtil.buildAuthorizationCodeResponseDTO(respDTO, authzCodeDO);
        }

        // Generating access token and generating response for access token flow.
        if (isAccessTokenIssued(responseType)) {
            AccessTokenDO accessTokenDO = ResponseTypeHandlerUtil.generateAccessToken(oauthAuthzMsgCtx, cacheEnabled);
            // Starting to trigger post listeners.
            ResponseTypeHandlerUtil.triggerPostListeners(oauthAuthzMsgCtx, accessTokenDO, respDTO);
            ResponseTypeHandlerUtil.buildAccessTokenResponseDTO(respDTO, accessTokenDO);
        }

        // Generating id_token and generating response for id_token flow.
        if (isIDTokenIssued(responseType)) {
            AccessTokenDO accessTokenDO = ResponseTypeHandlerUtil.generateAccessToken(oauthAuthzMsgCtx, cacheEnabled);
            // Starting to trigger post listeners.
            ResponseTypeHandlerUtil.triggerPostListeners(oauthAuthzMsgCtx, accessTokenDO, respDTO);
            ResponseTypeHandlerUtil.buildIDTokenResponseDTO(respDTO, accessTokenDO, oauthAuthzMsgCtx);
        }

        return respDTO;
    }

    private boolean isAuthorizationCodeIssued(String responseType) {
        return StringUtils.contains(responseType, ResponseType.CODE.toString());
    }

    private boolean isAccessTokenIssued(String responseType) {
        return StringUtils.contains(responseType, ResponseType.TOKEN.toString()) &&
                !responseType.equalsIgnoreCase(OAuthConstants.CODE_IDTOKEN);
    }

    private boolean isIDTokenIssued(String responseType) {
        return StringUtils.contains(responseType, OAuthConstants.ID_TOKEN);
    }

}

