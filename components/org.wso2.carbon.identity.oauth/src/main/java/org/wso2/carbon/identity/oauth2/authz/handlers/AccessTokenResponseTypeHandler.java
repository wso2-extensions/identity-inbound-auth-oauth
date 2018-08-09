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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.util.ResponseTypeHandlerUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Date;
import java.util.UUID;

/**
 * AccessTokenResponseTypeHandler class generates an access token.
 */
public class AccessTokenResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(AccessTokenResponseTypeHandler.class);

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {
        // Starting to trigger pre listeners.
        ResponseTypeHandlerUtil.triggerPreListeners(oauthAuthzMsgCtx);
        // Generating access token.
        AccessTokenDO accessTokenDO = ResponseTypeHandlerUtil.generateAccessToken(oauthAuthzMsgCtx, cacheEnabled);
        // Generating response for access token flow.
        OAuth2AuthorizeRespDTO respDTO = buildResponseDTO(oauthAuthzMsgCtx, accessTokenDO);
        // Starting to trigger post listeners.
        ResponseTypeHandlerUtil.triggerPostListeners(oauthAuthzMsgCtx, accessTokenDO, respDTO);
        return  respDTO;
    }

    /**
     * This method is used to set relevant values in to respDTO object when an access token is issued.
     * When an access token is issued we have to set access token, validity period and token type.
     * @param respDTO
     * @param accessTokenDO
     * @return OAuth2AuthorizeRespDTO object with access token details.
     */
    private OAuth2AuthorizeRespDTO buildResponseDTO(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {
        // Initializing the response.
        OAuth2AuthorizeRespDTO respDTO = initResponse(oauthAuthzMsgCtx);
        // Add access token details to the response.
        return ResponseTypeHandlerUtil.buildAccessTokenResponseDTO(respDTO, accessTokenDO);

    }

}


