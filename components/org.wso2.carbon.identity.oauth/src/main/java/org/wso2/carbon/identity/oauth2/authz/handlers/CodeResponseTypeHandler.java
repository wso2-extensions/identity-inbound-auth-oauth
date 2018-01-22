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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.util.ResponseTypeHandlerUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;


/**
 * CodeResponseTypeHandler class generates an authorization code.
 */
public class CodeResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CodeResponseTypeHandler.class);

    /**
     * Issue an authorization code and return the OAuth2AuthorizeRespDTO.
     * First the respDTO must be initialized using initResponse method in abstract class.
     * @param oauthAuthzMsgCtx
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {
        AuthzCodeDO authorizationCode = ResponseTypeHandlerUtil.generateAuthorizationCode(oauthAuthzMsgCtx, cacheEnabled
                , oauthIssuerImpl);
        //Trigger an event to update request_object_reference table.
        postIssueCode(authorizationCode.getAuthzCodeId(), oauthAuthzMsgCtx.getAuthorizationReqDTO().getSessionDataKey());
        return buildResponseDTO(oauthAuthzMsgCtx, authorizationCode);
    }

    private OAuth2AuthorizeRespDTO buildResponseDTO(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AuthzCodeDO authzCodeDO)
            throws IdentityOAuth2Exception {
        // Initializing the response.
        OAuth2AuthorizeRespDTO respDTO = initResponse(oauthAuthzMsgCtx);
        // Add authorization code details to the response.
        return ResponseTypeHandlerUtil.buildAuthorizationCodeResponseDTO(respDTO, authzCodeDO);
    }

    private void postIssueCode(String codeId, String sessionDataKey) throws IdentityOAuth2Exception {

        String eventName = OIDCConstants.Event.POST_ISSUE_CODE;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(OIDCConstants.Event.CODE_ID, codeId);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        Event requestObjectPersistanceEvent = new Event(eventName, properties);
        try {
            if (OpenIDConnectServiceComponentHolder.getInstance().getIdentityEventService() != null) {
                OpenIDConnectServiceComponentHolder.getInstance().getIdentityEventService().handleEvent
                        (requestObjectPersistanceEvent);
                if (log.isDebugEnabled()) {
                    log.debug("The event " + eventName + " triggered after the code is issued.");
                }
            }
        } catch (IdentityEventException e) {
            throw new IdentityOAuth2Exception("Error while invoking the request object persistance handler.");
        }
    }
}
