/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;

import java.util.HashMap;

/**
 * Utility class for publishing OAuth-related events.
 */
public class OAuthEventPublishingUtil {

    private static final Log log = LogFactory.getLog(OAuthEventPublishingUtil.class);
    private static final String APP_DAO = "OAuthAppDO";

    /**
     * Publishes an event when a token is issued.
     *
     * @param tokReqMsgCtx            The token request message context containing information about the token request.
     * @param oAuth2AccessTokenReqDTO The OAuth2 access token request DTO containing details about the access token
     *                                request.
     * @throws UserIdNotFoundException If the user ID cannot be found in the context.
     */
    public static void publishTokenIssueEvent(OAuthTokenReqMessageContext tokReqMsgCtx,
                                              OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO)
            throws UserIdNotFoundException {

        HashMap<String, Object> properties = new HashMap<>();

        OauthTokenIssuer tokenIssuer = null;
        try {
            tokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(oAuth2AccessTokenReqDTO.getClientId());
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while retrieving the OAuth token issuer for client ID: " +
                    oAuth2AccessTokenReqDTO.getClientId(), e);
        } catch (InvalidOAuthClientException e) {
            log.error("Invalid OAuth client with client ID: " + oAuth2AccessTokenReqDTO.getClientId(), e);
        }
        if (tokenIssuer != null) {
            properties.put(IdentityEventConstants.EventProperty.TOKEN_TYPE, tokenIssuer.getAccessTokenType());
        }

        if (tokReqMsgCtx != null) {

            if (tokReqMsgCtx.getAuthorizedUser() != null) {
                properties.put(IdentityEventConstants.EventProperty.USER_ID,
                        tokReqMsgCtx.getAuthorizedUser().getUserId());
                properties.put(IdentityEventConstants.EventProperty.USER_NAME,
                        tokReqMsgCtx.getAuthorizedUser().getUserName());
                properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN,
                        tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain());
            }

            properties.put(IdentityEventConstants.EventProperty.IAT, tokReqMsgCtx.getAccessTokenIssuedTime());
            properties.put(IdentityEventConstants.EventProperty.JTI, tokReqMsgCtx.getJWTID());
            properties.put(IdentityEventConstants.EventProperty.GRANT_TYPE, oAuth2AccessTokenReqDTO.getGrantType());

            if (tokReqMsgCtx.getProperty(APP_DAO) != null &&
                    tokReqMsgCtx.getProperty(APP_DAO) instanceof OAuthAppDO) {
                OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty(APP_DAO);
                properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID, oAuthAppDO.getId());
                properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, oAuthAppDO.getApplicationName());
                properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, oAuthAppDO.getOauthConsumerKey());
            }
        }

        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId());

        Event identityMgtEvent = new Event(IdentityEventConstants.Event.TOKEN_ISSUED, properties);

        try {
            OAuth2ServiceComponentHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            log.error("Error occurred publishing event " + IdentityEventConstants.Event.TOKEN_ISSUED, e);
        }
    }
}
