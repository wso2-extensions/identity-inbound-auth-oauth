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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import java.util.HashMap;
import java.util.List;

import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.NEW_ACCESS_TOKEN;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.OLD_ACCESS_TOKEN;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.TOKEN_STATE;

/**
 * Utility methods for OAuth token related functions.
 */
public class OAuth2TokenUtil {

    private static final Log log = LogFactory.getLog(OAuth2TokenUtil.class);

    /**
     * Uses to update access token details in the request object reference table.
     *
     * @param tokenId        token id
     * @param sessionDataKey session data key
     * @throws IdentityOAuth2Exception
     */
    public static void postIssueAccessToken(String tokenId, String sessionDataKey) throws
            IdentityOAuth2Exception {

        String eventName = OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(OIDCConstants.Event.TOKEN_ID, tokenId);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        Event requestObjectPersistanceEvent = new Event(eventName, properties);
        IdentityEventService identityEventService = OpenIDConnectServiceComponentHolder.getIdentityEventService();
        try {
            if (identityEventService != null) {
                identityEventService.handleEvent(requestObjectPersistanceEvent);
                if (log.isDebugEnabled()) {
                    log.debug("The event " + eventName + " triggered after the access token " + tokenId +
                            " is issued.");
                }
            }
        } catch (IdentityEventException e) {
            throw new IdentityOAuth2Exception("Error while invoking the request object persistance handler when issuing " +
                    "the access token id: " + tokenId);
        }
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokenId
     * @throws IdentityOAuth2Exception
     */
    public static void postUpdateAccessToken(String acessTokenId, String tokenState)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();

        if (StringUtils.isNotBlank(acessTokenId)) {
            eventName = OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN_BY_ID;
            properties.put(TOKEN_STATE, tokenState);
            properties.put(OIDCConstants.Event.TOKEN_ID, acessTokenId);
        }
        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokens
     * @throws IdentityOAuth2Exception
     */
    public static void postUpdateAccessTokens(List<String> acessTokens, String tokenState)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (CollectionUtils.isNotEmpty(acessTokens)) {
            eventName = OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN;
            properties.put(TOKEN_STATE, tokenState);
            properties.put(OIDCConstants.Event.ACEESS_TOKENS, acessTokens);
        }
        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokenId
     * @throws IdentityOAuth2Exception
     */
    public static void postRefreshAccessToken(String oldAcessTokenId, String acessTokenId, String tokenState)
            throws IdentityOAuth2Exception {

        String eventName;
        HashMap<String, Object> properties = new HashMap<>();
        if (StringUtils.isNotBlank(acessTokenId)) {
            properties.put(OLD_ACCESS_TOKEN, oldAcessTokenId);
            properties.put(NEW_ACCESS_TOKEN, acessTokenId);
        }
        eventName = OIDCConstants.Event.POST_REFRESH_TOKEN;
        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke codes from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param codeId     code id
     * @param tokenState
     * @param tokenId
     * @throws IdentityOAuth2Exception
     */
    public static void postRevokeCode(String codeId, String tokenState, String tokenId)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (StringUtils.isNotBlank(codeId)) {
            properties.put(OIDCConstants.Event.TOKEN_STATE, tokenState);
            properties.put(OIDCConstants.Event.TOKEN_ID, tokenId);
            properties.put(OIDCConstants.Event.CODE_ID, codeId);
            eventName = OIDCConstants.Event.POST_REVOKE_CODE_BY_ID;
        }

        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke codes from the request object related tables after token revocation
     * happens from access token related tables.
     * @param authzCodeDOs authzCodeDOs
     * @param tokenState state of the token
     * @throws IdentityOAuth2Exception
     */
    public static void postRevokeCodes(List<AuthzCodeDO> authzCodeDOs, String tokenState)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (CollectionUtils.isNotEmpty(authzCodeDOs)) {
            properties.put(OIDCConstants.Event.TOKEN_STATE, tokenState);
            eventName = OIDCConstants.Event.POST_REVOKE_CODE;
            properties.put(OIDCConstants.Event.CODES, authzCodeDOs);
        }

        triggerEvent(eventName, properties);
    }

    private static void triggerEvent(String eventName, HashMap<String, Object> properties)
            throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isNotBlank(eventName)) {
                Event requestObjectPersistanceEvent = new Event(eventName, properties);
                IdentityEventService identityEventService = OpenIDConnectServiceComponentHolder.getIdentityEventService();
                if (identityEventService != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("The event: " + eventName + " triggered.");
                    }

                    identityEventService.handleEvent(requestObjectPersistanceEvent);
                }
            }
        } catch (IdentityEventException e) {
            String message = "Error while triggering the event: " + eventName;
            log.error(message, e);
            throw new IdentityOAuth2Exception(message, e);
        }
    }

    /**
     * Uses to trigger an event once the code is issued.
     *
     * @param codeId         code id
     * @param sessionDataKey session data key
     * @throws IdentityOAuth2Exception
     */
    public static void postIssueCode(String codeId, String sessionDataKey) throws IdentityOAuth2Exception {

        String eventName = OIDCConstants.Event.POST_ISSUE_CODE;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(OIDCConstants.Event.CODE_ID, codeId);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        triggerEvent(eventName, properties);
    }
}

