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

package org.wso2.carbon.identity.openidconnect.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectPersistenceFactory;

import java.util.List;
import java.util.Map;

/**
 * This handler is used to invoke RequestObjectPersistenceFactory to revoke code or token from request object reference
 * table when code or token is revoked from the original tables.
 */
public class RequestObjectHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(RequestObjectHandler.class);

    /**
     * Handles the event and invoke RequestObjectPersistenceFactory.
     *
     * @param event event
     * @throws IdentityEventException
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String eventName = event.getEventName();
        try {
            String tokenState = (String) eventProperties.get(OIDCConstants.Event.TOKEN_STATE);
            String sessionDataKey = (String) eventProperties.get(OIDCConstants.Event.SESSION_DATA_KEY);

            if (OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN.equals(eventName)) {
                if (isTokenRemoved(tokenState)) {
                    List<String> accessTokens = (List) eventProperties.get(OIDCConstants.Event.ACEESS_TOKENS);
                    for (String accessToken : accessTokens) {
                        RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReference
                                (accessToken, null);
                    }
                }
            } else if (OIDCConstants.Event.POST_REVOKE_CODE.equals(eventName)) {
                if (isTokenRemoved(tokenState)) {
                    List<AuthzCodeDO> authzcodes = (List<AuthzCodeDO>) eventProperties.get(OIDCConstants.Event.CODES);
                    for (AuthzCodeDO authzCodeDO : authzcodes) {
                        RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReference
                                (null, authzCodeDO.getAuthzCodeId());
                    }
                }
            } else if (OIDCConstants.Event.POST_REFRESH_TOKEN.equals(eventName)) {
                String oldAccessToken = (String) eventProperties.get(OIDCConstants.Event.OLD_ACCESS_TOKEN);
                String newAccessToken = (String) eventProperties.get(OIDCConstants.Event.NEW_ACCESS_TOKEN);
                RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().refreshRequestObjectReference
                        (oldAccessToken, newAccessToken);
            }
            if (OIDCConstants.Event.POST_ISSUE_CODE.equals(eventName)) {
                String codeId = (String) eventProperties.get(OIDCConstants.Event.CODE_ID);
                RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReference
                        (sessionDataKey, codeId, null);

            } else if (OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN.equals(eventName)) {
                String tokenId = (String) eventProperties.get(OIDCConstants.Event.TOKEN_ID);
                RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReference
                        (sessionDataKey, null, tokenId);
            }
        } catch (IdentityOAuth2Exception | IdentityOAuthAdminException e) {
            String errorMsg = "Error while handling event: " + eventName;
            log.info(errorMsg);
            throw new IdentityEventException(errorMsg, e.getMessage());
        }
    }

    private boolean isTokenRemoved(String tokenState) {

        return OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(tokenState) || OAuthConstants.TokenStates.
                TOKEN_STATE_REVOKED.equals(tokenState);
    }

    public String getName() {

        return OIDCConstants.Event.HANDLE_REQUEST_OBJECT;
    }
}
