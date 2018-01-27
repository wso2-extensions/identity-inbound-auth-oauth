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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

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
                handlePostRevokeToken(eventProperties, tokenState);
            } else if (OIDCConstants.Event.POST_REVOKE_CODE.equals(eventName)) {
                handlePostRevokeCode(eventProperties, tokenState);
            } else if (OIDCConstants.Event.POST_REVOKE_CODE_BY_ID.equals(eventName)) {
                revokeCodeById(eventProperties, tokenState);
            } else if (OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN_BY_ID.equals(eventName)) {
                postRevokeTokenById(eventProperties, tokenState);
            } else if (OIDCConstants.Event.POST_REFRESH_TOKEN.equals(eventName)) {
                postRefreshToken(eventProperties);
            } else if (OIDCConstants.Event.POST_ISSUE_CODE.equals(eventName)) {
                postIssueCode(eventProperties, sessionDataKey);
            } else if (OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN.equals(eventName)) {
                postIssueTOken(eventProperties, sessionDataKey);
            }
        } catch (IdentityOAuth2Exception | IdentityOAuthAdminException e) {
            String errorMsg = "Error while handling event: " + eventName;
            log.info(errorMsg);
            throw new IdentityEventException(errorMsg, e.getMessage());
        }
    }

    private void postIssueTOken(Map<String, Object> eventProperties, String sessionDataKey) throws
            IdentityOAuth2Exception {

        String tokenId = (String) eventProperties.get(OIDCConstants.Event.TOKEN_ID);
        OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReferencebyTokenId
                (sessionDataKey, tokenId);
    }

    private void postIssueCode(Map<String, Object> eventProperties, String sessionDataKey) throws
            IdentityOAuth2Exception {

        String codeId = (String) eventProperties.get(OIDCConstants.Event.CODE_ID);
        OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReferencebyCodeId
                (sessionDataKey, codeId);
    }

    private void postRefreshToken(Map<String, Object> eventProperties) throws IdentityOAuth2Exception {

        String oldAccessToken = (String) eventProperties.get(OIDCConstants.Event.OLD_ACCESS_TOKEN);
        String newAccessToken = (String) eventProperties.get(OIDCConstants.Event.NEW_ACCESS_TOKEN);
        OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().refreshRequestObjectReference
                (oldAccessToken, newAccessToken);
    }

    private void revokeCodeById(Map<String, Object> eventProperties, String codeState) throws IdentityOAuth2Exception,
            IdentityOAuthAdminException {

        String tokenId = (String) eventProperties.get(OIDCConstants.Event.TOKEN_ID);
        String codeId = (String) eventProperties.get(OIDCConstants.Event.CODE_ID);

        if (StringUtils.isNotEmpty(tokenId) && OAuthConstants.AuthorizationCodeState.INACTIVE.equals(codeState)) {
            //update the token id  of request object reference identified by code id
            OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReferenceCodeToToken
                    (codeId, tokenId);
        } else if (isCodeRemoved(codeState)) {
            //remove the request object reference upon removal of the code
            OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReferenceByCode(codeId);

        }
    }

    private void postRevokeTokenById(Map<String, Object> eventProperties, String tokenState) throws
            IdentityOAuth2Exception, IdentityOAuthAdminException {

        if (isCodeRemoved(tokenState)) {
            String tokenId = (String) eventProperties.get(OIDCConstants.Event.TOKEN_ID);
            OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReferenceByTokenId
                    (tokenId);
        }
    }

    private void handlePostRevokeCode(Map<String, Object> eventProperties, String codeState) throws
            IdentityOAuth2Exception, IdentityOAuthAdminException {

        boolean isCodeRemove = isCodeRemoved(codeState);
        List<AuthzCodeDO> authzcodes = (List<AuthzCodeDO>) eventProperties.get(OIDCConstants.Event.CODES);
        for (AuthzCodeDO authzCodeDO : authzcodes) {
            String codeId = authzCodeDO.getAuthzCodeId();
            String tokenId = authzCodeDO.getOauthTokenId();
            if (isCodeRemove) {
                OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReferenceByCode
                        (codeId);
            } else if (StringUtils.isNotEmpty(tokenId) && OAuthConstants.AuthorizationCodeState
                    .INACTIVE.equals(codeState)) {
                //update the token id  of request object reference identified by code id
                OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO()
                        .updateRequestObjectReferenceCodeToToken(codeId, tokenId);

            }
        }
    }

    private void handlePostRevokeToken(Map<String, Object> eventProperties, String tokenState) throws
            IdentityOAuth2Exception, IdentityOAuthAdminException {

        if (isTokenRemoved(tokenState)) {
            List<String> accessTokens = (List) eventProperties.get(OIDCConstants.Event.ACEESS_TOKENS);
            for (String accessToken : accessTokens) {
                OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReferenceByTokenId
                        (accessToken);
            }
        }
    }

    private boolean isTokenRemoved(String tokenState) {

        return OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(tokenState) || OAuthConstants.TokenStates.
                TOKEN_STATE_REVOKED.equals(tokenState);
    }

    private boolean isCodeRemoved(String codeState) {

        return OAuthConstants.AuthorizationCodeState.EXPIRED.equals(codeState) || OAuthConstants.AuthorizationCodeState.
                REVOKED.equals(codeState);
    }

    public String getName() {

        return OIDCConstants.Event.HANDLE_REQUEST_OBJECT;
    }
}