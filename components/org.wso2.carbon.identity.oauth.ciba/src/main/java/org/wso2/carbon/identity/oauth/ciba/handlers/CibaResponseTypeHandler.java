/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

/**
 * Handles authorize requests with CibaAuthCode as response type.
 */
public class CibaResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CibaResponseTypeHandler.class);

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        try {
            // Assigning authenticated user for the request that to be persisted.
            AuthenticatedUser cibaAuthenticatedUser = authorizationReqDTO.getUser();

            // Assigning the authentication status that to be persisted.
            Enum authenticationStatus = AuthReqStatus.AUTHENTICATED;

            String authCodeKey =
                    CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authorizationReqDTO.getNonce());

            // Update successful authentication.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                    .persistAuthenticationSuccess(authCodeKey, cibaAuthenticatedUser);

            // Building custom CallBack URL.
            String callbackURL = authorizationReqDTO.getCallbackUrl() + "?authenticationStatus=" + authenticationStatus;
            respDTO.setCallbackURI(callbackURL);
            return respDTO;
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception("Error occurred in persisting authenticated user and authentication " +
                    "status for the request made by client: " + authorizationReqDTO.getConsumerKey(), e);
        }
    }

    @Override
    public OAuthErrorDTO handleUserConsentDenial(OAuth2Parameters oAuth2Parameters) {

        OAuthErrorDTO oAuthErrorDTO = new OAuthErrorDTO();
        String authReqID = oAuth2Parameters.getNonce();
        String authCodeKey = null;
        try {
            authCodeKey = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authReqID);

            // Update authenticationStatus when user denied the consent.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(authCodeKey, AuthReqStatus.CONSENT_DENIED);

            oAuthErrorDTO.setErrorDescription("User denied the consent.");
            return oAuthErrorDTO;
        } catch (CibaCoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating the authentication_status for the auth_req_id : " + authReqID +
                        "with responseType as (ciba). ");
            }
        }
        return null;
    }

    @Override
    public OAuthErrorDTO handleAuthenticationFailure(OAuth2Parameters oAuth2Parameters) {

        OAuthErrorDTO oAuthErrorDTO = new OAuthErrorDTO();
        String authReqID = oAuth2Parameters.getNonce();
        String authCodeKey = null;
        try {
            authCodeKey = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authReqID);
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(authCodeKey, AuthReqStatus.FAILED);
            oAuthErrorDTO.setErrorDescription("Authentication failed.");
            return oAuthErrorDTO;
        } catch (CibaCoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating the authentication_status for the ID : " + authReqID +
                        "with responseType as (ciba). ");
            }
        }
        return null;
    }
}
