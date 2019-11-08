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
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.SubErrorCodes.CONSENT_DENIED;

/**
 * This class is responsible for handling the authorize requests with ciba as response type.
 */
public class CibaResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CibaResponseTypeHandler.class);

    public CibaResponseTypeHandler() {

    }

    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

        // Obtaining key to update database tables.
        String cibaAuthCodeID = authorizationReqDTO.getNonce();

        // Assigning authenticated user for the request that to be persisted.
        String cibaAuthenticatedUser = authorizationReqDTO.getUser().getUserName();

        // Assigning the authentication status that to be persisted.
        String authenticationStatus = AuthenticationStatus.AUTHENTICATED.toString();

        try {

            // Update ciba Authentication Status.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistStatus(cibaAuthCodeID, authenticationStatus);

            // Update ciba Authenticated user.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistUser(cibaAuthCodeID, cibaAuthenticatedUser);

        } catch (CibaCoreException e) {
            try {
                throw OAuthProblemException.error(OAuth2ErrorCodes.SERVER_ERROR)
                        .description("OAuth System exception in issuing response for the authorize request" +
                                " for the authenticated_user : " + cibaAuthenticatedUser + "of the request with ID : " +
                                cibaAuthCodeID);

            } catch (OAuthProblemException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred in persisting user and authenticated user for the cibaAuthCodeDOKey : " +
                            cibaAuthCodeID);
                }
            }
        }

        // Building custom CallBack URL.
        String callbackURL = authorizationReqDTO.getCallbackUrl() + "?authenticationStatus=" + authenticationStatus;
        respDTO.setCallbackURI(callbackURL);
        return respDTO;
    }

    /**
     * This method handles user denial for authorization.
     *
     * @param oAuth2Parameters OAuth2parameters are captured by this.
     * @return OAuth2AuthorizeRespDTO Authorize Response DTO.
     */
    public OAuth2AuthorizeRespDTO handleUserConsentDenial(OAuth2Parameters oAuth2Parameters) {

        String cibaAuthCodeDOKey = oAuth2Parameters.getNonce();
        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();

        try {
            // Update authenticationStatus when user denied the consent.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistStatus(cibaAuthCodeDOKey,
                    AuthenticationStatus.DENIED.toString());
            respDTO.setErrorCode(CONSENT_DENIED);
            respDTO.setErrorMsg("User Denied the consent.");
            return respDTO;

        } catch (CibaCoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating the authentication_status for the ID : " + cibaAuthCodeDOKey +
                        "with " +
                        "responseType as (ciba). ");
            }
        }
        return null;
    }

    /**
     * This method handles failure in authentication process.
     *
     * @param oAuth2Parameters OAuth2parameters are captured by this.
     * @return OAuth2AuthorizeRespDTO Authorize Response DTO.
     */
    public OAuth2AuthorizeRespDTO handleAuthenticationFailed(OAuth2Parameters oAuth2Parameters) {

        String nonce = oAuth2Parameters.getNonce();
        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        try {
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                    .persistStatus(nonce, AuthenticationStatus.FAILED.toString());
            respDTO.setErrorCode(ErrorCodes.SubErrorCodes.AUTHENTICATION_FAILED);
            respDTO.setErrorMsg("Authentication failed.");
            return respDTO;
        } catch (CibaCoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating the authentication_status for the ID : " + nonce + "with " +
                        "responseType as (ciba). ");
            }
        }
        return null;
    }
}