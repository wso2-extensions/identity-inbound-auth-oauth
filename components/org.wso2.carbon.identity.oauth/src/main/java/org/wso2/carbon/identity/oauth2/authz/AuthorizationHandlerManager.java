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

package org.wso2.carbon.identity.oauth2.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.HashMap;
import java.util.Map;

import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.INVALID_SCOPE;
import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.UNAUTHORIZED_CLIENT;
import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE;

public class AuthorizationHandlerManager {

    public static final String OAUTH_APP_PROPERTY = "OAuthAppDO";
    private static Log log = LogFactory.getLog(AuthorizationHandlerManager.class);

    private static AuthorizationHandlerManager instance;

    private Map<String, ResponseTypeHandler> responseHandlers = new HashMap<>();


    private AuthorizationHandlerManager() throws IdentityOAuth2Exception {
        responseHandlers = OAuthServerConfiguration.getInstance().getSupportedResponseTypes();

        if (AppInfoCache.getInstance() != null) {
            if (log.isDebugEnabled() && AppInfoCache.getInstance().isEnabled()) {
                log.debug("Successfully enabled AppInfoCache under " + OAuthConstants.OAUTH_CACHE_MANAGER);
            }
        } else {
            log.error("Error while creating AppInfoCache");
        }
    }

    public static AuthorizationHandlerManager getInstance() throws IdentityOAuth2Exception {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthorizationHandlerManager.class) {
                if (instance == null) {
                    instance = new AuthorizationHandlerManager();
                }
            }
        }
        return instance;
    }

    public OAuth2AuthorizeRespDTO handleAuthorization(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, IdentityOAuthAdminException, InvalidOAuthClientException {

        OAuthAuthzReqMessageContext authzReqMsgCtx = getOAuthAuthzReqMessageContext(authzReqDTO);
        ResponseTypeHandler authzHandler = getResponseHandler(authzReqDTO);
        OAuth2AuthorizeRespDTO authorizeRespDTO = validateAuthzRequest(authzReqDTO, authzReqMsgCtx, authzHandler);
        if (isErrorResponseFound(authorizeRespDTO)) {
            if (log.isDebugEnabled()) {
                log.debug("Error response received for authorization request by user : " + authzReqDTO.getUser()  +
                        ", client : " + authzReqDTO.getConsumerKey() + ", scope : " +
                        OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
            }
            return authorizeRespDTO;
        }
        try {
	    // set the authorization request context to be used by downstream handlers. This is introduced as a fix for
	    // IDENTITY-4111
	    OAuth2Util.setAuthzRequestContext(authzReqMsgCtx);
	    authorizeRespDTO = authzHandler.issue(authzReqMsgCtx);
        } finally {
            // clears authorization request context
            OAuth2Util.clearAuthzRequestContext();
        }
        return authorizeRespDTO;
    }

    private ResponseTypeHandler getResponseHandler(OAuth2AuthorizeReqDTO authzReqDTO) {
        return responseHandlers.get(authzReqDTO.getResponseType());
    }

    private OAuth2AuthorizeRespDTO validateAuthzRequest(OAuth2AuthorizeReqDTO authzReqDTO,
                                                        OAuthAuthzReqMessageContext authzReqMsgCtx,
                                                        ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
        if (isInvalidResponseType(authzReqDTO, authorizeRespDTO)) {
            return authorizeRespDTO;
        }
        if (isInvalidClient(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }
        if (isInvalidAccessDelegation(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }
        validateScope(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler);
        return authorizeRespDTO;
    }

    private boolean validateScope(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO,
                                  OAuthAuthzReqMessageContext authzReqMsgCtx, ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        boolean scopeValidationStatus = authzHandler.validateScope(authzReqMsgCtx);
        if (!scopeValidationStatus) {
            handleErrorRequest(authorizeRespDTO, INVALID_SCOPE, "Invalid Scope!");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("Scope validation failed for user : " + authzReqDTO.getUser() + ", for the scope(s) : "
                        + OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
            }
            return false;
        } else if (approvedScopeNotSetByTheCallbackHandler(authzReqMsgCtx)) {
            // We are here because the call-back handler has approved the scope.
            // If call-back handler set the approved scope - then we respect that. If not we take
            // the approved scope as the provided scope.
            authzReqMsgCtx.setApprovedScope(authzReqMsgCtx.getAuthorizationReqDTO().getScopes());
        }
        if (log.isDebugEnabled()) {
            log.debug("Approved scope(s) : " + OAuth2Util.buildScopeString(authzReqMsgCtx.getApprovedScope()));
        }
        return true;
    }

    private boolean approvedScopeNotSetByTheCallbackHandler(OAuthAuthzReqMessageContext authzReqMsgCtx) {
        return authzReqMsgCtx.getApprovedScope() == null || authzReqMsgCtx.getApprovedScope().length == 0;
    }

    private boolean isInvalidAccessDelegation(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO,
                                              OAuthAuthzReqMessageContext authzReqMsgCtx,
                                              ResponseTypeHandler authzHandler) throws IdentityOAuth2Exception {
        boolean accessDelegationAuthzStatus = authzHandler.validateAccessDelegation(authzReqMsgCtx);
        if (!accessDelegationAuthzStatus) {
            handleErrorRequest(authorizeRespDTO, UNAUTHORIZED_CLIENT, "Authorization Failure!");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("User : " + authzReqDTO.getUser() +
                        " doesn't have necessary rights to grant access to the resource(s) : " +
                        OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
            }
            return true;
        }
        return false;
    }

    private boolean isInvalidClient(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO,
                                    OAuthAuthzReqMessageContext authzReqMsgCtx, ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        boolean isAuthorizedClient = authzHandler.isAuthorizedClient(authzReqMsgCtx);
        if (!isAuthorizedClient) {
            handleErrorRequest(authorizeRespDTO, UNAUTHORIZED_CLIENT,
                    "The authenticated client is not authorized to use this authorization grant type");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("Client validation failed for user : " + authzReqDTO.getUser() +
                        ", for client : " + authzReqDTO.getConsumerKey());
            }
            return true;
        }
        return false;
    }

    private OAuthAuthzReqMessageContext getOAuthAuthzReqMessageContext(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {
        OAuthAuthzReqMessageContext authorizeRequestMessageContext = new OAuthAuthzReqMessageContext(authzReqDTO);
        // loading the stored application data
        OAuthAppDO oAuthAppDO = getAppInformation(authzReqDTO);
        authorizeRequestMessageContext.addProperty(OAUTH_APP_PROPERTY, oAuthAppDO);

        // load the SP tenant domain from the OAuth App info
        authorizeRequestMessageContext.getAuthorizationReqDTO().setTenantDomain(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO));
        return authorizeRequestMessageContext;
    }

    private boolean isErrorResponseFound(OAuth2AuthorizeRespDTO authorizeRespDTO) {
        return authorizeRespDTO.getErrorMsg() != null;
    }

    private boolean isInvalidResponseType(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO) {
        if (!responseHandlers.containsKey(authzReqDTO.getResponseType())) {
            handleErrorRequest(authorizeRespDTO, UNSUPPORTED_RESPONSE_TYPE,
                    "Unsupported Response Type!");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("Unsupported Response Type : " + authzReqDTO.getResponseType() +
                        " provided for user : " + authzReqDTO.getUser() +
                        ", for client :" + authzReqDTO.getConsumerKey());
            }
            return true;
        }
        return false;
    }

    private OAuthAppDO getAppInformation(OAuth2AuthorizeReqDTO authzReqDTO) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {
        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(authzReqDTO.getConsumerKey());
        if (oAuthAppDO != null) {
            return oAuthAppDO;
        } else {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(authzReqDTO.getConsumerKey());
            AppInfoCache.getInstance().addToCache(authzReqDTO.getConsumerKey(), oAuthAppDO);
            return oAuthAppDO;
        }
    }

    private void handleErrorRequest(OAuth2AuthorizeRespDTO respDTO, String errorCode,
                                    String errorMsg) {
        respDTO.setErrorCode(errorCode);
        respDTO.setErrorMsg(errorMsg);
    }
}
