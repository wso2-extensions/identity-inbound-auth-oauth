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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes;

public abstract class AbstractResponseTypeHandler implements ResponseTypeHandler {

    private static Log log = LogFactory.getLog(AbstractResponseTypeHandler.class);

    public static final String IMPLICIT = "implicit";
    protected OauthTokenIssuer oauthIssuerImpl;
    protected TokenMgtDAO tokenMgtDAO;
    protected boolean cacheEnabled;
    protected OAuthCache oauthCache;
    private OAuthCallbackManager callbackManager;

    @Override
    public void init() throws IdentityOAuth2Exception {
        callbackManager = new OAuthCallbackManager();
        oauthIssuerImpl = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();
        tokenMgtDAO = new TokenMgtDAO();
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            cacheEnabled = true;
            oauthCache = OAuthCache.getInstance();
        }
    }

    @Override
    public boolean validateAccessDelegation(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String responseType = authzReqDTO.getResponseType();

        OAuthAppDO oAuthAppDO = (OAuthAppDO)oauthAuthzMsgCtx.getProperty("OAuthAppDO");
        // If the application has defined a limited set of grant types, then check the grant
        if (oAuthAppDO.getGrantTypes() != null) {
            if (ResponseType.CODE.toString().equals(responseType)) {
                //Do not change this log format as these logs use by external applications
                if (!oAuthAppDO.getGrantTypes().contains("authorization_code")) {
                    log.debug("Unsupported Response Type : " + responseType +
                            " for client id : " + authzReqDTO.getConsumerKey());
                    handleErrorRequest(oauthAuthzMsgCtx, OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE,
                            "Unsupported Response Type!");
                    return false;
                }
            } else if (StringUtils.contains(responseType, ResponseType.TOKEN.toString()) &&
                    !oAuthAppDO.getGrantTypes().contains(IMPLICIT)) {
                //Do not change this log format as these logs use by external applications
                log.debug("Unsupported Response Type : " + responseType + " for client id : " + authzReqDTO
                        .getConsumerKey());
                handleErrorRequest(oauthAuthzMsgCtx, OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE,
                        "Unsupported Response Type!");
                return false;
            }
        }

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        OAuthCallback authzCallback = new OAuthCallback(authorizationReqDTO.getUser(),
                authorizationReqDTO.getConsumerKey(), OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_AUTHZ);
        authzCallback.setRequestedScope(authorizationReqDTO.getScopes());
        authzCallback.setResponseType(authorizationReqDTO.getResponseType());
        callbackManager.handleCallback(authzCallback);

        oauthAuthzMsgCtx.setValidityPeriod(authzCallback.getValidityPeriod());
        return authzCallback.isAuthorized();
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        OAuthCallback scopeValidationCallback = new OAuthCallback(authorizationReqDTO.getUser(),
                authorizationReqDTO.getConsumerKey(), OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_AUTHZ);
        scopeValidationCallback.setRequestedScope(authorizationReqDTO.getScopes());
        scopeValidationCallback.setResponseType(authorizationReqDTO.getResponseType());

        callbackManager.handleCallback(scopeValidationCallback);

        oauthAuthzMsgCtx.setValidityPeriod(scopeValidationCallback.getValidityPeriod());
        oauthAuthzMsgCtx.setApprovedScope(scopeValidationCallback.getApprovedScope());
        return scopeValidationCallback.isValidScope();
    }

    private void handleErrorRequest(OAuthAuthzReqMessageContext authzReqMessageContext, String errorCode,
                                    String errorMsg) {
        authzReqMessageContext.addProperty("ErrorCode", errorCode);
        authzReqMessageContext.addProperty("ErrorMsg", errorMsg);
    }

    @Override
    public boolean isAuthorizedClient(OAuthAuthzReqMessageContext authzReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO = authzReqMsgCtx.getAuthorizationReqDTO();

        String grantType = null;

        if (OAuthConstants.CODE.equals(authzReqDTO.getResponseType())) {
            grantType = GrantTypes.AUTHORIZATION_CODE;
        } else if (OAuthConstants.TOKEN.equals(authzReqDTO.getResponseType())) {
            grantType = GrantTypes.IMPLICIT;
        }

        // Load application data from the cache
        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        String consumerKey = authzReqDTO.getConsumerKey();
        OAuthAppDO oAuthAppDO = appInfoCache.getValueFromCache(consumerKey);
        if (oAuthAppDO == null) {
            try {
                oAuthAppDO = new OAuthAppDAO().getAppInformation(consumerKey);
                appInfoCache.addToCache(consumerKey, oAuthAppDO);
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception(e.getMessage(), e);
            }
        }

        if (StringUtils.isBlank(oAuthAppDO.getGrantTypes())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find authorized grant types for client id: " + consumerKey);
            }
            return false;
        }
        // If the application has defined a limited set of grant types, then check the grant
        if (!oAuthAppDO.getGrantTypes().contains(grantType)) {
            if (log.isDebugEnabled()) {
                //Do not change this log format as these logs use by external applications
                log.debug("Unsupported Grant Type : " + grantType + " for client id : " + consumerKey);
            }
            return false;
        }

        return true;
    }
}
