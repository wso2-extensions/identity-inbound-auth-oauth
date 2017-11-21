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
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Date;
import java.util.UUID;

public class CodeResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CodeResponseTypeHandler.class);

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {
        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        String authorizationCode;
        String codeId;
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(authorizationReqDTO.getConsumerKey());
        if (oAuthAppDO == null) {
            try {
                oAuthAppDO = new OAuthAppDAO().getAppInformation(authorizationReqDTO.getConsumerKey());
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Invalid consumer application. Failed to issue Grant token.", e);
            }
            AppInfoCache.getInstance().addToCache(oAuthAppDO.getOauthConsumerKey(), oAuthAppDO);
        }

        Timestamp timestamp = new Timestamp(new Date().getTime());

        long validityPeriod = OAuthServerConfiguration.getInstance()
                .getAuthorizationCodeValidityPeriodInSeconds();

        // if a VALID callback is set through the callback handler, use
        // it instead of the default one
        long callbackValidityPeriod = oauthAuthzMsgCtx.getValidityPeriod();

        if ((callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD)
                && callbackValidityPeriod > 0) {
            validityPeriod = callbackValidityPeriod;
        }
        // convert to milliseconds
        validityPeriod = validityPeriod * 1000;
        
        // set the validity period. this is needed by downstream handlers.
        // if this is set before - then this will override it by the calculated new value.
        oauthAuthzMsgCtx.setValidityPeriod(validityPeriod);
    
        // set code issued time.this is needed by downstream handlers.
        oauthAuthzMsgCtx.setCodeIssuedTime(timestamp.getTime());

        if (authorizationReqDTO.getUser() != null && authorizationReqDTO.getUser().isFederatedUser()) {
            //if a federated user, treat the tenant domain as similar to application domain.
            authorizationReqDTO.getUser().setTenantDomain(authorizationReqDTO.getTenantDomain());
        }

        try {
            authorizationCode = oauthIssuerImpl.authorizationCode(oauthAuthzMsgCtx);
            codeId = UUID.randomUUID().toString();
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }

        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authorizationReqDTO.getUser(),
                oauthAuthzMsgCtx.getApprovedScope(),timestamp, validityPeriod, authorizationReqDTO.getCallbackUrl(),
                authorizationReqDTO.getConsumerKey(), authorizationCode, codeId,
                authorizationReqDTO.getPkceCodeChallenge(), authorizationReqDTO.getPkceCodeChallengeMethod());

        tokenMgtDAO.storeAuthorizationCode(authorizationCode, authorizationReqDTO.getConsumerKey(),
                authorizationReqDTO.getCallbackUrl(), authzCodeDO);

        if (cacheEnabled) {
            // Cache the authz Code, here we prepend the client_key to avoid collisions with
            // AccessTokenDO instances. In database level, these are in two databases. But access
            // tokens and authorization codes are in a single cache.
            String cacheKeyString = OAuth2Util.buildCacheKeyStringForAuthzCode(
                    authorizationReqDTO.getConsumerKey(), authorizationCode);
            OAuthCache.getInstance().addToCache(new OAuthCacheKey(cacheKeyString), authzCodeDO);
            if (log.isDebugEnabled()) {
                log.debug("Authorization Code info was added to the cache for client id : " +
                        authorizationReqDTO.getConsumerKey());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Issued Authorization Code to user : " + authorizationReqDTO.getUser() +
                    ", Using the redirect url : " + authorizationReqDTO.getCallbackUrl() +
                    ", Scope : " + OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope()) +
                    ", validity period : " + validityPeriod);
        }

        respDTO.setCallbackURI(authorizationReqDTO.getCallbackUrl());
        respDTO.setAuthorizationCode(authorizationCode);
        respDTO.setCodeId(codeId);
        return respDTO;
    }


}
