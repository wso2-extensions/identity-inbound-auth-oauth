/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * This class extends OAuthEventInterceptor and listen to oauth related events.
 */
public class OAuthEventInterceptorListener extends AbstractOAuthEventInterceptor {

    private static final Log log = LogFactory.getLog(OAuthEventInterceptorListener.class);

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Listening to the post token issue event");
        }
        String tokenId = tokenRespDTO.getTokenId();
        String code = tokenReqDTO.getAuthorizationCode();
        String sessionContextId = null;
        if (StringUtils.isBlank(code)) {
            if (log.isDebugEnabled()) {
                log.debug("Since Authorization code is null, couldn't find session context identifier " +
                        "for the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        sessionContextId = getSessionContextIdentifier(code);
        String tenantDomain = tokenReqDTO.getTenantDomain();
        if (StringUtils.isBlank(tenantDomain)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tenant domain of the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        if (StringUtils.isBlank(sessionContextId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the session context identifier for the application: " +
                        tokenReqDTO.getClientId());
            }
            return;
        }
        persistTokenToSessionMapping(sessionContextId, tokenId, OAuth2Util.getTenantId(tenantDomain));
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Listening to the token renewal event");
        }
        String tokenId = tokenRespDTO.getTokenId();
        if (StringUtils.isBlank(tokenId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tokenId of the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        String accessToken = tokenRespDTO.getAccessToken();
        if (StringUtils.isBlank(accessToken)) {
            if (log.isDebugEnabled()) {
                log.debug("Since the accesstoken is invalid, couldn't find session context identifier " +
                        "for the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        String sessionContextId = getSessionContextIdentifier(accessToken);
        if (StringUtils.isBlank(sessionContextId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the session context identifier for the application: " +
                        tokenReqDTO.getClientId());
            }
            return;
        }
        String tenantDomain = tokenReqDTO.getTenantDomain();
        if (StringUtils.isBlank(tenantDomain)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tenant domain of the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        persistTokenToSessionMapping(sessionContextId, tokenId, tenantId);
    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Listening to the token renewal event");
        }
        String sessionContextId = oauthAuthzMsgCtx.getAuthorizationReqDTO().getIdpSessionIdentifier();
        if (StringUtils.isBlank(sessionContextId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the session context identifier for the application: " +
                        tokenDO.getConsumerKey());
            }
            return;
        }
        String tokenId = tokenDO.getTokenId();
        if (StringUtils.isBlank(tokenId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tokenId of the application: " + tokenDO.getConsumerKey());
            }
            return;
        }
        int tenantId = tokenDO.getTenantID();
        persistTokenToSessionMapping(sessionContextId, tokenId, tenantId);
    }

    public boolean isEnabled() {
        return true;
    }

    private String getSessionContextIdentifier(String token) {

        String sessionContextIdentifier = null;
        if (isNotBlank(token)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(token);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
            if (cacheEntry != null) {
                sessionContextIdentifier = cacheEntry.getSessionContextIdentifier();
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Found session context identifier: %s for the obtained authorization code",
                            sessionContextIdentifier));
                }
            }
        }
        return sessionContextIdentifier;
    }

    private void persistTokenToSessionMapping(String sessionContextId, String tokenId, int tenantId)
            throws IdentityOAuth2Exception {

        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .storeTokenToSessionMapping(sessionContextId, tokenId, tenantId);
    }
}
