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
package org.wso2.carbon.identity.oidc.session.backChannelLogout;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.cache.OIDCBackChannelAuthCodeCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCBackChannelAuthCodeCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCBackChannelAuthCodeCacheKey;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;

import javax.servlet.http.Cookie;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * This class is used to insert sid claim into ID token
 */
public class ClaimProviderImpl implements ClaimProvider {

    private static Log log = LogFactory.getLog(ClaimProviderImpl.class);

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext,
                                                   OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO)
            throws IdentityOAuth2Exception {

        Map<String, Object> additionalClaims = new HashMap<>();
        String claimValue;
        OIDCSessionState previousSession = getSessionState(oAuthAuthzReqMessageContext);
        if (previousSession == null) {
            // If there is no previous browser session, generate new sid value.
            claimValue = UUID.randomUUID().toString();
            if (log.isDebugEnabled()) {
                log.debug("sid claim is generated for auth request. ");
            }
        } else {
            // Previous browser session exists, get sid claim from OIDCSessionState.
            claimValue = previousSession.getSidClaim();
            if (log.isDebugEnabled()) {
                log.debug("sid claim is found in the session state");
            }
        }
        additionalClaims.put(OAuthConstants.OIDCClaims.SESSION_ID_CLAIM, claimValue);

        addSidToCacheWhenIDTokenIsEncrypted(oAuthAuthzReqMessageContext, claimValue);

        return additionalClaims;
    }

    /**
     * Add session id to cache when ID token encryption is enabled.
     *
     * @param oAuthAuthzReqMessageContext OAuthAuthzReqMessageContext object.
     * @param claimValue                  Session ID to be inserted to the cache.
     * @throws IdentityOAuth2Exception
     */
    private void addSidToCacheWhenIDTokenIsEncrypted(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext,
                                                     String claimValue) throws IdentityOAuth2Exception {
        try {
            OAuthAppDO app = OAuth2Util.getAppInformationByClientId(
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
            if (app.isIdTokenEncryptionEnabled()) {
                // Add sid to cache for the instances where id token is encrypted.
                OIDCBackChannelAuthCodeCacheKey authCacheKey = new OIDCBackChannelAuthCodeCacheKey(
                        OAuthConstants.OIDCClaims.SESSION_ID_CLAIM);
                OIDCBackChannelAuthCodeCacheEntry sidCacheEntry = new OIDCBackChannelAuthCodeCacheEntry();
                sidCacheEntry.setSessionId(claimValue);
                OIDCBackChannelAuthCodeCache.getInstance().addToCache(authCacheKey, sidCacheEntry);
                if (log.isDebugEnabled()) {
                    log.debug("Adding sid to OIDCBackChannelAuthCodeCache since id token encryption is enabled.");
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Retrieving OAuthAppDO failed for the client id: " +
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getConsumerKey(), e);
        }
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext oAuthTokenReqMessageContext,
                                                   OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO)
            throws IdentityOAuth2Exception {

        Map<String, Object> additionalClaims = new HashMap<>();
        String claimValue = null;
        String accessCode = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        OIDCBackChannelAuthCodeCacheEntry cacheEntry = getOIDCBackChannelAuthCodeCacheEntry(accessCode);
        if (cacheEntry != null) {
            claimValue = cacheEntry.getSessionId();
        }
        if (claimValue != null) {
            if (log.isDebugEnabled()) {
                log.debug("sid claim is found in the session state");
            }
            additionalClaims.put("sid", claimValue);
        }
        return additionalClaims;
    }

    /**
     * Return previousSessionState using opbs cookie.
     *
     * @param oAuthAuthzReqMessageContext
     * @return OIDCSession state
     */
    private OIDCSessionState getSessionState(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        Cookie[] cookies = oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getCookie();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (OIDCSessionConstants.OPBS_COOKIE_ID.equals(cookie.getName())) {
                    OIDCSessionState previousSessionState = OIDCSessionManagementUtil.getSessionManager()
                            .getOIDCSessionState(cookie.getValue());
                    return previousSessionState;
                }
            }
        }
        return null;
    }

    /**
     * Return OIDCBackChannelAuthCodeCacheEntry for a authorization code.
     *
     * @param authCode
     * @return OIDCBackChannelAuthCodeCacheEntry
     */
    private OIDCBackChannelAuthCodeCacheEntry getOIDCBackChannelAuthCodeCacheEntry(String authCode) {

        if (StringUtils.isBlank(authCode)) {
            if (log.isDebugEnabled()) {
                log.debug("getOIDCBackChannelAuthCodeCacheEntry returned null.");
            }
            return null;
        }
        OIDCBackChannelAuthCodeCacheKey cacheKey = new OIDCBackChannelAuthCodeCacheKey(authCode);
        OIDCBackChannelAuthCodeCacheEntry cacheEntry =
                OIDCBackChannelAuthCodeCache.getInstance().getValueFromCache(cacheKey);
        return cacheEntry;
    }
}
