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
package org.wso2.carbon.identity.oidc.session.backchannellogout;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.ws.rs.core.HttpHeaders;

/**
 * This class is used to insert sid claim into ID token.
 */
public class ClaimProviderImpl implements ClaimProvider {

    private static final Log LOG = LogFactory.getLog(ClaimProviderImpl.class);

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
            LOG.debug("sid claim is generated for auth request.");
        } else {
            // Previous browser session exists, get sid claim from OIDCSessionState.
            claimValue = previousSession.getSidClaim();
            LOG.debug("sid claim is found in the session state.");
        }
        additionalClaims.put(OAuthConstants.OIDCClaims.SESSION_ID_CLAIM, claimValue);
        oAuth2AuthorizeRespDTO.setOidcSessionId(claimValue);
        return additionalClaims;
    }

    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntryFromCode(String authorizationCode) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        return AuthorizationGrantCache.getInstance().getValueFromCacheByCode(authorizationGrantCacheKey);
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext oAuthTokenReqMessageContext,
                                                   OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO)
            throws IdentityOAuth2Exception {

        Map<String, Object> additionalClaims = new HashMap<>();
        String claimValue = null;
        String accessCode = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getAuthorizationCode();

        if (StringUtils.isNotBlank(accessCode)) {
            AuthorizationGrantCacheEntry authzGrantCacheEntry =
                    getAuthorizationGrantCacheEntryFromCode(accessCode);
            if (authzGrantCacheEntry != null) {
                claimValue = authzGrantCacheEntry.getOidcSessionId();
            }
        } else if (OAuthConstants.GrantTypes.REFRESH_TOKEN.equalsIgnoreCase(
                oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType())) {
            OIDCSessionState previousSession = getSessionState(oAuthTokenReqMessageContext);
            if (previousSession != null) {
                claimValue = previousSession.getSidClaim();
            } else {
                AuthorizationGrantCacheKey authorizationGrantCacheKey =
                        new AuthorizationGrantCacheKey(oAuth2AccessTokenRespDTO.getAccessToken());
                AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                        AuthorizationGrantCache.getInstance().getValueFromCacheByCode(authorizationGrantCacheKey);
                if (authorizationGrantCacheEntry != null) {
                    claimValue = authorizationGrantCacheEntry.getOidcSessionId();
                }
            }
        } else {
            LOG.debug("AccessCode is null. Possibly a back end grant");
            return additionalClaims;
        }

        if (claimValue != null) {
            LOG.debug("sid claim is found in the session state");
            additionalClaims.put("sid", claimValue);
        }
        return additionalClaims;
    }

    /**
     * Return previousSessionState using opbs cookie.
     *
     * @param oAuthAuthzReqMessageContext OAuthAuthzReqMessageContext.
     * @return OIDCSession state
     */
    private OIDCSessionState getSessionState(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        Cookie[] cookies = oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getCookie();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (OIDCSessionConstants.OPBS_COOKIE_ID.equals(cookie.getName())) {
                    return OIDCSessionManagementUtil.getSessionManager()
                            .getOIDCSessionState(cookie.getValue(), oAuthAuthzReqMessageContext.
                                    getAuthorizationReqDTO().getLoggedInTenantDomain());
                }
            }
        }
        return null;
    }

    /**
     * Get session state using opbs cookie.
     *
     * @param oAuthTokenReqMessageContext OAuth Token Request Message Context.
     * @return OIDC session state.
     */
    private OIDCSessionState getSessionState(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) {

        HttpRequestHeader[] httpRequestHeaders = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getHttpRequestHeaders();
        if (ArrayUtils.isEmpty(httpRequestHeaders)) {
            return null;
        }
        for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
            if (HttpHeaders.COOKIE.equalsIgnoreCase(httpRequestHeader.getName())) {
                if (ArrayUtils.isEmpty(httpRequestHeader.getValue())) {
                    return null;
                }
                String[] cookies = httpRequestHeader.getValue()[0].split(";");
                for (String cookie : cookies) {
                    String[] cookieParts = cookie.split("=");
                    if (cookieParts.length == 2 && OIDCSessionConstants.OPBS_COOKIE_ID.equals(cookieParts[0].trim())) {
                        String opbsCookieValue = cookieParts[1];
                        if (StringUtils.isBlank(opbsCookieValue)) {
                            return null;
                        }
                        return OIDCSessionManagementUtil.getSessionManager().getOIDCSessionState(opbsCookieValue,
                                oAuthTokenReqMessageContext.getAuthorizedUser().getTenantDomain());
                    }
                }
            }
        }
        return null;
    }
}
