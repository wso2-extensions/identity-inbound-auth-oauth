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
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
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
 * This class extends AbstractOAuthEventInterceptor and listen to oauth related events. In this class, we persist
 * token to session mapping.
 */
public class OAuthTokenSessionMappingEventHandler extends AbstractOAuthEventInterceptor {

    private static final Log log = LogFactory.getLog(OAuthTokenSessionMappingEventHandler.class);

    /**
     * This method handles stores token to session mapping during post token issuance. This is used by authorization
     * grant flow.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokenRespDTO OAuth2AccessTokenRespDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the post token issue event with the grant type: %s for the " +
                    "application: %s", tokenReqDTO.getGrantType(), tokenReqDTO.getClientId()));
        }
        String code = null;
        if (StringUtils.equals(OAuthConstants.GrantTypes.AUTHORIZATION_CODE, tokenReqDTO.getGrantType())) {
            code = tokenReqDTO.getAuthorizationCode();
        }
        if (StringUtils.isBlank(code)) {
            /*
              We need authorization code to get the session context Id from the authorization grant cache for
              code grant. After this event is triggered, we change this cache mapping from code to
              access token. So at this level, we have the mapping of code to session in the authorization grant cache.
             */
            if (log.isDebugEnabled()) {
                log.debug("Since Authorization code is null, couldn't find session context identifier for the " +
                        "application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        if (StringUtils.isBlank(tokenReqDTO.getTenantDomain())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tenant domain of the application: " + tokenReqDTO.getClientId());
            }
            return;
        }

        if (tokenRespDTO == null) {
            if (log.isDebugEnabled()) {
                log.debug("TokenRespDTO passed was null. Cannot proceed further to build the token session mapping.");
            }
            return;
        }

        persistTokenToSessionMapping(getSessionContextIdentifierByCode(code), tokenRespDTO.getTokenId(),
                OAuth2Util.getTenantId(tokenReqDTO.getTenantDomain()), tokenReqDTO.getClientId());
    }

    /**
     * This method handles stores token to session mapping during post token renewal event. This happens for
     * refresh token grant.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokenRespDTO OAuth2AccessTokenRespDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Listening to the token renewal event for the application: " + tokenReqDTO.getClientId());
        }
        if (tokenRespDTO == null) {
            if (log.isDebugEnabled()) {
                log.debug("TokenRespDTO passed was null. Cannot proceed further to build the token session mapping "
                        + "for the clientId: " + tokenReqDTO.getClientId());
            }
            return;
        }
        if (StringUtils.isBlank(tokenRespDTO.getAccessToken())) {
            // Need accesstoken to get the sessioncontext Id from the authorization grant cache for refresh token grant.
            if (log.isDebugEnabled()) {
                log.debug("Since the access token is invalid, couldn't find session context identifier " +
                        "for the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        if (StringUtils.isBlank(tokenReqDTO.getTenantDomain())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tenant domain of the application: " + tokenReqDTO.getClientId());
            }
            return;
        }
        persistTokenToSessionMapping(getSessionContextIdentifierByToken(tokenRespDTO.getAccessToken()),
                tokenRespDTO.getTokenId(), OAuth2Util.getTenantId(tokenReqDTO.getTenantDomain()),
                tokenReqDTO.getClientId());
    }

    /**
     * This method handles stores token to session mapping during post token issuance event. This happens for
     * implicit and hybrid flow.
     *
     * @param oauthAuthzMsgCtx OAuthAuthzReqMessageContext.
     * @param tokenDO          AccessTokenDO
     * @param respDTO          OAuth2AuthorizeRespDTO
     * @param params           Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the post token issue event with the response type: %s for the " +
                    "application: %s", oauthAuthzMsgCtx.getAuthorizationReqDTO().getResponseType(),
                    tokenDO.getConsumerKey()));
        }
        String sessionContextId = oauthAuthzMsgCtx.getAuthorizationReqDTO().getIdpSessionIdentifier();
        persistTokenToSessionMapping(sessionContextId, tokenDO.getTokenId(), tokenDO.getTenantID(),
                tokenDO.getConsumerKey());
    }

    /**
     * This handler is enabled by default. If there are no any configs in the identity.xml file, then this handler will
     * be enabled. If there are any config, then the enable property will be read from the config file.
     *
     * @return True by default. Return the enabled property if any config is added.
     */
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ||
                Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    /**
     * Return session context identifier from authorization grant cache. For authorization code flow, we mapped it
     * against auth_code.
     *
     * @param authorizationCode Authorization code.
     * @return SessionContextIdentifier.
     */
    private String getSessionContextIdentifierByCode(String authorizationCode) {

        String sessionContextIdentifier = null;
        if (isNotBlank(authorizationCode)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
            if (cacheEntry != null) {
                sessionContextIdentifier = cacheEntry.getSessionContextIdentifier();
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Found session context identifier: %s for the obtained authorization " +
                            "code", sessionContextIdentifier));
                }
            }
        }
        return sessionContextIdentifier;
    }

    /**
     * Return session context identifier from authorization grant cache. For refresh token flow, we mapped it
     * against the accesstoken.
     *
     * @param accessToken Accesstoken.
     * @return SessionContextIdentifier.
     */
    private String getSessionContextIdentifierByToken(String accessToken) {

        String sessionContextIdentifier = null;
        if (isNotBlank(accessToken)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
            if (cacheEntry != null) {
                sessionContextIdentifier = cacheEntry.getSessionContextIdentifier();
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Found session context identifier: %s for the obtained accesstoken",
                            sessionContextIdentifier));
                }
            }
        }
        return sessionContextIdentifier;
    }

    /**
     * This method persists token to session mapping to the db.
     * @param sessionContextId SessionContextId.
     * @param tokenId TokenId.
     * @param tenantId TenantId.
     * @param clientId ClientId.
     * @throws IdentityOAuth2Exception
     */
    private void persistTokenToSessionMapping(String sessionContextId, String tokenId, int tenantId, String clientId)
            throws IdentityOAuth2Exception {

        if (OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .getTokenIdBySessionIdentifier(sessionContextId).contains(tokenId)) {
            /**
             *  If there is already a session to token mapping exists, we don't need to persist that mapping again.
             *  This can happen if a user try to login from the same browser again with same (app+scope+binding).
             */
            if (log.isDebugEnabled()) {
                log.debug("This token to session mapping is already persisted in the DB");
            }
            return;
        }
        if (StringUtils.isBlank(tokenId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the tokenId of the application: " + clientId);
            }
            return;
        }
        if (StringUtils.isBlank(sessionContextId)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find the session context identifier for the application: " + clientId);
            }
            return;
        }
        if (tenantId == 0) {
            // TenantId should have some value rather than 0.
            if (log.isDebugEnabled()) {
                log.debug("Tenant id is not valid for the client: " + clientId);
            }
            return;
        }
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .storeTokenToSessionMapping(sessionContextId, tokenId, tenantId);
    }

    public String getName() {

        return "OAuthTokenSessionMappingEventHandler";
    }
}
