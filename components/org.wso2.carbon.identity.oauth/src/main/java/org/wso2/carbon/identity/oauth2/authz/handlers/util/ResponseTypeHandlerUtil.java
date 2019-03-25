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
package org.wso2.carbon.identity.oauth2.authz.handlers.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;

/**
 * ResponseTypeHandlerUtil contains all the common methods in tokenResponseTypeHandler and IDTokenResponseTypeHandler.
 */
public class ResponseTypeHandlerUtil {
    public static final int SECOND_TO_MILLISECONDS_FACTOR = 1000;
    private static Log log = LogFactory.getLog(ResponseTypeHandlerUtil.class);
    private static boolean isHashDisabled = OAuth2Util.isHashDisabled();

    public static void triggerPreListeners(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            try {
                oAuthEventInterceptorProxy.onPreTokenIssue(oauthAuthzMsgCtx, paramMap);
                if (log.isDebugEnabled()) {
                    log.debug("Oauth pre token issue listener is triggered.");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth pre token issue listener ", e);
            }
        }

    }

    public static void triggerPostListeners(OAuthAuthzReqMessageContext
                                              oauthAuthzMsgCtx, AccessTokenDO tokenDO, OAuth2AuthorizeRespDTO respDTO) {
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy.onPostTokenIssue(oauthAuthzMsgCtx, tokenDO, respDTO, paramMap);
                if (log.isDebugEnabled()) {
                    log.debug("Oauth post token issue listener is triggered.");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth post token issue listener ", e);
            }
        }
    }

    /**
     * Generates access token for the issuer type registered in the service provider app.
     *
     * @param oauthAuthzMsgCtx
     * @param cacheEnabled
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static AccessTokenDO generateAccessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled)
            throws IdentityOAuth2Exception {

        String consumerKey = oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey();
        OauthTokenIssuer oauthTokenIssuer;
        try {
             oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
        } catch (InvalidOAuthClientException e) {
            String errorMsg = "Error when instantiating the OAuthIssuer for service provider app with client Id: " +
                    consumerKey + ". Defaulting to OAuthIssuerImpl";
            log.error(errorMsg, e);
            oauthTokenIssuer = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();
        }
        return generateAccessToken(oauthAuthzMsgCtx, cacheEnabled, oauthTokenIssuer);
    }

    /**
     * Generates access token for the given oauth issuer.
     *
     * @param oauthAuthzMsgCtx
     * @param cacheEnabled
     * @param oauthIssuerImpl
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static AccessTokenDO generateAccessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled,
                                              OauthTokenIssuer oauthIssuerImpl)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

        String scope = OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope());
        String consumerKey = authorizationReqDTO.getConsumerKey();
        String authorizedUser = authorizationReqDTO.getUser().toString();

        synchronized ((consumerKey + ":" + authorizedUser + ":" + scope).intern()) {

            AccessTokenDO existingTokenBean = getExistingToken(oauthAuthzMsgCtx, cacheEnabled);

            // Return a new access token in each request when JWTTokenIssuer is used.
            if (isNotRenewAccessTokenPerRequest(oauthIssuerImpl)) {
                if (existingTokenBean != null) {

                    // Revoke token if RenewTokenPerRequest configuration is enabled.
                    if (OAuthServerConfiguration.getInstance().isTokenRenewalPerRequestEnabled()) {

                        if (log.isDebugEnabled()) {
                            log.debug("RenewTokenPerRequest configuration active. " +
                                    "Proceeding to revoke any existing active tokens for client Id: "
                                    + consumerKey + ", user: " + authorizedUser + " and scope: " + scope + ".");
                        }

                        revokeExistingToken(existingTokenBean.getConsumerKey(), existingTokenBean.getAccessToken());

                        // When revoking the token state will be set as REVOKED.
                        // existingTokenBean.setTokenState(TOKEN_STATE_REVOKED) can be used instead of 'null' but
                        // then the token state will again be updated to EXPIRED when a new token is generated.
                        existingTokenBean = null;
                    }

                    // Return existing token if it is still valid.
                    if (isAccessTokenValid(existingTokenBean)) {
                        return existingTokenBean;
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug("No active access token found for client Id: " + consumerKey + ", user: " +
                            authorizedUser + " and scope: " + scope + ". Therefore issuing new token");
                }
            }

            // Issue a new access token.
            return generateNewAccessToken(oauthAuthzMsgCtx, existingTokenBean, oauthIssuerImpl, cacheEnabled);
        }
    }

    public static AuthzCodeDO generateAuthorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled)
            throws IdentityOAuth2Exception {
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String consumerKey = authorizationReqDTO.getConsumerKey();
        try {
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
            return generateAuthorizationCode(oauthAuthzMsgCtx, cacheEnabled, oauthTokenIssuer);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
        }
    }

    public static AuthzCodeDO generateAuthorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled,
                                                 OauthTokenIssuer oauthIssuerImpl)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String authorizationCode;
        String codeId = UUID.randomUUID().toString();
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
        oauthAuthzMsgCtx.setAuthorizationCodeValidityPeriod(validityPeriod);

        // set code issued time.this is needed by downstream handlers.
        oauthAuthzMsgCtx.setCodeIssuedTime(timestamp.getTime());

        if (authorizationReqDTO.getUser() != null && authorizationReqDTO.getUser().isFederatedUser()) {
            //if a federated user, treat the tenant domain as similar to application domain.
            authorizationReqDTO.getUser().setTenantDomain(authorizationReqDTO.getTenantDomain());
        }

        try {
            authorizationCode = oauthIssuerImpl.authorizationCode(oauthAuthzMsgCtx);
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }

        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authorizationReqDTO.getUser(),
                oauthAuthzMsgCtx.getApprovedScope(), timestamp, validityPeriod, authorizationReqDTO.getCallbackUrl(),
                authorizationReqDTO.getConsumerKey(), authorizationCode, codeId,
                authorizationReqDTO.getPkceCodeChallenge(), authorizationReqDTO.getPkceCodeChallengeMethod());

        OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                .insertAuthorizationCode(authorizationCode, authorizationReqDTO.getConsumerKey(),
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
        return authzCodeDO;
    }

    public static OAuth2AuthorizeRespDTO buildAuthorizationCodeResponseDTO(OAuth2AuthorizeRespDTO respDTO, AuthzCodeDO authzCodeDO)
            throws IdentityOAuth2Exception {
        respDTO.setAuthorizationCode(authzCodeDO.getAuthorizationCode());
        respDTO.setCodeId(authzCodeDO.getAuthzCodeId());
        return  respDTO;
    }

    public  static OAuth2AuthorizeRespDTO buildAccessTokenResponseDTO(OAuth2AuthorizeRespDTO respDTO, AccessTokenDO accessTokenDO) {

        long expireTime = OAuth2Util.getTokenExpireTimeMillis(accessTokenDO);
        if (log.isDebugEnabled()) {
            if (expireTime > 0) {
                log.debug("Access Token" +
                        " is valid for another " + expireTime + "ms");
            } else {
                log.debug("Infinite lifetime Access Token found in cache");
            }
        }
        respDTO.setAccessToken(accessTokenDO.getAccessToken());
        if (expireTime > 0) {
            respDTO.setValidityPeriod(expireTime / 1000);
        } else {
            respDTO.setValidityPeriod(Long.MAX_VALUE / 1000);
        }
        respDTO.setTokenType(accessTokenDO.getTokenType());
        return  respDTO;
    }

    /**
     * This method is used to set the id_token value in respDTO.
     * When creating the id_token, an access token is issued and through that access token user attributes are called.
     * This access token details are not necessary for respDTO when issuing the id_token.
     * So a new OAuth2AuthorizeRespDTO object is created and set all the relevant details that are needed in
     * DefaultIDTokenBuilder class. After the id_token is issued, set the id_token value to respDTO object and return.
     * @param respDTO
     * @param accessTokenDO
     * @param oauthAuthzMsgCtx
     * @return OAuth2AuthorizeRespDTO object with id_token details.
     * @throws IdentityOAuth2Exception
     */
    public static OAuth2AuthorizeRespDTO buildIDTokenResponseDTO(OAuth2AuthorizeRespDTO respDTO, AccessTokenDO accessTokenDO,
                                                   OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {
        if (isOIDCRequest(oauthAuthzMsgCtx)) {
            OAuth2AuthorizeRespDTO newRespDTO = new OAuth2AuthorizeRespDTO();
            newRespDTO.setAccessToken(accessTokenDO.getAccessToken());
            newRespDTO.setAuthorizationCode(respDTO.getAuthorizationCode());
            buildIdToken(oauthAuthzMsgCtx, newRespDTO);
            respDTO.setIdToken(newRespDTO.getIdToken());
        }
        return  respDTO;
    }

    private static boolean isOIDCRequest (OAuthAuthzReqMessageContext msgCtx) {

        return msgCtx.getApprovedScope() != null && OAuth2Util.isOIDCAuthzRequest(msgCtx.getApprovedScope());
    }

    /**
     * Handles caching user attributes and building the id_token for the OIDC implicit authz request.
     *
     * @param msgCtx
     * @param authzRespDTO
     * @throws IdentityOAuth2Exception
     */
    private static void buildIdToken(OAuthAuthzReqMessageContext msgCtx, OAuth2AuthorizeRespDTO authzRespDTO)
            throws IdentityOAuth2Exception {

        if (StringUtils.isNotBlank(authzRespDTO.getAccessToken())) {
            addUserAttributesToCache(authzRespDTO.getAccessToken(), msgCtx);
        }

        if (StringUtils.contains(msgCtx.getAuthorizationReqDTO().getResponseType(), "id_token")) {
            IDTokenBuilder builder = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenBuilder();
            authzRespDTO.setIdToken(builder.buildIDToken(msgCtx, authzRespDTO));
        }
    }

    private static void addUserAttributesToCache(String accessToken, OAuthAuthzReqMessageContext msgCtx)
    throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizeReqDTO = msgCtx.getAuthorizationReqDTO();
        Map<ClaimMapping, String> userAttributes = authorizeReqDTO.getUser().getUserAttributes();
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);
        if (StringUtils.isNotBlank(authorizeReqDTO.getEssentialClaims())) {
            authorizationGrantCacheEntry.setEssentialClaims(authorizeReqDTO.getEssentialClaims());
        }

        ClaimMapping key = new ClaimMapping();
        Claim claimOfKey = new Claim();
        claimOfKey.setClaimUri(OAuth2Util.SUB);
        key.setRemoteClaim(claimOfKey);
        String sub = authorizeReqDTO.getUser().getUserName();

        AccessTokenDO accessTokenDO = getAccessTokenDO(accessToken, msgCtx);
        if (accessTokenDO != null && StringUtils.isNotBlank(accessTokenDO.getTokenId())) {
            authorizationGrantCacheEntry.setTokenId(accessTokenDO.getTokenId());
        }

        if (StringUtils.isBlank(sub)) {
            sub = authorizeReqDTO.getUser().getAuthenticatedSubjectIdentifier();
        }

        if (StringUtils.isNotBlank(sub)) {
            userAttributes.put(key, sub);
        }

        authorizationGrantCacheEntry.setValidityPeriod(TimeUnit.MILLISECONDS.toNanos(accessTokenDO.getValidityPeriodInMillis()));
        AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey,
                authorizationGrantCacheEntry);
    }

    private static AccessTokenDO getAccessTokenDO(String accessToken,
                                                  OAuthAuthzReqMessageContext msgCtx) throws IdentityOAuth2Exception {

        Object accessTokenObject = msgCtx.getProperty(OAuth2Util.ACCESS_TOKEN_DO);
        if (accessTokenObject instanceof AccessTokenDO) {
            return (AccessTokenDO) accessTokenObject;
        }
        return OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessToken);
    }

    private static void deactivateCurrentAuthorizationCode(String authorizationCode, String tokenId)
            throws IdentityOAuth2Exception {

        if (authorizationCode != null) {
            AuthzCodeDO authzCodeDO = new AuthzCodeDO();
            authzCodeDO.setAuthorizationCode(authorizationCode);
            authzCodeDO.setOauthTokenId(tokenId);
            OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().deactivateAuthorizationCode(authzCodeDO);
        }
    }

    private static AccessTokenDO getExistingToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled)
            throws IdentityOAuth2Exception {

        AccessTokenDO existingTokenBean = null;
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String scope = OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope());
        String consumerKey = authorizationReqDTO.getConsumerKey();
        String authorizedUser = authorizationReqDTO.getUser().toString();

        if (cacheEnabled) {
            existingTokenBean = getExistingTokenFromCache(consumerKey, scope, authorizedUser);
        }

        if (existingTokenBean == null) {
            existingTokenBean = getExistingTokenFromDB(oauthAuthzMsgCtx, cacheEnabled);
        }
        return existingTokenBean;
    }

    private static AccessTokenDO getExistingTokenFromCache(String consumerKey, String scope, String authorizedUser)
            throws IdentityOAuth2Exception {

        AccessTokenDO existingTokenBean = null;
        OAuthCacheKey cacheKey = getOAuthCacheKey(consumerKey, scope, authorizedUser);
        CacheEntry cacheEntry = OAuthCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry != null && cacheEntry instanceof AccessTokenDO) {
            existingTokenBean = (AccessTokenDO) cacheEntry;
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved active access token(hashed): " + DigestUtils.sha256Hex(existingTokenBean
                            .getAccessToken()) + " in state: " + existingTokenBean.getTokenState() + " for client " +
                            "Id: " + consumerKey + ", user: " + authorizedUser + " and scope: " + scope + " from" +
                            " cache.");

                } else {
                    log.debug("Retrieved active access token in state: " + existingTokenBean.getTokenState() + " for " +
                            "" + "client Id: " + consumerKey + ", user: " + authorizedUser + " and scope: " + scope +
                            " from cache.");
                }
            }
            if (getAccessTokenExpiryTimeMillis(existingTokenBean) == 0) {
                // Token is expired. Clear it from cache.
                removeTokenFromCache(cacheKey, existingTokenBean);
            }
        }
        return existingTokenBean;
    }

    private static AccessTokenDO getExistingTokenFromDB(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean
            cacheEnabled) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String scope = OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope());
        String consumerKey = authorizationReqDTO.getConsumerKey();
        AuthenticatedUser authorizedUser = authorizationReqDTO.getUser();

        AccessTokenDO existingToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getLatestAccessToken(consumerKey, authorizedUser, getUserStoreDomain(authorizedUser), scope, false);
        if (existingToken != null) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex(existingToken
                            .getAccessToken()) + " in state: " + existingToken.getTokenState() + " for client Id: " +
                            consumerKey + " user: " + authorizedUser + " and scope: " + scope + " from db");
                } else {
                    log.debug("Retrieved latest access token for client Id: " + consumerKey + " user: " +
                            authorizedUser + " and scope: " + scope + " from db");
                }
            }

            long expireTime = getAccessTokenExpiryTimeMillis(existingToken);
            if (TOKEN_STATE_ACTIVE.equals(existingToken.getTokenState()) && expireTime != 0 && cacheEnabled) {
                // Active token retrieved from db, adding to cache if cacheEnabled
                addTokenToCache(getOAuthCacheKey(consumerKey, scope, authorizedUser.toString()), existingToken);
            }
        }
        return existingToken;
    }

    private static AccessTokenDO generateNewAccessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO
            existingTokenBean, OauthTokenIssuer oauthIssuerImpl, boolean cacheEnabled) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String scope = OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope());
        String consumerKey = authorizationReqDTO.getConsumerKey();
        String authorizedUser = authorizationReqDTO.getUser().toString();

        OAuthAppDO oAuthAppBean = getOAuthApp(consumerKey);
        Timestamp timestamp = new Timestamp(new Date().getTime());
        long validityPeriodInMillis = getConfiguredAccessTokenValidityPeriodInMillis(oauthAuthzMsgCtx, oAuthAppBean);
        AccessTokenDO newTokenBean = createNewTokenBean(oauthAuthzMsgCtx, oAuthAppBean, existingTokenBean,
                oauthIssuerImpl, timestamp, validityPeriodInMillis);
        setDetailsToMessageContext(oauthAuthzMsgCtx, newTokenBean);
        // Persist the access token in database
        persistAccessTokenInDB(oauthAuthzMsgCtx, existingTokenBean, newTokenBean);
        deactivateCurrentAuthorizationCode(newTokenBean.getAuthorizationCode(), newTokenBean.getTokenId());
        //update cache with newly added token
        if (isHashDisabled && cacheEnabled) {
            addTokenToCache(getOAuthCacheKey(consumerKey, scope, authorizedUser), newTokenBean);
        }
        return newTokenBean;
    }

    private static AccessTokenDO createNewTokenBean(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, OAuthAppDO
            oAuthAppBean, AccessTokenDO existingTokenBean, OauthTokenIssuer oauthIssuerImpl, Timestamp timestamp,
                                                    long validityPeriodInMillis) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

        AccessTokenDO newTokenBean = new AccessTokenDO();
        newTokenBean.setTokenState(TOKEN_STATE_ACTIVE);
        newTokenBean.setConsumerKey(authorizationReqDTO.getConsumerKey());
        newTokenBean.setAuthzUser(authorizationReqDTO.getUser());
        newTokenBean.setTenantID(OAuth2Util.getTenantId(authorizationReqDTO.getTenantDomain()));
        newTokenBean.setScope(oauthAuthzMsgCtx.getApprovedScope());
        newTokenBean.setTokenId(UUID.randomUUID().toString());
        newTokenBean.setTokenType(OAuthConstants.UserType.APPLICATION_USER);
        newTokenBean.setIssuedTime(timestamp);
        newTokenBean.setValidityPeriodInMillis(validityPeriodInMillis);
        newTokenBean.setValidityPeriod(validityPeriodInMillis / SECOND_TO_MILLISECONDS_FACTOR);
        newTokenBean.setGrantType(getGrantType(authorizationReqDTO.getResponseType()));
        newTokenBean.setAccessToken(getNewAccessToken(oauthAuthzMsgCtx, oauthIssuerImpl));
        setRefreshTokenDetails(oauthAuthzMsgCtx, oAuthAppBean, existingTokenBean, newTokenBean, oauthIssuerImpl,
                timestamp);
        return newTokenBean;
    }

    private static String getNewAccessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, OauthTokenIssuer
            oauthIssuerImpl) throws IdentityOAuth2Exception {

        try {
            String newAccessToken = oauthIssuerImpl.accessToken(oauthAuthzMsgCtx);
            if (OAuth2Util.checkUserNameAssertionEnabled()) {
                newAccessToken = OAuth2Util.addUsernameToToken(oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser(),
                        newAccessToken);
            }
            return newAccessToken;
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception("Error while generating new access token", e);
        }
    }

    private static String getNewRefreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, OauthTokenIssuer
            oauthIssuerImpl) throws IdentityOAuth2Exception {

        try {
            String refreshToken = oauthIssuerImpl.refreshToken(oauthAuthzMsgCtx);
            if (OAuth2Util.checkUserNameAssertionEnabled()) {
                refreshToken = OAuth2Util.addUsernameToToken(oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser(),
                        refreshToken);
            }
            return refreshToken;
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception("Error while generating new refresh token", e);
        }
    }

    private static void setRefreshTokenDetails(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, OAuthAppDO oAuthAppBean,
                                               AccessTokenDO existingTokenBean, AccessTokenDO newTokenBean,
                                               OauthTokenIssuer oauthIssuerImpl, Timestamp timestamp) throws
            IdentityOAuth2Exception {

        if (isRefreshTokenValid(existingTokenBean)) {
            setRefreshTokenDetailsFromExistingToken(existingTokenBean, newTokenBean);
        } else {
            newTokenBean.setRefreshTokenIssuedTime(timestamp);
            newTokenBean.setRefreshTokenValidityPeriodInMillis(getConfiguredRefreshTokenValidityPeriodInMillis
                    (oAuthAppBean));
            newTokenBean.setRefreshToken(getNewRefreshToken(oauthAuthzMsgCtx, oauthIssuerImpl));
        }
    }

    private static void setRefreshTokenDetailsFromExistingToken(AccessTokenDO existingTokenBean, AccessTokenDO
            newTokenBean) {

        newTokenBean.setRefreshToken(existingTokenBean.getRefreshToken());
        newTokenBean.setRefreshTokenIssuedTime(existingTokenBean.getRefreshTokenIssuedTime());
        newTokenBean.setRefreshTokenValidityPeriodInMillis(existingTokenBean.getRefreshTokenValidityPeriodInMillis());
    }

    private static void setDetailsToMessageContext(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO
            newTokenBean) {

        // Set the validity period. This is needed by downstream handlers.
        // Any value set before will be override by the calculated new value.
        oauthAuthzMsgCtx.setValidityPeriod(newTokenBean.getValidityPeriodInMillis());

        // Set the refresh token validity period. This is needed by downstream handlers.
        // Any value set before will be override by the calculated new value.
        oauthAuthzMsgCtx.setRefreshTokenvalidityPeriod(newTokenBean.getRefreshTokenValidityPeriodInMillis());

        // Set access token issued time. This is needed by downstream handlers.
        oauthAuthzMsgCtx.setAccessTokenIssuedTime(newTokenBean.getIssuedTime().getTime());

        // Set refresh token issued time. This is needed by downstream handlers.
        oauthAuthzMsgCtx.setRefreshTokenIssuedTime(newTokenBean.getRefreshTokenIssuedTime().getTime());

        oauthAuthzMsgCtx.addProperty(OAuth2Util.ACCESS_TOKEN_DO, newTokenBean);
    }

    private static void persistAccessTokenInDB(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO
            existingTokenBean, AccessTokenDO newTokenBean) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        storeAccessToken(authorizationReqDTO, getUserStoreDomain(authorizationReqDTO.getUser()), existingTokenBean,
                newTokenBean);
        if (log.isDebugEnabled()) {
            log.debug("Persisted Access Token for" + " Client ID: " + authorizationReqDTO.getConsumerKey() + ", " +
                    "Authorized User: " + authorizationReqDTO.getUser() + ", Is Federated User: " +
                    authorizationReqDTO.getUser().isFederatedUser() + ", Timestamp: " + newTokenBean.getIssuedTime()
                    + ", Validity period: " + newTokenBean.getValidityPeriod() + " s" + ", Scope: " + OAuth2Util
                    .buildScopeString(oauthAuthzMsgCtx.getApprovedScope()) + " and Token State: " + TOKEN_STATE_ACTIVE);
        }
    }

    private static void storeAccessToken(OAuth2AuthorizeReqDTO authorizationReqDTO, String userStoreDomain,
                                         AccessTokenDO existingTokenBean, AccessTokenDO newTokenBean) throws
            IdentityOAuth2Exception {

        try {
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().insertAccessToken(newTokenBean
                    .getAccessToken(), authorizationReqDTO.getConsumerKey(), newTokenBean, existingTokenBean,
                    userStoreDomain);
        } catch (IdentityException e) {
            String errorMsg;
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                errorMsg = "Error occurred while storing new access token(hashed) : " + DigestUtils.sha256Hex
                        (newTokenBean.getAccessToken());

            } else {
                errorMsg = "Error occurred while storing new access token.";
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    private static long getAccessTokenExpiryTimeMillis(AccessTokenDO tokenBean) throws IdentityOAuth2Exception {

        // Consider both access and refresh expiry time
        long expireTimeMillis = OAuth2Util.getTokenExpireTimeMillis(tokenBean);

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                if (expireTimeMillis > 0) {
                    log.debug("Access Token(hashed): " + DigestUtils.sha256Hex(tokenBean.getAccessToken()) + " is " +
                            "still valid. Remaining time: " + expireTimeMillis + " ms");
                } else {
                    log.debug("Infinite lifetime Access Token(hashed) " + DigestUtils.sha256Hex(tokenBean
                            .getAccessToken()) + " found");
                }
            } else {
                if (expireTimeMillis > 0) {
                    log.debug("Valid access token is found for client: " + tokenBean.getConsumerKey() + ". Remaining " +
                            "time: " + expireTimeMillis + " ms");
                } else {
                    log.debug("Infinite lifetime Access Token found for client: " + tokenBean.getConsumerKey());
                }
            }
        }
        return expireTimeMillis;
    }

    private static long getConfiguredAccessTokenValidityPeriodInMillis(OAuthAuthzReqMessageContext oauthAuthzMsgCtx,
                                                                       OAuthAppDO oAuthAppBean) throws
            IdentityOAuth2Exception {

        long validityPeriodInMillis;

        long callbackValidityPeriod = oauthAuthzMsgCtx.getAccessTokenValidityPeriod();
        if (callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD && callbackValidityPeriod > 0) {
            // If a valid validity period is set through the callback, use it.
            validityPeriodInMillis = callbackValidityPeriod * SECOND_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + oAuthAppBean.getOauthConsumerKey() + ", using access token " +
                        "validity period configured from callback: " + validityPeriodInMillis + " ms");
            }
        } else if (oAuthAppBean.getUserAccessTokenExpiryTime() != 0) {
            // Get user access token expiry time configured for OAuth application.
            validityPeriodInMillis = oAuthAppBean.getUserAccessTokenExpiryTime() * SECOND_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id: " + oAuthAppBean.getOauthConsumerKey() + ", using user access token " +
                        "" + "validity period configured for application: " + validityPeriodInMillis + " ms");
            }
        } else {
            // Get user access token expiry time configured over global configuration in identity.xml file.
            validityPeriodInMillis = OAuthServerConfiguration.getInstance().
                    getUserAccessTokenValidityPeriodInSeconds() * SECOND_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id: " + oAuthAppBean.getOauthConsumerKey() + ", using user access token " +
                        "" + "validity period configured for server: " + validityPeriodInMillis + " ms");
            }
        }

        return validityPeriodInMillis;
    }

    private static long getConfiguredRefreshTokenValidityPeriodInMillis(OAuthAppDO oAuthAppBean) {

        long refreshTokenValidityPeriodInMillis;
        if (oAuthAppBean.getRefreshTokenExpiryTime() != 0) {
            refreshTokenValidityPeriodInMillis = oAuthAppBean.getRefreshTokenExpiryTime() *
                    SECOND_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + oAuthAppBean.getOauthConsumerKey() + ", using refresh token " +
                        "validity period configured for application: " + refreshTokenValidityPeriodInMillis + " ms");
            }
        } else {
            refreshTokenValidityPeriodInMillis = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * SECOND_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id: " + oAuthAppBean.getOauthConsumerKey() + ", using refresh token " +
                        "validity period configured for server: " + refreshTokenValidityPeriodInMillis + " ms");
            }
        }
        return refreshTokenValidityPeriodInMillis;
    }

    private static boolean isAccessTokenValid(AccessTokenDO tokenBean) throws IdentityOAuth2Exception {

        if (tokenBean != null) {
            long expireTime = getAccessTokenExpiryTimeMillis(tokenBean);
            if (TOKEN_STATE_ACTIVE.equals(tokenBean.getTokenState()) && expireTime != 0) {
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                        log.debug("Access token(hashed): " + DigestUtils.sha256Hex(tokenBean.getAccessToken()) + " is" +
                                " not valid anymore");
                    } else {
                        log.debug("Latest access token in the database for client: " + tokenBean.getConsumerKey() + "" +
                                " is not valid anymore");
                    }
                }
            }
        }
        return false;
    }

    private static boolean isRefreshTokenValid(AccessTokenDO tokenBean) {

        if (tokenBean != null) {
            long refreshTokenExpireTime = OAuth2Util.getRefreshTokenExpireTimeMillis(tokenBean);
            if (TOKEN_STATE_ACTIVE.equals(tokenBean.getTokenState())) {
                String consumerKey = tokenBean.getConsumerKey();
                if (!isRefreshTokenExpired(tokenBean.getConsumerKey(), refreshTokenExpireTime)) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Existing access token(hashed): " + DigestUtils.sha256Hex(tokenBean
                                    .getAccessToken()) + " has expired, but refresh token(hashed):" + DigestUtils
                                    .sha256Hex(tokenBean.getRefreshToken()) + " is still valid for client: " +
                                    consumerKey + ". Remaining time: " + refreshTokenExpireTime + " ms. Using " +
                                    "existing refresh token.");

                        } else {
                            log.debug("Existing access token has expired, but refresh token is still valid for " +
                                    "client: " + consumerKey + ". Remaining time: " + refreshTokenExpireTime + "ms. "
                                    + "Using existing refresh token.");
                        }
                    }
                    return true;
                } else {
                    // no valid refresh token found in existing Token
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                            log.debug("Refresh token: " + tokenBean.getRefreshToken() + " for client: " + tokenBean
                                    .getConsumerKey() + " is expired. Issuing a new refresh token.");

                        } else {
                            log.debug("Refresh token for client: " + tokenBean.getConsumerKey() + " is expired. " +
                                    "Issuing a new refresh token.");
                        }
                    }
                }
            }
        }
        return false;
    }

    private static boolean isRefreshTokenExpired(String consumerKey, long refreshTokenExpireTime) {

        if (refreshTokenExpireTime < 0) {
            // refresh token has infinite validity
            if (log.isDebugEnabled()) {
                log.debug("Infinite lifetime Refresh Token found for client: " + consumerKey);
            }
            return false;
        }
        return !(refreshTokenExpireTime > 0);
    }

    private static OAuthAppDO getOAuthApp(String consumerKey) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppBean;
        try {
            oAuthAppBean = OAuth2Util.getAppInformationByClientId(consumerKey);
            if (log.isDebugEnabled()) {
                log.debug("Service Provider specific expiry time enabled for application : " + consumerKey + ". " +
                        "Application access token expiry time : " + oAuthAppBean.getApplicationAccessTokenExpiryTime
                        () + ", User access token expiry time : " + oAuthAppBean.getUserAccessTokenExpiryTime() + ", " +
                        "" + "Refresh token expiry time : " + oAuthAppBean.getRefreshTokenExpiryTime());
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId : " + consumerKey,
                    e);
        }
        return oAuthAppBean;
    }

    private static boolean isNotRenewAccessTokenPerRequest(OauthTokenIssuer oauthIssuerImpl) {

        boolean isRenew = oauthIssuerImpl.renewAccessTokenPerRequest();
        if (log.isDebugEnabled()) {
            log.debug("Enable Access Token renew per request: " + isRenew);
        }
        return !isRenew;
    }

    private static String getUserStoreDomain(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        String userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            //select the user store domain when multiple user stores are configured.
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                throw new IdentityOAuth2Exception("Error occurred while getting user store domain for user: " +
                        authenticatedUser, e);
            }
        }
        return userStoreDomain;
    }

    private static String getGrantType(String responseType) {

        String grantType;
        if (StringUtils.contains(responseType, OAuthConstants.GrantTypes.TOKEN)) {
            // This sets the grant type for implicit when response_type contains 'token' or 'id_token'.
            grantType = OAuthConstants.GrantTypes.IMPLICIT;
        } else {
            grantType = responseType;
        }

        return grantType;
    }

    private static OAuthCacheKey getOAuthCacheKey(String consumerKey, String scope, String authorizedUser) {

        String cacheKeyString = OAuth2Util.buildCacheKeyStringForToken(consumerKey, scope, authorizedUser);
        return new OAuthCacheKey(cacheKeyString);
    }

    private static void addTokenToCache(OAuthCacheKey cacheKey, AccessTokenDO tokenBean) {

        OAuthCache.getInstance().addToCache(cacheKey, tokenBean);
        // Adding AccessTokenDO to improve validation performance
        OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(tokenBean.getAccessToken());
        OAuthCache.getInstance().addToCache(accessTokenCacheKey, tokenBean);
        if (log.isDebugEnabled()) {
            log.debug("Access token info was added to the cache for cache key : " + cacheKey.getCacheKeyString());
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token was added to OAuthCache for cache key : " + accessTokenCacheKey
                        .getCacheKeyString());
            }
        }
    }

    private static void removeTokenFromCache(OAuthCacheKey cacheKey, AccessTokenDO tokenBean) {

        OAuthCache.getInstance().clearCacheEntry(cacheKey);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token(hashed): " + DigestUtils.sha256Hex(tokenBean.getAccessToken()) + " is expired" +
                        ". Therefore cleared it from cache.");
            } else {
                log.debug("Existing access token for client: " + tokenBean.getConsumerKey() + " is expired. " +
                        "Therefore cleared it from cache.");
            }
        }
    }

    private static void revokeExistingToken(String clientId, String accessToken) throws IdentityOAuth2Exception {

        // This is used to avoid client validation failure in revokeTokenByOAuthClient.
        // This will not affect the flow negatively as the client is already authenticated by this point.
        OAuthClientAuthnContext oAuthClientAuthnContext =
                buildAuthenticatedOAuthClientAuthnContext(clientId);

        OAuthRevocationRequestDTO revocationRequestDTO =
                OAuth2Util.buildOAuthRevocationRequest(oAuthClientAuthnContext, accessToken);

        OAuthRevocationResponseDTO revocationResponseDTO =
                getOauth2Service().revokeTokenByOAuthClient(revocationRequestDTO);

        if (revocationResponseDTO.isError()) {
            String msg = "Error while revoking tokens for clientId:" + clientId +
                    " Error Message:" + revocationResponseDTO.getErrorMsg();
            log.error(msg);
            throw new IdentityOAuth2Exception(msg);
        }
    }

    private static OAuth2Service getOauth2Service() {

        return (OAuth2Service) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
    }

    /**
     * This method is used to avoid client validation failure in OAuth2Service.revokeTokenByOAuthClient.
     *
     * @param clientId client id of the application.
     * @return Returns a OAuthClientAuthnContext with isAuthenticated set to true.
     */
    private static OAuthClientAuthnContext buildAuthenticatedOAuthClientAuthnContext(String clientId) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setClientId(clientId);

        return oAuthClientAuthnContext;
    }
}


