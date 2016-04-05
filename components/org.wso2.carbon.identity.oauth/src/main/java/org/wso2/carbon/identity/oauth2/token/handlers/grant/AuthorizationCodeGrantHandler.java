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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Base64;

/**
 * Implements the AuthorizationGrantHandler for the Grant Type : authorization_code.
 */
public class AuthorizationCodeGrantHandler extends AbstractAuthorizationGrantHandler {

    // This is used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    private static final String AUTHZ_CODE = "AuthorizationCode";

    private static Log log = LogFactory.getLog(AuthorizationCodeGrantHandler.class);
    private static AppInfoCache appInfoCache;

    public AuthorizationCodeGrantHandler() {
        appInfoCache = AppInfoCache.getInstance();
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!super.validateGrant(tokReqMsgCtx)) {
            return false;
        }

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String authorizationCode = oAuth2AccessTokenReqDTO.getAuthorizationCode();

        String clientId = oAuth2AccessTokenReqDTO.getClientId();

        AuthzCodeDO authzCodeDO = null;
        OAuthAppDO oAuthAppDO = null;
        // if cache is enabled, check in the cache first.
        if (cacheEnabled) {
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    clientId, authorizationCode));
            authzCodeDO = (AuthzCodeDO) oauthCache.getValueFromCache(cacheKey);
        }
        oAuthAppDO = appInfoCache.getValueFromCache(clientId);
        if (oAuthAppDO != null) {
            try {
                oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId);
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Invalid OAuth client", e);
            }
            appInfoCache.addToCache(clientId, oAuthAppDO);
        }
        if (log.isDebugEnabled()) {
            if (authzCodeDO != null) {
                log.debug("Authorization Code Info was available in cache for client id : "
                        + clientId);
            } else {
                log.debug("Authorization Code Info was not available in cache for client id : "
                        + clientId);
            }
        }

        // authz Code is not available in cache. check the database
        if (authzCodeDO == null) {
            authzCodeDO = tokenMgtDAO.validateAuthorizationCode(clientId, authorizationCode);
        }

        if (authzCodeDO != null && OAuthConstants.AuthorizationCodeState.INACTIVE.equals(authzCodeDO.getState())){
            String scope = OAuth2Util.buildScopeString(authzCodeDO.getScope());
            String authorizedUser = authzCodeDO.getAuthorizedUser().toString();
            boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
            String cacheKeyString;
            if (isUsernameCaseSensitive) {
                cacheKeyString = clientId + ":" + authorizedUser + ":" + scope;
            } else {
                cacheKeyString = clientId + ":" + authorizedUser.toLowerCase() + ":" + scope;
            }
            OAuthCacheKey cacheKey = new OAuthCacheKey(cacheKeyString);
            oauthCache.clearCacheEntry(cacheKey);
            if (log.isDebugEnabled()) {
                log.debug("Invalid access token request with inactive authorization code for Client Id : " + clientId);
            }
            return false;
        }

        //Check whether it is a valid grant
        if (authzCodeDO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid access token request with " +
                        "Client Id : " + clientId);
            }
            return false;
        }

        // Validate redirect_uri if it was presented in authorization request
        if (authzCodeDO.getCallbackUrl() != null && !authzCodeDO.getCallbackUrl().equals("")) {
            if (oAuth2AccessTokenReqDTO.getCallbackURI() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid access token request with " +
                            "Client Id : " + clientId +
                            "redirect_uri not present in request");
                }
                return false;
            } else if (!oAuth2AccessTokenReqDTO.getCallbackURI().equals(authzCodeDO.getCallbackUrl())) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid access token request with " +
                            "Client Id : " + clientId +
                            "redirect_uri does not match previously presented redirect_uri to authorization endpoint");
                }
                return false;
            }
        }

        // Check whether the grant is expired
        long issuedTimeInMillis = authzCodeDO.getIssuedTime().getTime();
        long validityPeriodInMillis = authzCodeDO.getValidityPeriod();
        long timestampSkew = OAuthServerConfiguration.getInstance()
                .getTimeStampSkewInSeconds() * 1000;
        long currentTimeInMillis = System.currentTimeMillis();

        // if authorization code is expired.
        if ((currentTimeInMillis - timestampSkew) > (issuedTimeInMillis + validityPeriodInMillis)) {
            if (log.isDebugEnabled()) {
                log.debug("Authorization Code is expired." +
                        " Issued Time(ms) : " + issuedTimeInMillis +
                        ", Validity Period : " + validityPeriodInMillis +
                        ", Timestamp Skew : " + timestampSkew +
                        ", Current Time : " + currentTimeInMillis);
            }

            // remove the authorization code from the database.
            tokenMgtDAO.expireAuthzCode(authorizationCode);
            if (log.isDebugEnabled()) {
                log.debug("Expired Authorization code" +
                        " issued for client " + clientId +
                        " was removed from the database.");
            }

            // remove the authorization code from the cache
            oauthCache.clearCacheEntry(new OAuthCacheKey(
                    OAuth2Util.buildCacheKeyStringForAuthzCode(clientId,
                            authorizationCode)));

            if (log.isDebugEnabled()) {
                log.debug("Expired Authorization code" +
                        " issued for client " + clientId +
                        " was removed from the cache.");
            }

            return false;
        }


        //Perform PKCE Validation for "Authorization Code" Grant Type
        String PKCECodeChallenge = authzCodeDO.getPkceCodeChallenge();
        String PKCECodeChallengeMethod = authzCodeDO.getPkceCodeChallengeMethod();
        String codeVerifier = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getPkceCodeVerifier();
        if (!doPKCEValidation(PKCECodeChallenge, codeVerifier, PKCECodeChallengeMethod, oAuthAppDO)) {
            //possible malicious oAuthRequest
            log.warn("Failed PKCE Verification for oAuth 2.0 request");
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Found an Authorization Code, " +
                    "Client : " + clientId +
                    ", authorized user : " + authzCodeDO.getAuthorizedUser() +
                    ", scope : " + OAuth2Util.buildScopeString(authzCodeDO.getScope()));
        }

        tokReqMsgCtx.setAuthorizedUser(authzCodeDO.getAuthorizedUser());
        tokReqMsgCtx.setScope(authzCodeDO.getScope());
        // keep the pre processed authz code as a OAuthTokenReqMessageContext property to avoid
        // calculating it again when issuing the access token.
        tokReqMsgCtx.addProperty(AUTHZ_CODE, authorizationCode);
        return true;
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);

        // get the token from the OAuthTokenReqMessageContext which is stored while validating
        // the authorization code.
        String authzCode = (String) tokReqMsgCtx.getProperty(AUTHZ_CODE);
        boolean existingTokenUsed = false;
        if (tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED) != null) {
            existingTokenUsed = (Boolean) tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED);
        }
        // if it's not there (which is unlikely), recalculate it.
        if (authzCode == null) {
            authzCode = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        }

        try {
            if (existingTokenUsed){
                //has given an already issued access token. So the authorization code is not deactivated yet
                tokenMgtDAO.deactivateAuthorizationCode(authzCode, tokenRespDTO.getTokenId());
            }
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception("Error occurred while deactivating authorization code", e);
        }

        // Clear the cache entry
        if (cacheEnabled) {
            String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    clientId, authzCode));
            oauthCache.clearCacheEntry(cacheKey);

            if (log.isDebugEnabled()) {
                log.debug("Cache was cleared for authorization code info for client id : " + clientId);
            }
        }

        return tokenRespDTO;
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        // authorization is handled when the authorization code was issued.
        return true;
    }

    @Override
    protected void storeAccessToken(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String userStoreDomain,
                                    AccessTokenDO newAccessTokenDO, String newAccessToken, AccessTokenDO
                                                existingAccessTokenDO)
            throws IdentityOAuth2Exception {
        try {
            newAccessTokenDO.setAuthorizationCode(oAuth2AccessTokenReqDTO.getAuthorizationCode());
            tokenMgtDAO.storeAccessToken(newAccessToken, oAuth2AccessTokenReqDTO.getClientId(),
                                         newAccessTokenDO, existingAccessTokenDO, userStoreDomain);
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while storing new access token", e);
        }
    }
    private boolean doPKCEValidation(String referenceCodeChallenge, String codeVerifier, String challenge_method, OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {
        if(oAuthAppDO.isPkceMandatory() || referenceCodeChallenge != null){

            //As per RFC 7636 Fallback to 'plain' if no code_challenge_method parameter is sent
            if(challenge_method == null || challenge_method.trim().length() == 0) {
                challenge_method = "plain";
            }

            //if app with no PKCE code verifier arrives
            if ((codeVerifier == null || codeVerifier.trim().length() == 0)) {
                //if pkce is mandatory, throw error
                if(oAuthAppDO.isPkceMandatory()) {
                    throw new IdentityOAuth2Exception("No PKCE code verifier found.PKCE is mandatory for this " +
                            "oAuth 2.0 application.");
                } else {
                    //PKCE is optional, see if the authz code was requested with a PKCE challenge
                    if(referenceCodeChallenge == null || referenceCodeChallenge.trim().length() == 0) {
                        //since no PKCE challenge was provided
                        return true;
                    } else {
                        throw new IdentityOAuth2Exception("Empty PKCE code_verifier sent. This authorization code " +
                                "requires a PKCE verification to obtain an access token.");
                    }
                }
            }
            //verify that the code verifier is upto spec as per RFC 7636
            if(!codeVerifier.matches("[\\w\\-\\._~]+") || (codeVerifier.length() < 43 || codeVerifier.length() > 128)) {
                throw new IdentityOAuth2Exception("Code verifier used is not up to RFC 7636 specifications.");
            }
            if (OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(challenge_method)) {
                //if the current applicatoin explicitly doesn't support plain, throw exception
                if(!oAuthAppDO.isPkceSupportPlain()) {
                    throw new IdentityOAuth2Exception("This application does not allow 'plain' transformation algorithm.");
                }
                if (!referenceCodeChallenge.equals(codeVerifier)) {
                    return false;
                }
            } else if (OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(challenge_method)) {

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

                    byte[] hash = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                    //Trim the base64 string to remove trailing CR LF characters.
                    String referencePKCECodeChallenge = new String(Base64.encodeBase64URLSafe(hash),
                            StandardCharsets.UTF_8).trim();
                    if (!referencePKCECodeChallenge.equals(referenceCodeChallenge)) {
                        return false;
                    }
                } catch (NoSuchAlgorithmException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to create SHA256 Message Digest.");
                    }
                    return false;
                }
            } else {
                //Invalid OAuth2 token response
                throw new IdentityOAuth2Exception("Invalid OAuth2 Token Response. Invalid PKCE Code Challenge Method '"
                        + challenge_method + "'. Server only supports plain, S256 transformation algorithms.");
            }
        }
        //pkce validation sucessfull
        return true;
    }
}
