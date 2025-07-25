/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;

import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.IS_REQUEST_OBJECT_FLOW;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.NEW_ACCESS_TOKEN;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.OLD_ACCESS_TOKEN;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.TOKEN_STATE;

/**
 * Utility methods for OAuth token related functions.
 */
public class OAuth2TokenUtil {

    private static final Log log = LogFactory.getLog(OAuth2TokenUtil.class);

    /**
     * Uses to update access token details in the request object reference table.
     *
     * @param tokenId        token id
     * @param sessionDataKey session data key
     * @throws IdentityOAuth2Exception
     */
    public static void postIssueAccessToken(String tokenId, String sessionDataKey) throws
            IdentityOAuth2Exception {

        String eventName = OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(OIDCConstants.Event.TOKEN_ID, tokenId);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        Event requestObjectPersistanceEvent = new Event(eventName, properties);
        IdentityEventService identityEventService = OpenIDConnectServiceComponentHolder.getIdentityEventService();
        try {
            if (identityEventService != null) {
                identityEventService.handleEvent(requestObjectPersistanceEvent);
                if (log.isDebugEnabled()) {
                    log.debug("The event " + eventName + " triggered after the access token " + tokenId +
                            " is issued.");
                }
            }
        } catch (IdentityEventException e) {
            throw new IdentityOAuth2Exception("Error while invoking the request object persistance handler when " +
                    "issuing the access token id: " + tokenId);
        }
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokenId
     * @throws IdentityOAuth2Exception
     * @deprecated to use {{@link #postUpdateAccessToken(String, String, boolean)}}
     */
    public static void postUpdateAccessToken(String acessTokenId, String tokenState)
            throws IdentityOAuth2Exception {
        postUpdateAccessToken(acessTokenId, tokenState, true);
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param accessTokenId
     * @param isRequestObjectFlow whether the request object is included.
     * @throws IdentityOAuth2Exception
     */
    public static void postUpdateAccessToken(String accessTokenId, String tokenState, boolean isRequestObjectFlow)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();

        if (StringUtils.isNotBlank(accessTokenId)) {
            eventName = OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN_BY_ID;
            properties.put(TOKEN_STATE, tokenState);
            properties.put(OIDCConstants.Event.TOKEN_ID, accessTokenId);
            properties.put(IS_REQUEST_OBJECT_FLOW, isRequestObjectFlow);
        }
        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokens
     * @throws IdentityOAuth2Exception
     */
    public static void postUpdateAccessTokens(List<String> acessTokens, String tokenState)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (CollectionUtils.isNotEmpty(acessTokens)) {
            eventName = OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN;
            properties.put(TOKEN_STATE, tokenState);
            properties.put(OIDCConstants.Event.ACEESS_TOKENS, acessTokens);
        }
        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokenId
     * @throws IdentityOAuth2Exception
     * @deprecated to use {{@link #postRefreshAccessToken(String, String, String, boolean)}}
     */
    public static void postRefreshAccessToken(String oldAcessTokenId, String acessTokenId, String tokenState)
            throws IdentityOAuth2Exception {
        postRefreshAccessToken(oldAcessTokenId, acessTokenId, tokenState, true);
    }

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokenId
     * @throws IdentityOAuth2Exception
     */
    public static void postRefreshAccessToken(String oldAcessTokenId, String acessTokenId, String tokenState,
                                              boolean isRequestObjectFlow) throws IdentityOAuth2Exception {

        String eventName;
        HashMap<String, Object> properties = new HashMap<>();
        if (StringUtils.isNotBlank(acessTokenId)) {
            properties.put(OLD_ACCESS_TOKEN, oldAcessTokenId);
            properties.put(NEW_ACCESS_TOKEN, acessTokenId);
            properties.put(IS_REQUEST_OBJECT_FLOW, isRequestObjectFlow);
        }
        eventName = OIDCConstants.Event.POST_REFRESH_TOKEN;
        triggerEvent(eventName, properties);
    }


    /**
     * Uses to revoke codes from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param codeId     code id
     * @param tokenState
     * @param tokenId
     * @throws IdentityOAuth2Exception
     *
     * @deprecated to use {{@link #postRevokeCode(String, String, String, String)}}
     */
    @Deprecated
    public static void postRevokeCode(String codeId, String tokenState, String tokenId)
            throws IdentityOAuth2Exception {

        postRevokeCode(codeId, tokenState, tokenId, StringUtils.EMPTY);
    }

    /**
     * Uses to revoke codes from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param codeId     code id
     * @param tokenState
     * @param tokenId
     * @param authorizationCode
     * @throws IdentityOAuth2Exception
     */
    public static void postRevokeCode(String codeId, String tokenState, String tokenId, String authorizationCode)
            throws IdentityOAuth2Exception {

        boolean isRequestObjectFlow = true;
        if (StringUtils.isNotBlank(authorizationCode)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
            if (cacheEntry != null) {
                isRequestObjectFlow = cacheEntry.isRequestObjectFlow();
            }
        }
        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (StringUtils.isNotBlank(codeId)) {
            properties.put(OIDCConstants.Event.TOKEN_STATE, tokenState);
            properties.put(OIDCConstants.Event.TOKEN_ID, tokenId);
            properties.put(OIDCConstants.Event.CODE_ID, codeId);
            properties.put(OIDCConstants.Event.IS_REQUEST_OBJECT_FLOW, isRequestObjectFlow);
            eventName = OIDCConstants.Event.POST_REVOKE_CODE_BY_ID;
        }

        triggerEvent(eventName, properties);
    }

    /**
     * Uses to revoke codes from the request object related tables after token revocation
     * happens from access token related tables.
     * @param authzCodeDOs authzCodeDOs
     * @param tokenState state of the token
     * @throws IdentityOAuth2Exception
     */
    public static void postRevokeCodes(List<AuthzCodeDO> authzCodeDOs, String tokenState)
            throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (CollectionUtils.isNotEmpty(authzCodeDOs)) {
            properties.put(OIDCConstants.Event.TOKEN_STATE, tokenState);
            eventName = OIDCConstants.Event.POST_REVOKE_CODE;
            properties.put(OIDCConstants.Event.CODES, authzCodeDOs);
        }

        triggerEvent(eventName, properties);
    }

    /**
     * Get JWT claim set from the token.
     *
     * @param token The token string.
     * @return JWT claim set.
     * @throws IdentityOAuth2Exception Throws if an error occurred while preparing the JWT claim set.
     */
    public static JWTClaimsSet getJWTClaimSet(String token) throws IdentityOAuth2Exception {

        if (StringUtils.isNotBlank(token)) {
            SignedJWT signedJWT = OAuth2TokenUtil.getSignedJWT(token);
            if (signedJWT != null) {
                return OAuth2TokenUtil.getClaimSet(signedJWT);
            }
        }
        return null;
    }

    /**
     * Get signed JWT from the token.
     *
     * @param token token
     * @return Signed JWT
     * @throws IdentityOAuth2Exception Throws if an error occurred while parsing the JWT.
     */
    public static SignedJWT getSignedJWT(String token) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        if (StringUtils.isBlank(token)) {
            return null;
        }
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while parsing the JWT", e);
        }
        return signedJWT;
    }

    /**
     * Get claim set from the signed JWT.
     *
     * @param signedJWT signed JWT.
     * @return JWT Claims Set.
     * @throws IdentityOAuth2Exception Throws if an error occurred while retrieving the claim set.
     */
    public static JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        if (signedJWT == null) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                    "No valid JWT is found.");
        }
        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Claim values are empty in the given JSON Web Token");
            }
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Error when retrieving claimsSet from the JWT", e);
        }
        return claimsSet;
    }

    private static void triggerEvent(String eventName, HashMap<String, Object> properties)
            throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isNotBlank(eventName)) {
                Event requestObjectPersistanceEvent = new Event(eventName, properties);
                IdentityEventService identityEventService =
                        OpenIDConnectServiceComponentHolder.getIdentityEventService();
                if (identityEventService != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("The event: " + eventName + " triggered.");
                    }

                    identityEventService.handleEvent(requestObjectPersistanceEvent);
                }
            }
        } catch (IdentityEventException e) {
            String message = "Error while triggering the event: " + eventName;
            log.error(message, e);
            throw new IdentityOAuth2Exception(message, e);
        }
    }

    /**
     * Uses to trigger an event once the code is issued.
     *
     * @param codeId         code id
     * @param sessionDataKey session data key
     * @throws IdentityOAuth2Exception
     *
     * @deprecated to use {{@link #postRevokeCode(String, String, String, String)}}
     */
    @Deprecated
    public static void postIssueCode(String codeId, String sessionDataKey)
            throws IdentityOAuth2Exception {

        postIssueCode(codeId, sessionDataKey, true);
    }

    /**
     * Uses to trigger an event once the code is issued.
     *
     * @param codeId                    code id
     * @param sessionDataKey            session data key
     * @param isRequestObjectFlow       whether the request object is included.
     * @throws IdentityOAuth2Exception
     */
    public static void postIssueCode(String codeId, String sessionDataKey, boolean isRequestObjectFlow)
            throws IdentityOAuth2Exception {

        String eventName = OIDCConstants.Event.POST_ISSUE_CODE;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(OIDCConstants.Event.CODE_ID, codeId);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        properties.put(OIDCConstants.Event.IS_REQUEST_OBJECT_FLOW, isRequestObjectFlow);
        triggerEvent(eventName, properties);
    }

}

