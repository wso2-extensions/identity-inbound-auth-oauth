/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.response;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.model.FederatedTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used to get the federated tokens for the token response.
 * This supports both authorization code grant (where federated tokens are cached by authorization code)
 * and CIBA grant (where federated tokens are cached by auth_req_id).
 */
public class FederatedTokenResponseHandler implements AccessTokenResponseHandler {

    private static final Log LOG = LogFactory.getLog(FederatedTokenResponseHandler.class);
    private static final String CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    private static final String AUTH_REQ_ID = "auth_req_id";

    /**
     * This method returns the federated tokens in the auth grant cache.
     *
     * @param tokReqMsgCtx {@link OAuthTokenReqMessageContext} Token request message context with a token request DTO.
     * @return Map of the federated tokens.
     */
    @Override
    public Map<String, Object> getAdditionalTokenResponseAttributes(OAuthTokenReqMessageContext tokReqMsgCtx) {

        AuthorizationGrantCacheEntry cacheEntry = getCacheEntry(tokReqMsgCtx);
        if (cacheEntry == null) {
            return null;
        }

        List<FederatedTokenDO> federatedTokens = cacheEntry.getFederatedTokens();
        if (CollectionUtils.isEmpty(federatedTokens)) {
            return null;
        }
        // Removing the federated token from the cache entry since it is no longer required.
        cacheEntry.setFederatedTokens(null);
        // Add federated tokens to the token response if available.
        Map<String, Object> additionalAttributes = new HashMap<>();

        additionalAttributes.putIfAbsent(FrameworkConstants.FEDERATED_TOKENS, federatedTokens);
        if (LOG.isDebugEnabled() && tokReqMsgCtx.getAuthorizedUser() != null) {
            LOG.debug("Federated tokens will be added to the additional attributes of the token response." +
                    " for the user: " + tokReqMsgCtx.getAuthorizedUser().getLoggableMaskedUserId());
        }

        return additionalAttributes;
    }

    /**
     * Retrieves the AuthorizationGrantCacheEntry based on the grant type.
     * For authorization code grant, the cache entry is looked up by authorization code.
     * For CIBA grant, the cache entry is looked up by auth_req_id.
     *
     * @param tokReqMsgCtx Token request message context.
     * @return AuthorizationGrantCacheEntry or null if not found.
     */
    private AuthorizationGrantCacheEntry getCacheEntry(OAuthTokenReqMessageContext tokReqMsgCtx) {

        String authorizationCode = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        if (StringUtils.isNotBlank(authorizationCode)) {
            return AuthorizationGrantCache.getInstance().getValueFromCacheByCode(
                    new AuthorizationGrantCacheKey(authorizationCode));
        }

        // For CIBA grant, look up the cache entry by auth_req_id.
        if (CIBA_GRANT_TYPE.equals(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
            String authReqId = getAuthReqId(tokReqMsgCtx);
            if (StringUtils.isNotBlank(authReqId)) {
                return AuthorizationGrantCache.getInstance().getValueFromCache(
                        new AuthorizationGrantCacheKey(authReqId));
            }
        }
        return null;
    }

    /**
     * Extracts the auth_req_id from the CIBA token request parameters.
     *
     * @param tokReqMsgCtx Token request message context.
     * @return The auth_req_id value, or null if not found.
     */
    private String getAuthReqId(OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        if (parameters == null) {
            return null;
        }
        for (RequestParameter parameter : parameters) {
            if (AUTH_REQ_ID.equals(parameter.getKey()) && parameter.getValue() != null
                    && parameter.getValue().length > 0) {
                return parameter.getValue()[0];
            }
        }
        return null;
    }
}
