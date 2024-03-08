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
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used to get the federated tokens for the token response.
 * This expects the authorization code is available in the token request message context
 * so that the federated tokens can be retrieved from the auth grant cache.
 */
public class FederatedTokenResponseHandler implements AccessTokenResponseHandler {

    private static final Log LOG = LogFactory.getLog(FederatedTokenResponseHandler.class);

    /**
     * This method returns the federated tokens in the auth grant cache.
     *
     * @param tokReqMsgCtx {@link OAuthTokenReqMessageContext} Token request message context with a token request DTO.
     * @return Map of the federated tokens.
     */
    @Override
    public Map<String, Object> getAdditionalTokenResponseAttributes(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (StringUtils.isBlank(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode())) {
            return null;
        }
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByCode(new AuthorizationGrantCacheKey(
                        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode()));

        if (cacheEntry == null) {
            return null;
        }

        List<FederatedTokenDO> federatedTokens = cacheEntry.getFederatedTokens();
        if (CollectionUtils.isEmpty(federatedTokens)) {
            return null;
        }
        // Removing the federated token from the session cache entry since it is no longer required.
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
}
