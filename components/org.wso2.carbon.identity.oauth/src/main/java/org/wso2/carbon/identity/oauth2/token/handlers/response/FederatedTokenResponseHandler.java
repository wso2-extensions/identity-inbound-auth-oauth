/*
 *
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.oauth2.token.handlers.response;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedToken;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
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

        List<FederatedToken> federatedTokens = cacheEntry.getFederatedTokens();
        if (CollectionUtils.isEmpty(federatedTokens)) {
            return null;
        }
        // Removing the federated token from the auth grant cache entry since it is no longer required.
        cacheEntry.setFederatedTokens(null);
        // Add federated tokens to the token response if available.
        Map<String, Object> additionalAttributes = new HashMap<>();

        additionalAttributes.putIfAbsent(DefaultAuthenticationRequestHandler.FEDERATED_TOKENS, federatedTokens);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Federated tokens will be added to the additional attributes of the token response.");
        }

        return additionalAttributes;
    }
}
