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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.openidconnect.AbstractUserInfoResponseBuilder;

import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.collections.MapUtils.isEmpty;

/**
 * Builds user info response as a JSON string according to
 * http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
 */
public class UserInfoJSONResponseBuilder extends AbstractUserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(UserInfoJSONResponseBuilder.class);

    @Override
    protected Map<String, Object> retrieveUserClaims(OAuth2TokenValidationResponseDTO tokenValidationResponse)
            throws UserInfoEndpointException {

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenValidationResponse);
        Map<String, Object> claims;

        if (isEmpty(userAttributes)) {
            claims = ClaimUtil.getClaimsFromUserStore(tokenValidationResponse);
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Trying to retrieve from user store.");
            }
        } else {
            UserInfoClaimRetriever retriever = UserInfoEndpointConfig.getInstance().getUserInfoClaimRetriever();
            claims = retriever.getClaimsMap(userAttributes);
        }

        if (claims == null) {
            claims = new HashMap<>();
        }

        return claims;
    }

    @Override
    protected String buildResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                   String spTenantDomain,
                                   Map<String, Object> filteredUserClaims) throws UserInfoEndpointException {
        return JSONUtils.buildJSON(filteredUserClaims);
    }

    private Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse) {
        AuthorizationGrantCacheKey cacheKey =
                new AuthorizationGrantCacheKey(tokenResponse.getAuthorizationContextToken().getTokenString());
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);

        if (cacheEntry == null) {
            return new HashMap<>();
        }

        return cacheEntry.getUserAttributes();
    }


}
