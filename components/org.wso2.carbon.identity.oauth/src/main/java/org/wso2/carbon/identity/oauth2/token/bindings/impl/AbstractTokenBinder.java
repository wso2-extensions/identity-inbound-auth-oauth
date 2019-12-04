/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;

import java.util.Optional;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;

/**
 * This class provides the abstract token binder implementation.
 */
public abstract class AbstractTokenBinder implements TokenBinder {

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        if (AUTHORIZATION_CODE.equals(oAuth2AccessTokenReqDTO.getGrantType()) && StringUtils
                .isNotBlank(oAuth2AccessTokenReqDTO.getAuthorizationCode())) {

            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(
                    oAuth2AccessTokenReqDTO.getAuthorizationCode());
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry = AuthorizationGrantCache.getInstance()
                    .getValueFromCacheByCode(cacheKey);
            if (authorizationGrantCacheEntry != null && StringUtils
                    .isNotBlank(authorizationGrantCacheEntry.getTokenBindingValue())) {
                return Optional.of(authorizationGrantCacheEntry.getTokenBindingValue());
            }
        }

        return Optional.empty();
    }
}
