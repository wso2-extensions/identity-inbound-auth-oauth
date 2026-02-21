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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;

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

    /**
     * Check validity of the token binding.
     *
     * @param request request object.
     * @param bindingReference token binding reference
     * @param cookieName cookie name
     * @return true if token binding is valid.
     */
    protected boolean isValidTokenBinding(Object request, String bindingReference, String cookieName) {

        if (request == null || StringUtils.isBlank(bindingReference) || StringUtils.isBlank(cookieName)) {
            return false;
        }

        if (request instanceof HttpServletRequest) {
            return isValidTokenBinding((HttpServletRequest) request, bindingReference);
        } else if (request instanceof OAuth2AccessTokenReqDTO) {
            return isValidTokenBinding((OAuth2AccessTokenReqDTO) request, bindingReference, cookieName);
        }

        throw new RuntimeException("Unsupported request type: " + request.getClass().getName());
    }

    private boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference,
            String cookieName) {

        if (REFRESH_TOKEN.equals(oAuth2AccessTokenReqDTO.getGrantType())) {
            Optional<String> tokenBindingValueOptional = OAuth2Util.getTokenBindingValue(oAuth2AccessTokenReqDTO,
                    cookieName);
            if (tokenBindingValueOptional.isPresent()) {
                String tokenBindingValue = tokenBindingValueOptional.get();
                String receivedBindingReference = OAuth2Util.getTokenBindingReference(tokenBindingValue);
                return bindingReference.equals(receivedBindingReference);
            }

            return false;
        }

        throw new RuntimeException("Unsupported grant type: " + oAuth2AccessTokenReqDTO.getGrantType());
    }

    private boolean isValidTokenBinding(HttpServletRequest request, String bindingReference) {

        String tokenBindingValue;
        try {
            tokenBindingValue = getTokenBindingValue(request);
        } catch (OAuthSystemException e) {
            return false;
        }

        return bindingReference.equals(OAuth2Util.getTokenBindingReference(tokenBindingValue));
    }
}
