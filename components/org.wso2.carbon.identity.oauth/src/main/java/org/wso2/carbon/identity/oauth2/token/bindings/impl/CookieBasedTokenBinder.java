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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.core.SameSiteCookie;
import org.wso2.carbon.core.ServletCookie;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuthSystemClientException;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.COOKIE_BASED_TOKEN_BINDER;

/**
 * This class provides the cookie based token binder implementation.
 */
public class CookieBasedTokenBinder extends AbstractTokenBinder {

    private static final String COOKIE_NAME = "atbv";

    private List<String> supportedGrantTypes = Collections.singletonList(AUTHORIZATION_CODE);

    @Override
    public String getBindingType() {

        return COOKIE_BASED_TOKEN_BINDER;
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        return Collections.unmodifiableList(supportedGrantTypes);
    }

    @Override
    public String getDisplayName() {

        return "Cookie Based";
    }

    @Override
    public String getDescription() {

        return "Bind token to the browser cookie. Supported grant types: Code";
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        String tokenBindingValue = retrieveTokenBindingValueFromRequest(request);

        if (StringUtils.isNotBlank(tokenBindingValue)) {
            return tokenBindingValue;
        } else {
            return UUID.randomUUID().toString();
        }
    }

    @Override
    public String getTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        String tokenBindingValue = retrieveTokenBindingValueFromRequest(request);

        if (StringUtils.isNotBlank(tokenBindingValue)) {
            return tokenBindingValue;
        } else {
            throw new OAuthSystemClientException("Failed to retrieve token binding value.");
        }
    }

    private String retrieveTokenBindingValueFromRequest(HttpServletRequest request) throws OAuthSystemException {

        Cookie[] cookies = request.getCookies();
        if (ArrayUtils.isEmpty(cookies)) {
            return null;
        }

        Optional<Cookie> tokenBindingCookieOptional = Arrays.stream(cookies)
                .filter(t -> COOKIE_NAME.equals(t.getName())).findAny();
        if (!tokenBindingCookieOptional.isPresent() || StringUtils
                .isBlank(tokenBindingCookieOptional.get().getValue())) {
            return null;
        }

        String tokenBindingValue = tokenBindingCookieOptional.get().getValue();
        boolean isTokenBindingValueValid;
        try {
            // Do we need additional validation here? like validate local user.
            isTokenBindingValueValid = OAuthTokenPersistenceFactory.getInstance().getTokenBindingMgtDAO()
                    .isTokenBindingExistsForBindingReference(OAuth2Util.getTokenBindingReference(tokenBindingValue));
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException("Failed to check token binding reference existence", e);
        }

        return isTokenBindingValueValid ? tokenBindingValue : null;
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue) {

        ServletCookie cookie = new ServletCookie(COOKIE_NAME, bindingValue);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSameSite(SameSiteCookie.NONE);
        response.addCookie(cookie);
    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {
        // Not required as we not clear the atbv cookie from the browser.
    }

    @Override
    public boolean isValidTokenBinding(Object request, String bindingReference) {

        return isValidTokenBinding(request, bindingReference, COOKIE_NAME);
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        return isValidTokenBinding(oAuth2AccessTokenReqDTO, bindingReference, COOKIE_NAME);
    }
}
