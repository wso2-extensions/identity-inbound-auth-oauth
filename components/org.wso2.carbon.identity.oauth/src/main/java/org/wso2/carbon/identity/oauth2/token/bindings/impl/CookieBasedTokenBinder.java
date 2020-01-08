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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * This class provides the cookie based token binder implementation.
 */
public class CookieBasedTokenBinder extends AbstractTokenBinder {

    private static final String BINDING_TYPE = "cookie";

    private static final String COOKIE_NAME = "atbv";

    private List<String> supportedGrantTypes = Collections.singletonList(AUTHORIZATION_CODE);

    @Override
    public String getBindingType() {

        return BINDING_TYPE;
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

        Cookie[] cookies = request.getCookies();
        if (ArrayUtils.isEmpty(cookies)) {
            return UUID.randomUUID().toString();
        }

        Optional<Cookie> tokenBindingCookieOptional = Arrays.stream(cookies)
                .filter(t -> COOKIE_NAME.equals(t.getName())).findAny();
        if (!tokenBindingCookieOptional.isPresent() || StringUtils
                .isBlank(tokenBindingCookieOptional.get().getValue())) {
            return UUID.randomUUID().toString();
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

        if (isTokenBindingValueValid) {
            return tokenBindingValue;
        }
        return UUID.randomUUID().toString();
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue) {

        Cookie cookie = new Cookie(COOKIE_NAME, bindingValue);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();
        if (ArrayUtils.isNotEmpty(cookies)) {
            Arrays.stream(cookies).filter(t -> COOKIE_NAME.equals(t.getName())).findAny().ifPresent(cookie -> {
                cookie.setMaxAge(0);
                cookie.setSecure(true);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                response.addCookie(cookie);
            });
        }
    }

    @Override
    public boolean isValidTokenBinding(Object request, String bindingReference) {

        if (request == null || StringUtils.isBlank(bindingReference)) {
            return false;
        }

        if (request instanceof HttpServletRequest) {
            Cookie[] cookies = ((HttpServletRequest) request).getCookies();
            if (ArrayUtils.isEmpty(cookies)) {
                return false;
            }

            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return bindingReference.equals(OAuth2Util.getTokenBindingReference(cookie.getValue()));
                }
            }
        }

        throw new RuntimeException("Unsupported request type: " + request.getClass().getName());
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        if (StringUtils.isBlank(bindingReference) || NONE.equals(bindingReference)) {
            return true;
        }

        if (REFRESH_TOKEN.equals(oAuth2AccessTokenReqDTO.getGrantType())) {

            HttpRequestHeader[] httpRequestHeaders = oAuth2AccessTokenReqDTO.getHttpRequestHeaders();
            if (ArrayUtils.isEmpty(httpRequestHeaders)) {
                return false;
            }

            for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
                if (HttpHeaders.COOKIE.equalsIgnoreCase(httpRequestHeader.getName())) {
                    if (ArrayUtils.isEmpty(httpRequestHeader.getValue())) {
                        return false;
                    }

                    String[] cookies = httpRequestHeader.getValue()[0].split(";");
                    String cookiePrefix = COOKIE_NAME + "=";
                    for (String cookie : cookies) {
                        if (StringUtils.isNotBlank(cookie) && cookie.trim().startsWith(cookiePrefix)) {
                            String receivedBindingReference = OAuth2Util
                                    .getTokenBindingReference(HttpCookie.parse(cookie).get(0).getValue());
                            return bindingReference.equals(receivedBindingReference);
                        }
                    }
                }
            }
        }
        return false;
    }
}
