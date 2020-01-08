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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.COMMONAUTH_COOKIE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;

/**
 * This class provides the sso session based token binder implementation. This will generate new access token for
 * each new session.
 */
public class SSOSessionBasedTokenBinder extends AbstractTokenBinder {

    private static final String BINDING_TYPE = "sso-session";

    private List<String> supportedGrantTypes = Collections.singletonList(AUTHORIZATION_CODE);

    @Override
    public String getDisplayName() {

        return "SSO Session Based";
    }

    @Override
    public String getDescription() {

        return "Bind token to the SSO session. Supported grant types: Code";
    }

    @Override
    public String getBindingType() {

        return BINDING_TYPE;
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        return Collections.unmodifiableList(supportedGrantTypes);
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        Cookie[] cookies = request.getCookies();
        if (ArrayUtils.isEmpty(cookies)) {
            throw new OAuthSystemException("Failed to retrieve token binding value.");
        }

        Optional<Cookie> commonAuthCookieOptional = Arrays.stream(cookies)
                .filter(t -> COMMONAUTH_COOKIE.equals(t.getName())).findAny();
        if (!commonAuthCookieOptional.isPresent() || StringUtils.isBlank(commonAuthCookieOptional.get().getValue())) {
            throw new OAuthSystemException("Failed to retrieve token binding value.");
        }

        // Get the session context key value form common auth cookie value.
        return DigestUtils.sha256Hex(commonAuthCookieOptional.get().getValue());
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue) {

        // Not required.
    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {

        // Not required.
    }

    @Override
    public boolean isValidTokenBinding(Object request, String bindingReference) {

        return true;
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        return true;
    }
}
