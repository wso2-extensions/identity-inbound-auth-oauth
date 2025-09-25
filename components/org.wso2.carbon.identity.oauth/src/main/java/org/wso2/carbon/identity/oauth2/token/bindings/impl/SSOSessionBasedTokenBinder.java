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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;

/**
 * This class provides the sso session based token binder implementation. This will generate new access token for
 * each new session.
 */
public class SSOSessionBasedTokenBinder extends AbstractTokenBinder {

    private List<String> supportedGrantTypes = Collections.singletonList(AUTHORIZATION_CODE);
    private static final String COMMONAUTH_COOKIE = "commonAuthId";
    private static final Log log = LogFactory.getLog(SSOSessionBasedTokenBinder.class);

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

        return OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER;
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        return Collections.unmodifiableList(supportedGrantTypes);
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        return retrieveTokenBindingValueFromRequest(request);
    }

    @Override
    public String getTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        return retrieveTokenBindingValueFromRequest(request);
    }

    private String retrieveTokenBindingValueFromRequest(HttpServletRequest request) throws OAuthSystemException {

        if (Boolean.TRUE.equals(request.getAttribute(OAuthConstants.IS_API_BASED_LOGOUT_WITHOUT_COOKIES))) {
            // The session id is a sha256Hex of the commonAuthId cookie value.
            return request.getParameter(FrameworkConstants.RequestParams.SESSION_ID);
        }
        Cookie[] cookies = request.getCookies();
        String commonAuthCookieValueFromRequestAttribute = (String) request.getAttribute(COMMONAUTH_COOKIE);
        if (ArrayUtils.isNotEmpty(cookies)) {
            Optional<Cookie> commonAuthCookieOptional = Arrays.stream(cookies)
                    .filter(t -> COMMONAUTH_COOKIE.equals(t.getName())).findAny();

            if (commonAuthCookieOptional.isPresent() &&
                    StringUtils.isNotBlank(commonAuthCookieOptional.get().getValue())) {
                return DigestUtils.sha256Hex(commonAuthCookieOptional.get().getValue());
            }
        }
        if (StringUtils.isNotEmpty(commonAuthCookieValueFromRequestAttribute)) {
            return DigestUtils.sha256Hex(commonAuthCookieValueFromRequestAttribute);
        }
        throw new OAuthSystemException("Failed to retrieve token binding value.");
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

        try {
            String sessionIdentifier = getTokenBindingValue((HttpServletRequest) request);
            if (StringUtils.isBlank(sessionIdentifier)) {
                if (log.isDebugEnabled()) {
                    log.debug("CommonAuthId cookie is not found in the request.");
                }
                return false;
            }
            if (!isValidSession(sessionIdentifier, FrameworkUtils.getLoginTenantDomainFromContext())) {
                return false;
            }
        } catch (OAuthSystemException e) {
            log.error("Error while getting the token binding value", e);
            return false;
        }
        return isValidTokenBinding(request, bindingReference, COMMONAUTH_COOKIE);
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        return isValidTokenBinding(oAuth2AccessTokenReqDTO, bindingReference, COMMONAUTH_COOKIE);
    }

    @Override
    public boolean isValidTokenBinding(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null || accessTokenDO.getTokenBinding() == null ||
                StringUtils.isBlank(accessTokenDO.getTokenBinding().getBindingValue())) {
            if (log.isDebugEnabled()) {
                log.debug("No token binding value is found for SSO session bound token.");
            }
            return false;
        }
        String sessionIdentifier = accessTokenDO.getTokenBinding().getBindingValue();
        return isValidSession(sessionIdentifier, resolveTenantDomain(accessTokenDO));
    }

    /**
     * Checks if the session is valid by retrieving the session context information using the session identifier.
     *
     * @param sessionIdentifier The session identifier from the token binding.
     * @param tenantDomain      The tenant domain extracted from the access token owner.
     * @return true if the session is valid, false otherwise.
     */
    private boolean isValidSession(String sessionIdentifier, String tenantDomain) {

        SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(sessionIdentifier, tenantDomain);
        if (sessionContext == null) {
            if (log.isDebugEnabled()) {
                log.debug("Session context is not found corresponding to the session identifier: " +
                        sessionIdentifier);
            }
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("SSO session validation successful for the given session identifier: " + sessionIdentifier);
        }
        return true;
    }

    /**
     * Resolve the tenant domain.
     *
     * @param accessTokenDO The access token data object.
     * @return The tenant domain.
     */
    private String resolveTenantDomain(AccessTokenDO accessTokenDO) {

        if (accessTokenDO.getAuthzUser() != null) {
            return accessTokenDO.getAuthzUser().getTenantDomain();
        }
        return FrameworkUtils.getLoginTenantDomainFromContext();
    }
}
