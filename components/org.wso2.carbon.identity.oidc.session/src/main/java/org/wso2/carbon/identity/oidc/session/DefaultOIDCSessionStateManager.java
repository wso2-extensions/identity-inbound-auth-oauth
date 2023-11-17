/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.SameSiteCookie;
import org.wso2.carbon.core.ServletCookie;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil.getOrigin;

/**
 * Manager class for default OIDC session state.
 */
public class DefaultOIDCSessionStateManager implements OIDCSessionStateManager {

    private static final String RANDOM_ALG_DRBG = "DRBG";
    private static final String DIGEST_ALG_SHA256 = "SHA-256";

    private static final Log log = LogFactory.getLog(OIDCSessionStateManager.class);

    /**
     * Generates a session state using the provided client id, client callback url and browser state cookie id.
     *
     * @param clientId
     * @param rpCallBackUrl
     * @param opBrowserState
     * @return generated session state value
     */
    public String getSessionStateParam(String clientId, String rpCallBackUrl, String opBrowserState) {

        try {
            String salt = generateSaltValue();
            String sessionStateDataString =
                    clientId + " " + getOrigin(rpCallBackUrl) + " " + opBrowserState + " " + salt;

            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALG_SHA256);
            digest.update(sessionStateDataString.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest.digest()) + "." + salt;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error while calculating session state.", e);
        }
    }

    /**
     * Adds the browser state cookie to the response.
     *
     * @param response
     * @return Cookie
     */
    public Cookie addOPBrowserStateCookie(HttpServletResponse response) {

        ServletCookie cookie = new ServletCookie(OIDCSessionConstants.OPBS_COOKIE_ID, UUID.randomUUID().toString());
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setSameSite(SameSiteCookie.NONE);

        response.addCookie(cookie);
        return cookie;
    }

    /**
     * Adds the browser state cookie with tenant qualified path to the response.
     *
     * @param response
     * @param request
     * @param loginTenantDomain
     * @param opbsValue
     * @return Cookie
     */
    @Override
    public Cookie addOPBrowserStateCookie(HttpServletResponse response, HttpServletRequest request,
                                          String loginTenantDomain, String opbsValue) {

        ServletCookie cookie;
        if (IdentityTenantUtil.isTenantedSessionsEnabled() && loginTenantDomain != null) {
            // Invalidate the old opbs cookies which haven't tenanted paths.
            removeOPBrowserStateCookiesInRoot(request, response);

            cookie = new ServletCookie(OIDCSessionConstants.OPBS_COOKIE_ID, opbsValue);
            if (isOrganizationQualifiedRequest()) {
                cookie.setPath(FrameworkConstants.ORGANIZATION_CONTEXT_PREFIX + loginTenantDomain + "/");
            } else {
                if (!IdentityTenantUtil.isSuperTenantAppendInCookiePath() &&
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(loginTenantDomain)) {
                    cookie.setPath("/");
                } else {
                    cookie.setPath(FrameworkConstants.TENANT_CONTEXT_PREFIX + loginTenantDomain + "/");
                }

            }
        } else {
            cookie = new ServletCookie(OIDCSessionConstants.OPBS_COOKIE_ID, opbsValue);
            cookie.setPath("/");
        }
        cookie.setSecure(true);
        cookie.setSameSite(SameSiteCookie.NONE);
        response.addCookie(cookie);
        return cookie;
    }

    @Override
    public String generateOPBrowserStateCookieValue(String tenantDomain) {

        if (IdentityTenantUtil.isTenantedSessionsEnabled() && tenantDomain != null) {
            // Invalidate the old opbs cookies which haven't tenanted paths.
           return UUID.randomUUID() + OIDCSessionConstants.TENANT_QUALIFIED_OPBS_COOKIE_SUFFIX;
        }
        return UUID.randomUUID().toString();
    }

    /**
     * Invalidate the old opbs cookies which haven't tenanted paths.
     *
     * @param request
     * @param response
     */
    private static void removeOPBrowserStateCookiesInRoot(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return;
        }

        for (Cookie cookie : cookies) {
            if (cookie != null && cookie.getName().equals(OIDCSessionConstants.OPBS_COOKIE_ID)) {
                if (cookie.getValue().endsWith(OIDCSessionConstants.TENANT_QUALIFIED_OPBS_COOKIE_SUFFIX)) {
                    continue;
                } else {
                    ServletCookie oldCookie = new ServletCookie(cookie.getName(), cookie.getValue());
                    oldCookie.setMaxAge(0);
                    oldCookie.setSecure(true);
                    oldCookie.setPath("/");
                    oldCookie.setSameSite(SameSiteCookie.NONE);
                    response.addCookie(oldCookie);

                    if (log.isDebugEnabled()) {
                        log.debug("OPBS cookie was found with the root path and Invalidated it.");
                    }
                }
            }
        }
    }

    private static String generateSaltValue() throws NoSuchAlgorithmException {

        byte[] bytes = new byte[16];
        SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALG_DRBG);
        secureRandom.nextBytes(bytes);
        return Base64.encodeBase64URLSafeString(bytes);
    }

    private static String bytesToHex(byte[] bytes) {

        StringBuilder result = new StringBuilder();
        for (byte byt : bytes) {
            result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        }
        return result.toString();
    }

    private static boolean isOrganizationQualifiedRequest() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId() != null;
    }
}
