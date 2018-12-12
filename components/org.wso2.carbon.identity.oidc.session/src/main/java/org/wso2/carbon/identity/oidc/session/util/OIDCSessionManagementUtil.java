/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oidc.session.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.DefaultOIDCSessionStateManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionStateManager;
import org.wso2.carbon.identity.oidc.session.config.OIDCSessionManagementConfiguration;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class includes all the utility methods with regard to OIDC session management
 */
public class OIDCSessionManagementUtil {

    private static final String RANDOM_ALG_SHA1 = "SHA1PRNG";
    private static final String DIGEST_ALG_SHA256 = "SHA-256";
    private static final String OIDC_SESSION_STATE_MANAGER_CONFIG = "OAuth.OIDCSessionStateManager";

    private static final OIDCSessionManager sessionManager = new OIDCSessionManager();
    private static OIDCSessionStateManager oidcSessionStateManager;

    private static final Log log = LogFactory.getLog(OIDCSessionManagementUtil.class);

    private OIDCSessionManagementUtil() {

    }

    /**
     * Returns an instance of SessionManager which manages session persistence
     *
     * @return
     */
    public static OIDCSessionManager getSessionManager() {
        return sessionManager;
    }

    /**
     * Generates a session state using the provided client id, client callback url and browser state cookie id
     *
     * @param clientId
     * @param rpCallBackUrl
     * @param opBrowserState
     * @return generated session state value
     */
    public static String getSessionStateParam(String clientId, String rpCallBackUrl, String opBrowserState) {

        return getOIDCessionStateManager().getSessionStateParam(clientId, rpCallBackUrl, opBrowserState);
    }

    /**
     * Add the provided session state to the url.
     * It may be added as a query parameter or a fragment component,
     * depending on the whether the response type is code or token.
     *
     * @param url
     * @param sessionState
     * @param responseType
     * @return url with the session state parameter
     */
    public static String addSessionStateToURL(String url, String sessionState, String responseType) {

        if (StringUtils.isNotBlank(url) && StringUtils.isNotBlank(sessionState)) {
            if(OAuth2Util.isImplicitResponseType(responseType)) {
                if (url.indexOf('#') > 0) {
                    return url + "&" + OIDCSessionConstants.OIDC_SESSION_STATE_PARAM + "=" + sessionState;
                } else {
                    return url + "#" + OIDCSessionConstants.OIDC_SESSION_STATE_PARAM + "=" + sessionState;
                }
            } else {
                if (url.indexOf('?') > 0) {
                    return url + "&" + OIDCSessionConstants.OIDC_SESSION_STATE_PARAM + "=" + sessionState;
                } else {
                    return url + "?" + OIDCSessionConstants.OIDC_SESSION_STATE_PARAM + "=" + sessionState;
                }
            }
        }

        return url;
    }

    /**
     * Generates a session state using the provided client id, client callback url and browser state cookie id and
     * adds the generated value to the url as a query parameter
     *
     * @param url
     * @param clientId
     * @param rpCallBackUrl
     * @param opBrowserStateCookie
     * @param responseType
     * @return
     */
    public static String addSessionStateToURL(String url, String clientId, String rpCallBackUrl,
                                              Cookie opBrowserStateCookie, String responseType) {

        String sessionStateParam = getSessionStateParam(clientId, rpCallBackUrl, opBrowserStateCookie == null ? null :
                                                                                 opBrowserStateCookie.getValue());
        return addSessionStateToURL(url, sessionStateParam, responseType);
    }

    /**
     * Returns the browser state cookie
     *
     * @param request
     * @return CookieString url, String clientId, String rpCallBackUrl,
                                              Cookie opBrowserStateCookie, String responseType
     */
    public static Cookie getOPBrowserStateCookie(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie != null && cookie.getName().equals(OIDCSessionConstants.OPBS_COOKIE_ID)) {
                    return cookie;
                }
            }
        }

        return null;
    }

    /**
     * Adds the browser state cookie to the response
     *
     * @param response
     * @return Cookie
     */
    public static Cookie addOPBrowserStateCookie(HttpServletResponse response) {

        return getOIDCessionStateManager().addOPBrowserStateCookie(response);
    }

    /**
     * Invalidate the browser state cookie
     *
     * @param request
     * @param response
     * @return invalidated cookie
     */
    public static Cookie removeOPBrowserStateCookie(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(OIDCSessionConstants.OPBS_COOKIE_ID)) {
                    cookie.setMaxAge(0);
                    cookie.setSecure(true);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                    return cookie;
                }
            }
        }

        return null;
    }

    /**
     * Returns the origin of the provided url
     * <scheme>://<host>:<port>
     *
     * @param url
     * @return origin of the url
     */
    public static String getOrigin(String url) {

        try {
            URI uri = new URI(url);
            return uri.getScheme() + "://" + uri.getAuthority();
        } catch (URISyntaxException e) {
            log.error("Error while parsing URL origin of " + url + ". URL seems to be malformed.");
        }

        return null;
    }

    /**
     * Returns OIDC logout consent page URL
     *
     * @return OIDC logout consent page URL
     */
    public static String getOIDCLogoutConsentURL() {

        String OIDCLogutConsentPageUrl = OIDCSessionManagementConfiguration.getInstance().getOIDCLogoutConsentPageUrl();
        if (StringUtils.isBlank(OIDCLogutConsentPageUrl)) {
            OIDCLogutConsentPageUrl =
                    IdentityUtil.getServerURL("/authenticationendpoint/oauth2_logout_consent.do", false, false);
        }
        return OIDCLogutConsentPageUrl;
    }

    /**
     * Returns OIDC logout URL
     *
     * @return OIDC logout URL
     */
    public static String getOIDCLogoutURL() {

        String OIDCLogutPageUrl = OIDCSessionManagementConfiguration.getInstance().getOIDCLogoutPageUrl();
        if (StringUtils.isBlank(OIDCLogutPageUrl)) {
            OIDCLogutPageUrl =
                    IdentityUtil.getServerURL("/authenticationendpoint/oauth2_logout.do", false, false);
        }
        return OIDCLogutPageUrl;
    }

    /**
     * Returns the error page URL with given error code and error message as query parameters
     *
     * @param errorCode
     * @param errorMessage
     * @return
     */
    public static String getErrorPageURL(String errorCode, String errorMessage) {

        String errorPageUrl = OAuthServerConfiguration.getInstance().getOauth2ErrorPageUrl();
        if (StringUtils.isBlank(errorPageUrl)) {
            errorPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_error.do", false, false);
        }

        try {
            errorPageUrl += "?" + OAuthConstants.OAUTH_ERROR_CODE + "=" + URLEncoder.encode(errorCode, "UTF-8") + "&"
                            + OAuthConstants.OAUTH_ERROR_MESSAGE + "=" + URLEncoder.encode(errorMessage, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            //ignore
            if (log.isDebugEnabled()) {
                log.debug("Error while encoding the error page url", e);
            }
        }

        return errorPageUrl;
    }


    /**
     * Returns the OpenIDConnect User Consent.
     *
     * @return
     */
    public static boolean getOpenIDConnectSkipeUserConsent() {

        return OAuthServerConfiguration.getInstance().getOpenIDConnectSkipeUserConsentConfig();
    }

    private static String generateSaltValue() throws NoSuchAlgorithmException {

        byte[] bytes = new byte[16];
        SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALG_SHA1);
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

    public static OIDCSessionStateManager getOIDCessionStateManager() {

        if (oidcSessionStateManager == null) {
            synchronized (OIDCSessionManagementUtil.class) {
                if (oidcSessionStateManager == null) {
                    initOIDCSessionStateManager();
                }
            }
        }
        return oidcSessionStateManager;
    }

    private static void initOIDCSessionStateManager() {

        String oidcSessionStateManagerClassName = IdentityUtil.getProperty(OIDC_SESSION_STATE_MANAGER_CONFIG);
        if (StringUtils.isNotBlank(oidcSessionStateManagerClassName)) {
            try {
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(oidcSessionStateManagerClassName);
                oidcSessionStateManager = (OIDCSessionStateManager) clazz.newInstance();

                if (log.isDebugEnabled()) {
                    log.debug("An instance of " + oidcSessionStateManagerClassName
                            + " is created for OIDCSessionManagementUtil.");
                }

            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                String errorMsg =
                        "Error when instantiating the OIDCSessionStateManager : " + oidcSessionStateManagerClassName
                                + ". Defaulting to DefaultOIDCSessionStateManager";
                log.error(errorMsg, e);
                oidcSessionStateManager = new DefaultOIDCSessionStateManager();
            }
        } else {
            oidcSessionStateManager = new DefaultOIDCSessionStateManager();
        }
    }

    /**
     * Returns config for handling already logged out sessions gracefully.
     *
     * @return Return true if config is enabled.
     */
    public static boolean handleAlreadyLoggedOutSessionsGracefully() {

        return OIDCSessionManagementConfiguration.getInstance().handleAlreadyLoggedOutSessionsGracefully();
    }
}
