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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.DefaultOIDCSessionStateManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionStateManager;
import org.wso2.carbon.identity.oidc.session.config.OIDCSessionManagementConfiguration;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Set;
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

    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";

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
     * Returns client id from servlet request.
     *
     * @param request
     * @return Client ID
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static String getClientId(HttpServletRequest request)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        String clientId;
        String idToken = getIdToken(request);
        if (idToken != null) {
            clientId = getClientIdFromIDTokenHint(idToken);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("IdTokenHint is not found in the request ");
            }
            return null;
        }
        if (validateIdTokenHint(clientId, idToken)) {
            return clientId;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Id Token is not valid");
            }
            return null;
        }
    }

    /**
     * Returns signing tenant domain.
     *
     * @param oAuthAppDO
     * @return Signing Tenant Domain
     */
    public static String getSigningTenantDomain(OAuthAppDO oAuthAppDO) {

        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String signingTenantDomain;

        if (isJWTSignedWithSPKey) {
            // Tenant domain of the SP.
            signingTenantDomain = getTenantDomain(oAuthAppDO);
        } else {
            // Tenant domain of the user.
            signingTenantDomain = oAuthAppDO.getUser().getTenantDomain();
        }
        return signingTenantDomain;
    }


    /**
     * Returns the OIDCsessionState of the obps cookie
     *
     * @param request
     * @return Session state
     */
    public static OIDCSessionState getSessionState(HttpServletRequest request) {

        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (opbsCookie != null) {
            String obpsCookieValue = opbsCookie.getValue();
            OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                    .getOIDCSessionState(obpsCookieValue);
            return sessionState;
        } else {
            return null;
        }
    }

    /**
     * Return client id of all the RPs belong to same session.
     *
     * @param sessionState
     * @return client id of all the RPs belong to same session
     */
    public static Set<String> getSessionParticipants(OIDCSessionState sessionState) {

        Set<String> sessionParticipants = sessionState.getSessionParticipants();
        return sessionParticipants;
    }

    /**
     * Returns the sid of the all the RPs belong to same session.
     *
     * @param sessionState
     * @return sid claim from session state
     */
    public static String getSidClaim(OIDCSessionState sessionState) {

        String sidClaim = sessionState.getSidClaim();
        return sidClaim;
    }

    public static IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(ERROR_GET_RESIDENT_IDP, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Returning issuer of the tenant domain.
     *
     * @param tenantDomain
     * @return issuer
     * @throws IdentityOAuth2Exception
     */
    public static String getIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        IdentityProvider identityProvider = getResidentIdp(tenantDomain);
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator.
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        // Setting issuer.
        String issuer =
                IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                        OPENID_IDP_ENTITY_ID).getValue();
        return issuer;
    }

    /**
     * Returns OAuthAppDo using clientID
     *
     * @param clientID
     * @return OAuthAppDO of the specific client ID
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static OAuthAppDO getOAuthAppDO(String clientID) throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientID);
        return oAuthAppDO;
    }

    /**
     * Returns tenant domain.
     *
     * @param oAuthAppDO
     * @return Tenant domain for OAuth app
     */
    public static String getTenantDomain(OAuthAppDO oAuthAppDO) {

        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        return tenantDomain;
    }

    /**
     * Returns ID Token
     *
     * @param request
     * @return ID token
     */
    public static String getIdToken(HttpServletRequest request) {

        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        if (idTokenHint != null) {
            return idTokenHint;
        }
        return null;
    }

    /**
     * Returns client ID from ID Token Hint.
     *
     * @param idTokenHint
     * @return client ID from ID Token Hint
     */
    public static String getClientIdFromIDTokenHint(String idTokenHint) {

        String clientId = null;
        if (StringUtils.isNotBlank(idTokenHint)) {
            try {
                clientId = extractClientFromIdToken(idTokenHint);
            } catch (ParseException e) {
                log.error("Error while decoding the ID Token Hint.", e);
            }
        }
        return clientId;
    }

    /**
     * Extract client Id from ID Token Hint.
     *
     * @param idToken
     * @return client Id from ID Token Hint
     * @throws ParseException
     */
    public static String extractClientFromIdToken(String idToken) throws ParseException {

        return SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
    }

    /**
     * Validate Id Token Hint.
     *
     * @param clientId
     * @param idToken
     * @return validity of ID token
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static Boolean validateIdTokenHint(String clientId, String idToken) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        String tenantDomain = getSigningTenantDomain(getOAuthAppDO(clientId));
        if (StringUtils.isEmpty(tenantDomain)) {
            return false;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RSAPublicKey publicKey;

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(jksName).getCertificate(tenantDomain)
                        .getPublicKey();
            } else {
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException | ParseException e) {
            log.error("Error occurred while validating id token signature.", e);
            return false;
        } catch (Exception e) {
            log.error("Error occurred while validating id token signature.", e);
            return false;
        }
    }
}
