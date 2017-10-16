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

package org.wso2.carbon.identity.oidc.session.servlet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheKey;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class OIDCLogoutServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(OIDCLogoutServlet.class);
    private static final long serialVersionUID = -9203934217770142011L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        /**
         * Recommended Parameter : id_token_hint
         * As per the specification https://openid.net/specs/openid-connect-session-1_0.html#RFC6454, it's recommended
         * to expect id_token_hint parameter to determine which RP initiated the logout request.
         * Otherwise, it could lead to DoS attacks. Thus, at least explicit user confirmation is needed to act upon
         * such logout requests.
         *
         * Optional Parameter : post_logout_redirect_uri
         * This denotes the RP URL to be redirected after logout has been performed. This value must be previously
         * registered at IdP via post_logout_redirect_uris registration parameter or by some other configuration. And
         * the received URL should be validated to be one of registered.
         */

        /**
         * todo: At the moment we do not persist id_token issued for clients, thus we could not retrieve the RP that
         * todo: a specific id_token has been issued.
         * todo: Since we use a browser cookie to track the session, for the moment, we
         * todo: will validate if the logout request is being initiated by an active session via the cookie
         * todo: This need to be fixed such that we do not rely on the cookie and the request is validated against
         * todo: the id_token_hint received
         *
         * todo: Should provide a way to register post_logout_redirect_uris at IdP and should validate the received
         * todo: parameter against the set of registered values. This depends on retrieving client for the received
         * todo: id_token_hint value
         */

        String redirectURL;
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);

        if (opBrowserStateCookie == null) {
            String msg = OIDCSessionConstants.OPBS_COOKIE_ID + " cookie not received. Missing session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            response.sendRedirect(redirectURL);
            return;
        }

        if (!OIDCSessionManagementUtil.getSessionManager().sessionExists(opBrowserStateCookie.getValue())) {
            String msg = "No valid session found for the received session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            response.sendRedirect(redirectURL);
            return;
        }

        String consent = request.getParameter(OIDCSessionConstants.OIDC_LOGOUT_CONSENT_PARAM);
        if (StringUtils.isNotBlank(consent)) {
            // User consent received for logout
            if (consent.equals(OAuthConstants.Consent.APPROVE)) {
                // User approved logout. Logout from authentication framework
                sendToFrameworkForLogout(request, response);
                return;
            } else {
                // User denied logout.
                redirectURL = OIDCSessionManagementUtil
                        .getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, "End User denied the logout request");
            }
        } else {
            // OIDC Logout response
            String sessionDataKey = request.getParameter(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM);
            if (sessionDataKey != null) {
                handleLogoutResponseFromFramework(request, response);
                return;
            }
            // Get user consent to logout
            boolean skipConsent = getOpenIDConnectSkipeUserConsent();
            if (skipConsent) {
                String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
                if (StringUtils.isNotBlank(idTokenHint)) {
                    redirectURL = processLogoutRequest(request, response);
                    if (StringUtils.isNotBlank(redirectURL)) {
                        response.sendRedirect(redirectURL);
                        return;
                    }
                } else {
                    // Add OIDC Cache entry without properties since OIDC Logout should work without id_token_hint
                    OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();
                    addSessionDataToCache(opBrowserStateCookie.getValue(), cacheEntry);
                }
                sendToFrameworkForLogout(request, response);
                return;
            } else {
                sendToConsentUri(request, response);
                return;
            }
        }

        response.sendRedirect(redirectURL);
    }

    /**
     * Process OIDC Logout request
     * Validate Id token
     * Add OIDC parameters to cache
     *
     * @param request Http servlet request
     * @param response Http servlet response
     * @return Redirect URI
     * @throws IOException
     */
    private String processLogoutRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String redirectURL = null;
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        String postLogoutRedirectUri = request
                .getParameter(OIDCSessionConstants.OIDC_POST_LOGOUT_REDIRECT_URI_PARAM);
        String state = request
                .getParameter(OIDCSessionConstants.OIDC_STATE_PARAM);

        String clientId;
        try {
            if (!validateIdToken(idTokenHint)) {
                String msg = "ID token signature validation failed.";
                log.error(msg);
                redirectURL = OIDCSessionManagementUtil
                        .getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                return redirectURL;
            }

            clientId = extractClientFromIdToken(idTokenHint);
            OAuthAppDAO appDAO = new OAuthAppDAO();
            OAuthAppDO oAuthAppDO = appDAO.getAppInformation(clientId);

            if (!validatePostLogoutUri(postLogoutRedirectUri, oAuthAppDO.getCallbackUrl())) {
                String msg = "Post logout URI does not match with registered callback URI.";
                redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                return redirectURL;
            }
        } catch (ParseException e) {
            String msg = "No valid session found for the received session state.";
            log.error(msg, e);
            redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            return redirectURL;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            String msg = "Error occurred while getting application information. Client id not found";
            log.error(msg, e);
            redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            return redirectURL;
        }

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM, clientId);
        OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();
        cacheEntry.setIdToken(idTokenHint);
        cacheEntry.setPostLogoutRedirectUri(postLogoutRedirectUri);
        cacheEntry.setState(state);
        cacheEntry.setParamMap(new ConcurrentHashMap<>(paramMap));
        addSessionDataToCache(opBrowserStateCookie.getValue(), cacheEntry);

        return redirectURL;
    }

    /**
     * Validate Id token signature
     * @param idToken Id token
     * @return validation state
     */
    private boolean validateIdToken(String idToken) {

        String tenantDomain = getTenantDomainForSignatureValidation(idToken);
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
            log.error("Error occurred while validating id token signature.");
            return false;
        } catch (Exception e) {
            log.error("Error occurred while validating id token signature.");
            return false;
        }
    }

    /**
     * Get tenant domain for signature validation.
     * There is a problem If Id token signed using SP's tenant and there is no direct way to get the tenant domain
     * using client id. So have iterate all the Tenants until get the right client id.
     * @param idToken id token
     * @return Tenant domain
     */
    private String getTenantDomainForSignatureValidation(String idToken) {
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String tenantDomain;

        try {
            String clientId = extractClientFromIdToken(idToken);
            if (isJWTSignedWithSPKey) {
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
                tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            } else {
                //It is not sending tenant domain with the subject in id_token by default, So to work this as
                //expected, need to enable the option "Use tenant domain in local subject identifier" in SP config
                tenantDomain = MultitenantUtils.getTenantDomain(extractSubjectFromIdToken(idToken));
            }
        } catch (ParseException e) {
            log.error("Error occurred while extracting client id from id token", e);
            return null;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error occurred while getting oauth application information.", e);
            return null;
        }
        return tenantDomain;
    }

    /**
     * Send request to consent URI
     * @param request Http servlet request
     * @param response Http servlet response
     * @throws IOException
     */
    private void sendToConsentUri(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        String redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();

        if (idTokenHint != null) {
            redirectURL = processLogoutRequest(request, response);
            if (StringUtils.isNotBlank(redirectURL)) {
                response.sendRedirect(redirectURL);
                return;
            } else {
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
            }
        } else {
            // Add OIDC Cache entry without properties since OIDC Logout should work without id_token_hint
            OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();
            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
            addSessionDataToCache(opBrowserStateCookie.getValue(), cacheEntry);
        }
        response.sendRedirect(redirectURL);
    }

    /**
     * Append state query parameter
     * @param redirectURL redirect URL
     * @param stateParam state query parameter
     * @return Redirect URL after appending state query param if exist
     */
    private String appendStateQueryParam(String redirectURL, String stateParam) {

        if (StringUtils.isNotEmpty(stateParam)) {
            redirectURL = redirectURL + "?" + OIDCSessionConstants.OIDC_STATE_PARAM + "=" + stateParam;
        }
        return redirectURL;
    }

    /**
     * Validate post logout URI with registered callback URI
     * @param postLogoutUri Post logout redirect URI
     * @param registeredCallbackUri registered callback URI
     * @return Validation state
     */
    private boolean validatePostLogoutUri(String postLogoutUri, String registeredCallbackUri) {

        if (StringUtils.isEmpty(postLogoutUri)) {
            return true;
        }

        String regexp = null;
        if (registeredCallbackUri.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            regexp = registeredCallbackUri.substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
        }

        if (regexp != null && postLogoutUri.matches(regexp)) {
            return true;
        } else if (registeredCallbackUri.equals(postLogoutUri)) {
            return true;
        } else {    // Provided Post logout redirect URL does not match the registered callback url.
            log.warn("Provided Post logout redirect URL does not match with the provided one.");
            return false;
        }
    }

    /**
     * Extract Client Id from Id token
     * @param idToken id token
     * @return Client Id
     * @throws ParseException
     */
    private String extractClientFromIdToken(String idToken) throws ParseException {

        return SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
    }

    /**
     * Extract Subject from id token
     * @param idToken id token
     * @return Authenticated Subject
     * @throws ParseException
     */
    private String extractSubjectFromIdToken(String idToken) throws ParseException {

        return SignedJWT.parse(idToken).getJWTClaimsSet().getSubject();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doGet(request, response);
    }

    private void sendToFrameworkForLogout(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Generate a SessionDataKey. Authentication framework expects this parameter
        String sessionDataKey = UUID.randomUUID().toString();

        //Add all parameters to authentication context before sending to authentication framework
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        Map<String, String[]> map = new HashMap<>();
        map.put(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM, new String[] { sessionDataKey });
        authenticationRequest.setRequestQueryParams(map);
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT, new String[] { "true" });
        authenticationRequest.setCommonAuthCallerPath(request.getRequestURI());
        authenticationRequest.setPost(true);

        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(opBrowserStateCookie.getValue());
        if (cacheEntry != null) {
            authenticationRequest
                    .setRelyingParty(cacheEntry.getParamMap().get(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM));
            addSessionDataToCache(sessionDataKey, cacheEntry);
        }

        //Add headers to AuthenticationRequestContext
        for (Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String headerName = e.nextElement().toString();
            authenticationRequest.addHeader(headerName, request.getHeader(headerName));
        }

        AuthenticationRequestCacheEntry authenticationRequestCacheEntry =
                new AuthenticationRequestCacheEntry(authenticationRequest);
        addAuthenticationRequestToRequest(request, authenticationRequestCacheEntry);
        sendRequestToFramework(request, response, sessionDataKey, FrameworkConstants.RequestType.CLAIM_TYPE_OIDC);
    }

    private void handleLogoutResponseFromFramework(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String sessionDataKey = request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
        OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(sessionDataKey);
        if (cacheEntry != null) {
            String redirectURL = cacheEntry.getPostLogoutRedirectUri();
            if (redirectURL == null) {
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutURL();
            }
            redirectURL = appendStateQueryParam(redirectURL, cacheEntry.getState());
            removeSessionDataFromCache(sessionDataKey);
            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
            OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opBrowserStateCookie.getValue());
            response.sendRedirect(redirectURL);
        } else {
            response.sendRedirect(
                    OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.SERVER_ERROR, "User logout failed"));
        }
    }

    private void addAuthenticationRequestToRequest(HttpServletRequest request,
            AuthenticationRequestCacheEntry authRequest) {
        request.setAttribute(FrameworkConstants.RequestAttribute.AUTH_REQUEST, authRequest);
    }

    private void sendRequestToFramework(HttpServletRequest request, HttpServletResponse response, String sessionDataKey,
            String type) throws ServletException, IOException {

        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

        CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(request);
        requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
        requestWrapper.setParameter(FrameworkConstants.RequestParams.TYPE, type);

        CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(response);
        commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);

        Object object = request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);

        if (object != null) {
            AuthenticatorFlowStatus status = (AuthenticatorFlowStatus) object;
            if (status == AuthenticatorFlowStatus.INCOMPLETE) {
                response.sendRedirect(responseWrapper.getRedirectURL());
            } else {
                handleLogoutResponseFromFramework(requestWrapper, response);
            }
        } else {
            handleLogoutResponseFromFramework(requestWrapper, response);
        }
    }

    private void addSessionDataToCache(String sessionDataKey, OIDCSessionDataCacheEntry cacheEntry) {

        OIDCSessionDataCacheKey cacheKey = new OIDCSessionDataCacheKey(sessionDataKey);
        OIDCSessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private OIDCSessionDataCacheEntry getSessionDataFromCache(String sessionDataKey) {

        OIDCSessionDataCacheKey cacheKey = new OIDCSessionDataCacheKey(sessionDataKey);
        return OIDCSessionDataCache.getInstance().getValueFromCache(cacheKey);
    }

    private void removeSessionDataFromCache(String sessionDataKey) {

        OIDCSessionDataCacheKey cacheKey = new OIDCSessionDataCacheKey(sessionDataKey);
        OIDCSessionDataCache.getInstance().clearCacheEntry(cacheKey);
    }

    /**
     * Returns the OpenIDConnect User Consent.
     *
     * @return
     */
    private static boolean getOpenIDConnectSkipeUserConsent() {
        return OAuthServerConfiguration.getInstance().getOpenIDConnectSkipeUserConsentConfig();

    }
}
