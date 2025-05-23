/*
 * Copyright (c) 2016-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session.servlet;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManagementException;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.backchannellogout.LogoutRequestSender;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheKey;
import org.wso2.carbon.identity.oidc.session.handler.OIDCLogoutHandler;
import org.wso2.carbon.identity.oidc.session.internal.OIDCSessionManagementComponentServiceHolder;
import org.wso2.carbon.identity.oidc.session.model.APIError;
import org.wso2.carbon.identity.oidc.session.model.LogoutContext;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.TENANT_DOMAIN;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.getRedirectURL;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validateRequestTenantDomain;
import static org.wso2.carbon.identity.oidc.session.OIDCSessionConstants.OIDCEndpoints.OIDC_LOGOUT_ENDPOINT;
import static org.wso2.carbon.identity.oidc.session.OIDCSessionConstants.OIDC_LOGOUT_CONSENT_DENIAL_REDIRECT_URL;
import static org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil.getErrorPageURL;

/**
 * Servlet class of OIDC Logout.
 */
public class OIDCLogoutServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(OIDCLogoutServlet.class);
    private static final String REQUEST_PARAM_SP = "sp";
    private static final String UTF_8 = "UTF-8";
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
        String opBrowserState = getOPBrowserState(request);
        LogoutContext logoutContext = new LogoutContext();
        try {
            boolean isAPIBasedLogout = isAPIBasedLogoutFlow(request);
            logoutContext.setAPIBasedLogout(isAPIBasedLogout);
            if (isAPIBasedLogout) {
                if (log.isDebugEnabled()) {
                    log.debug("The initiated logout flow is an API based logout flow.");
                }
                populateAPIBasedLogoutContext(request, logoutContext);
            }
        } catch (AuthServiceClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while populating logout context for api based logout.", e);
            }
            handleAPIBasedLogoutErrorResponse(e, response);
            return;
        } catch (AuthServiceException e) {
            log.error("Error while populating logout context for api based logout.", e);
            handleAPIBasedLogoutErrorResponse(e, response);
            return;
        }

        if (!logoutContext.isAPIBasedLogout() && StringUtils.isBlank(opBrowserState)) {
            String msg = OIDCSessionConstants.OPBS_COOKIE_ID + " cookie not received. Missing session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            if (OIDCSessionManagementUtil.handleAlreadyLoggedOutSessionsGracefully()) {
                handleMissingSessionStateGracefully(request, response);
                return;
            } else {
                if (log.isDebugEnabled()) {
                    msg = "HandleAlreadyLoggedOutSessionsGracefully configuration disabled. Missing session state is " +
                            "handled by redirecting to error page instead of default logout page.";
                    log.debug(msg);
                }
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            }
        }

        if (!logoutContext.isAPIBasedLogout() && !OIDCSessionManagementUtil.getSessionManager().
                sessionExists(opBrowserState, OAuth2Util.resolveTenantDomain(request))) {
            String msg = "No valid session found for the received session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
            if (OIDCSessionManagementUtil.handleAlreadyLoggedOutSessionsGracefully()) {
                handleMissingSessionStateGracefully(request, response);
            } else {
                if (log.isDebugEnabled()) {
                    msg = "HandleAlreadyLoggedOutSessionsGracefully configuration enabled. No valid session found is " +
                            "handled by redirecting to error page instead of default logout page.";
                    log.debug(msg);
                }
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                response.sendRedirect(getRedirectURL(redirectURL, request));
            }
            return;
        }

        String consent = request.getParameter(OIDCSessionConstants.OIDC_LOGOUT_CONSENT_PARAM);
        if (StringUtils.isNotBlank(consent)) {
            // User consent received for logout
            if (consent.equals(OAuthConstants.Consent.APPROVE)) {
                // User approved logout. Logout from authentication framework
                sendToFrameworkForLogout(request, response, logoutContext);
                return;
            } else {
                // User denied logout.
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, "End User denied the logout request");
                // If postlogoutUri is available then set it as redirectUrl
                redirectURL = generatePostLogoutRedirectUrl(redirectURL, opBrowserState, request);
                response.sendRedirect(redirectURL);
                return;
            }
        } else {
            // OIDC Logout response
            String sessionDataKey = request.getParameter(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM);
            if (sessionDataKey != null) {
                handleLogoutResponseFromFramework(request, response, logoutContext);
                return;
            }
            String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
            String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);
            boolean skipConsent;
            // Get user consent to logout
            try {
                skipConsent = logoutContext.isAPIBasedLogout() || getOpenIDConnectSkipUserConsent(request);
            } catch (ParseException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting clientId from the IdTokenHint.", e);
                }
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED,
                        "ID token signature validation failed.");
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            } catch (IdentityOAuth2ClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting service provider from the clientId.", e);
                }
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED,
                        "ID token signature validation failed.");
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            }  catch (IdentityOAuth2Exception e) {
                log.error("Error occurred while getting oauth application information.", e);
                return;
            }
            if (skipConsent) {
                if (StringUtils.isNotBlank(clientId) || StringUtils.isNotBlank(idTokenHint)) {
                    redirectURL = processLogoutRequest(request, response);
                    if (StringUtils.isNotBlank(redirectURL)) {
                        response.sendRedirect(getRedirectURL(redirectURL, request));
                        return;
                    }
                } else {
                    // Add OIDC Cache entry without properties since OIDC Logout should work without id_token_hint
                    OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();

                    /*
                     Logout request without client_id or id_token_hint will redirected to an IDP's page once logged out,
                     rather a RP's callback endpoint. The state parameter is set here in the cache, so that it will be
                     available in the redirected IDP's page to support any custom requirement.
                     */
                    setStateParameterInCache(request, cacheEntry);
                    addSessionDataToCache(opBrowserState, cacheEntry);
                }

                sendToFrameworkForLogout(request, response, logoutContext);
                return;
            } else {
                sendToConsentUri(request, response);
                return;
            }
        }
    }

    private String getOPBrowserState(HttpServletRequest request) {

        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (opBrowserStateCookie != null) {
            if (log.isDebugEnabled()) {
                log.debug("Resolving opBrowserState from the 'obps' Cookie in the inbound request.");
            }
            return opBrowserStateCookie.getValue();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("OpBrowserState cookie not found in the inbound request. Attempting to extract the " +
                        "opBrowserState from cache.");
            }
            String sessionDataKey = request.getParameter(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM);
            if (StringUtils.isNotBlank(sessionDataKey)) {
                OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(sessionDataKey);
                if (cacheEntry != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resolving the opBrowserState from cache.");
                    }
                    return cacheEntry.getParamMap().get(OIDCSessionConstants.OPBS_COOKIE_ID);
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Unable to resolve the opBrowser state.");
        }
        return null;
    }

    /**
     * If postLogoutRedirectUri is send in Logout request parameter then set it as redirect URL.
     *
     * @param redirectURL               Redirect URL.
     * @param opBrowserStateCookieValue OP browser state cookie value.
     * @param request                   HttpServletRequest.
     * @return If postLogoutRedirectUri is sent in Logout request parameter then return it as redirect URL.
     * @throws UnsupportedEncodingException
     */
    private String generatePostLogoutRedirectUrl(String redirectURL, String opBrowserStateCookieValue,
                                                 HttpServletRequest request) throws UnsupportedEncodingException {

        // Set postLogoutRedirectUri as redirectURL.
        boolean postLogoutRedirectUriRedirectIsEnabled =
                Boolean.parseBoolean(IdentityUtil.getProperty(OIDC_LOGOUT_CONSENT_DENIAL_REDIRECT_URL));
        if (postLogoutRedirectUriRedirectIsEnabled) {
            OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(opBrowserStateCookieValue);
            if (cacheEntry != null && cacheEntry.getPostLogoutRedirectUri() != null) {
                Map<String, String> params = new HashMap<>();
                params.put(OAuthConstants.OAUTH_ERROR, OAuth2ErrorCodes.ACCESS_DENIED);
                params.put(OAuthConstants.OAUTH_ERROR_DESCRIPTION, "End User denied the logout request");
                if (cacheEntry.getState() != null) {
                    params.put(OAuthConstants.OAuth20Params.STATE, cacheEntry.getState());
                }
                redirectURL = FrameworkUtils.buildURLWithQueryParams(
                        cacheEntry.getPostLogoutRedirectUri(), params);
            }
        }
        return buildRedirectURLAfterLogout(redirectURL, request);
    }

    /**
     * Process OIDC Logout request.
     * Validate Id token.
     * Add OIDC parameters to cache.
     *
     * @param request  Http servlet request
     * @param response Http servlet response
     * @return Redirect URI
     * @throws IOException
     */
    private String processLogoutRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String redirectURL = null;
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);
        String postLogoutRedirectUri = request
                .getParameter(OIDCSessionConstants.OIDC_POST_LOGOUT_REDIRECT_URI_PARAM);
        String state = request
                .getParameter(OIDCSessionConstants.OIDC_STATE_PARAM);

        String appTenantDomain;
        try {
            if (StringUtils.isBlank(clientId)) {
                clientId = getClientIdFromIdToken(request, idTokenHint);
            }
            appTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientId);
            validateRequestTenantDomain(appTenantDomain);
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            String spName = getServiceProviderName(clientId, appTenantDomain);
            setSPAttributeToRequest(request, spName, appTenantDomain);

            if (!validatePostLogoutUri(postLogoutRedirectUri, oAuthAppDO.getCallbackUrl())) {
                String msg = "Post logout URI does not match with registered callback URI.";
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                return getRedirectURL(redirectURL, request);
            }
        } catch (ParseException e) {
            String msg = "No valid session found for the received session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            return getRedirectURL(redirectURL, request);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            String msg;
            if (OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_ID_TOKEN.equals(e.getErrorCode())) {
                msg = e.getMessage();
            } else {
                msg = "Error occurred while getting application information. Client id not found.";
            }
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            return getRedirectURL(redirectURL, request);
        }

        if (opBrowserStateCookie != null) {
            Map<String, String> paramMap = new HashMap<>();
            paramMap.put(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM, clientId);
            paramMap.put(OIDCSessionConstants.OIDC_CACHE_TENANT_DOMAIN_PARAM, appTenantDomain);
            OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();
            if (StringUtils.isNotBlank(idTokenHint)) {
                cacheEntry.setIdToken(idTokenHint);
            }
            cacheEntry.setPostLogoutRedirectUri(postLogoutRedirectUri);
            cacheEntry.setState(state);
            cacheEntry.setParamMap(new ConcurrentHashMap<>(paramMap));
            addSessionDataToCache(opBrowserStateCookie.getValue(), cacheEntry);
        }

        return redirectURL;
    }

    /**
     * Validate Id token signature.
     *
     * @param idToken Id token
     * @return validation state
     */
    private boolean validateIdToken(String idToken) {

        String tenantDomain = getTenantDomainForSignatureValidation(idToken);
        if (StringUtils.isEmpty(tenantDomain)) {
            return false;
        }

        try {
            RSAPublicKey publicKey = (RSAPublicKey) IdentityKeyStoreResolver.getInstance().getCertificate(tenantDomain,
                    IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH).getPublicKey();
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException | ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating id token signature for the id token: " + idToken);
            }
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
     *
     * @param idToken id token
     * @return Tenant domain
     */
    private String getTenantDomainForSignatureValidation(String idToken) {

        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        if (log.isDebugEnabled()) {
            log.debug("'SignJWTWithSPKey' property is set to : " + isJWTSignedWithSPKey);
        }
        String tenantDomain;

        try {
            String clientId = extractClientFromIdToken(idToken);
            if (isJWTSignedWithSPKey) {
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
                tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                if (log.isDebugEnabled()) {
                    log.debug("JWT signature will be validated with the service provider's tenant domain : " +
                            tenantDomain);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("JWT signature will be validated with user tenant domain.");
                }
                tenantDomain = extractTenantDomainFromIdToken(idToken);
            }
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while extracting client id from id token: " + idToken, e);
            }
            return null;
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while getting oauth application information.", e);
            return null;
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while getting tenant domain for signature validation with id token: "
                        + idToken, e);
            }
            return null;
        }
        return tenantDomain;
    }

    /**
     * Send request to consent URI.
     *
     * @param request  Http servlet request
     * @param response Http servlet response
     * @throws IOException
     */
    private void sendToConsentUri(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);
        String redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();

        if (StringUtils.isNotBlank(clientId) || StringUtils.isNotBlank(idTokenHint)) {
            redirectURL = processLogoutRequest(request, response);
            if (StringUtils.isNotBlank(redirectURL)) {
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            } else {
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
            }
        } else {
            // Add OIDC Cache entry without properties since OIDC Logout should work without id_token_hint
            OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();

            // Logout request without client_id or id_token_hint will redirected to an IDP's page once logged out,
            // rather a RP's callback endpoint. The state parameter is set here in the cache, so that it will be
            // available in the redirected IDP's page to support any custom requirement.
            setStateParameterInCache(request, cacheEntry);
            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
            addSessionDataToCache(opBrowserStateCookie.getValue(), cacheEntry);
        }
        response.sendRedirect(getRedirectURL(redirectURL, request));
    }

    private void setStateParameterInCache(HttpServletRequest request, OIDCSessionDataCacheEntry cacheEntry) {

        String state = request.getParameter(OIDCSessionConstants.OIDC_STATE_PARAM);
        cacheEntry.setState(state);
    }

    /**
     * Append state query parameter.
     *
     * @param redirectURL redirect URL
     * @param stateParam  state query parameter
     * @return Redirect URL after appending state query param if exist
     */
    private String appendStateQueryParam(String redirectURL, String stateParam) throws UnsupportedEncodingException {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(OIDCSessionConstants.OIDC_STATE_PARAM, stateParam);
        if (StringUtils.isNotEmpty(stateParam)) {
            redirectURL = FrameworkUtils.buildURLWithQueryParams(redirectURL, paramMap);
        }
        return redirectURL;
    }

    /**
     * Validate post logout URI with registered callback URI.
     *
     * @param postLogoutUri         Post logout redirect URI
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
        } else {
            log.warn("Provided Post logout redirect URL does not match the registered callback url.");
            return false;
        }
    }

    /**
     * Extract Client Id from Id token.
     *
     * @param idToken id token
     * @return Client Id
     * @throws ParseException
     */
    private String extractClientFromIdToken(String idToken) throws ParseException {

        String clientId = (String) SignedJWT.parse(idToken).getJWTClaimsSet()
                .getClaims().get(OIDCSessionConstants.OIDC_ID_TOKEN_AZP_CLAIM);

        if (StringUtils.isBlank(clientId)) {
            clientId = SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
            log.info("Provided ID Token does not contain azp claim with client ID. " +
                    "Client ID is extracted from the aud claim in the ID Token.");
        }

        return clientId;
    }

    /**
     * Extract tenant domain from id token.
     *
     * @param idToken id token
     * @return tenant domain
     * @throws ParseException
     */
    private String extractTenantDomainFromIdToken(String idToken) throws ParseException {

        String tenantDomain = null;
        Map realm = null;

        JWTClaimsSet claimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();
        if (claimsSet.getClaims().get(OAuthConstants.OIDCClaims.REALM) instanceof Map) {
            realm = (Map) claimsSet.getClaims().get(OAuthConstants.OIDCClaims.REALM);
        }
        if (realm != null) {
            tenantDomain = (String) realm.get(OAuthConstants.OIDCClaims.TENANT);
        }
        if (StringUtils.isBlank(tenantDomain)) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to retrieve tenant domain from 'realm' claim. Hence falling back to 'sub' claim.");
            }
            //It is not sending tenant domain with the subject in id_token by default, So to work this as
            //expected, need to enable the option "Use tenant domain in local subject identifier" in SP config
            tenantDomain = MultitenantUtils.getTenantDomain(claimsSet.getSubject());
            if (log.isDebugEnabled()) {
                log.debug("User tenant domain derived from 'sub' claim of JWT. Tenant domain : " + tenantDomain);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("User tenant domain found in 'realm' claim of JWT. Tenant domain : " + tenantDomain);
            }
        }
        return tenantDomain;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        doGet(request, response);
    }

    private void sendToFrameworkForLogout(HttpServletRequest request, HttpServletResponse response,
                                          LogoutContext logoutContext) throws ServletException, IOException {

        try {
            triggerLogoutHandlersForPreLogout(request, response);
        } catch (OIDCSessionManagementException e) {
            log.error("Error executing logout handlers on pre logout.");
            if (log.isDebugEnabled()) {
                log.debug("Error executing logout handlers on pre logout.", e);
            }
            if (logoutContext.isAPIBasedLogout()) {
                handleAPIBasedLogoutErrorResponse(new AuthServiceException(
                        getDefaultError(false).code(),
                        getDefaultError(false).description(), e), response);
            } else {
                response.sendRedirect(getRedirectURL(getErrorPageURL(OAuth2ErrorCodes.SERVER_ERROR,
                        "User logout failed."), request));
            }
            return;
        }

        // Generate a SessionDataKey. Authentication framework expects this parameter
        String sessionDataKey = UUID.randomUUID().toString();
        String opBrowserStateCookieValue = null;
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (opBrowserStateCookie != null) {
            opBrowserStateCookieValue = opBrowserStateCookie.getValue();
        }

        //Add all parameters to authentication context before sending to authentication framework
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        Map<String, String[]> map = new HashMap<>();
        map.put(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM, new String[]{sessionDataKey});
        authenticationRequest.setRequestQueryParams(map);
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT, new String[]{"true"});
        try {
            authenticationRequest.setCommonAuthCallerPath(
                    ServiceURLBuilder.create().addPath(OIDC_LOGOUT_ENDPOINT).build().getRelativeInternalURL());
        } catch (URLBuilderException e) {
            log.error("Error building commonauth caller path to send logout request to framework.", e);
            if (logoutContext.isAPIBasedLogout()) {
                handleAPIBasedLogoutErrorResponse(new AuthServiceException(
                        getDefaultError(false).code(),
                        getDefaultError(false).description(), e), response);
            } else {
                response.sendRedirect(getRedirectURL(getErrorPageURL(OAuth2ErrorCodes.SERVER_ERROR,
                        "User logout failed."), request));
            }
            return;
        }
        authenticationRequest.setPost(true);

        if (StringUtils.isNotBlank(opBrowserStateCookieValue)) {
            OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(opBrowserStateCookieValue);
            if (cacheEntry != null) {
                authenticationRequest.setRelyingParty(
                        cacheEntry.getParamMap().get(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM));
                authenticationRequest.setTenantDomain(
                        cacheEntry.getParamMap().get(OIDCSessionConstants.OIDC_CACHE_TENANT_DOMAIN_PARAM));
                addOPBSCookieValueToCacheEntry(opBrowserStateCookieValue, cacheEntry);
                addSessionDataToCache(sessionDataKey, cacheEntry);
            }
        } else if (logoutContext.isAPIBasedLogout()) {
            authenticationRequest.setRelyingParty(logoutContext.getClientId());
            map.put(FrameworkConstants.RequestParams.SESSION_ID, new String[]{logoutContext.getSessionId()});
        }

        //Add headers to AuthenticationRequestContext
        for (Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String headerName = e.nextElement().toString();
            authenticationRequest.addHeader(headerName, request.getHeader(headerName));
        }

        AuthenticationRequestCacheEntry authenticationRequestCacheEntry =
                new AuthenticationRequestCacheEntry(authenticationRequest);
        addAuthenticationRequestToRequest(request, authenticationRequestCacheEntry);
        OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
        sendRequestToFramework(request, response, sessionDataKey, FrameworkConstants.RequestType.CLAIM_TYPE_OIDC,
                logoutContext);
    }

    private void addOPBSCookieValueToCacheEntry(String opBrowserStateCookieValue,
                                                OIDCSessionDataCacheEntry cacheEntry) {

        ConcurrentMap<String, String> paramMap = cacheEntry.getParamMap();
        if (paramMap == null) {
            paramMap = new ConcurrentHashMap<>();
        }
        paramMap.put(OIDCSessionConstants.OPBS_COOKIE_ID, opBrowserStateCookieValue);
        cacheEntry.setParamMap(paramMap);
    }

    private void handleLogoutResponseFromFramework(HttpServletRequest request, HttpServletResponse response,
                                                   LogoutContext logoutContext)
            throws IOException {

        if (logoutContext.isAPIBasedLogout() && logoutContext.isAPIBasedLogoutWithoutCookies()) {
            clearTokenBindingElements(logoutContext.getClientId(), request, response);
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        String sessionDataKey = request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
        OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(sessionDataKey);

        if (cacheEntry != null) {
            String obpsCookieValue = getOPBrowserState(request);
            String tenantDomain = OAuth2Util.resolveTenantDomain(request);
            if (log.isDebugEnabled()) {
                String clientId = cacheEntry.getParamMap().get(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM);
                String sidClaim;
                log.debug("Logout request received from client: " + clientId);

                if (StringUtils.isNotBlank(obpsCookieValue)) {
                    OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                            .getOIDCSessionState(obpsCookieValue, tenantDomain);
                    if (sessionState != null) {
                        sidClaim = sessionState.getSidClaim();
                        log.debug("Logout request received for sessionId: " + sidClaim);
                    }
                }
            }
            // BackChannel logout request.
            doBackChannelLogout(obpsCookieValue, tenantDomain);
            String redirectURL = cacheEntry.getPostLogoutRedirectUri();
            if (redirectURL == null) {
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutURL();
            }

            try {
                triggerLogoutHandlersForPostLogout(request, response);
            } catch (OIDCSessionManagementException e) {
                log.error("Error executing logout handlers on post logout.");
                if (log.isDebugEnabled()) {
                    log.debug("Error executing logout handlers on post logout.", e);
                }
                if (logoutContext.isAPIBasedLogout()) {
                    handleAPIBasedLogoutErrorResponse(new AuthServiceException(
                            getDefaultError(false).code(),
                            getDefaultError(false).description(), e), response);
                } else {
                    response.sendRedirect(getRedirectURL(getErrorPageURL(OAuth2ErrorCodes.SERVER_ERROR,
                            "User logout failed."), request));
                }
                return;
            }

            redirectURL = appendStateQueryParam(redirectURL, cacheEntry.getState());
            removeSessionDataFromCache(sessionDataKey);
            OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(obpsCookieValue, tenantDomain);
            // Clear binding elements from the response.
            clearTokenBindingElements(cacheEntry.getParamMap().get(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM),
                    request, response);
            if (logoutContext.isAPIBasedLogout()) {
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                response.sendRedirect(buildRedirectURLAfterLogout(redirectURL, request));
            }
        } else {
            if (logoutContext.isAPIBasedLogout()) {
                handleAPIBasedLogoutErrorResponse(new AuthServiceException(
                        getDefaultError(false).code(),
                        getDefaultError(false).description()), response);
            } else {
                response.sendRedirect(getRedirectURL(getErrorPageURL(OAuth2ErrorCodes.SERVER_ERROR,
                        "User logout failed"), request));
            }
        }
    }

    private void triggerLogoutHandlersForPostLogout(HttpServletRequest request, HttpServletResponse response)
            throws OIDCSessionManagementException {

        List<OIDCLogoutHandler> oidcLogoutHandlers =
                OIDCSessionManagementComponentServiceHolder.getOIDCLogoutHandlers();

        for (OIDCLogoutHandler oidcLogoutHandler : oidcLogoutHandlers) {
            oidcLogoutHandler.handlePostLogout(request, response);
        }
    }

    private void triggerLogoutHandlersForPreLogout(HttpServletRequest request, HttpServletResponse response)
            throws OIDCSessionManagementException {

        List<OIDCLogoutHandler> oidcLogoutHandlers =
                OIDCSessionManagementComponentServiceHolder.getOIDCLogoutHandlers();

        for (OIDCLogoutHandler oidcLogoutHandler : oidcLogoutHandlers) {
            oidcLogoutHandler.handlePreLogout(request, response);
        }
    }

    private void addAuthenticationRequestToRequest(HttpServletRequest request,
                                                   AuthenticationRequestCacheEntry authRequest) {

        request.setAttribute(FrameworkConstants.RequestAttribute.AUTH_REQUEST, authRequest);
    }

    private void sendRequestToFramework(HttpServletRequest request, HttpServletResponse response, String sessionDataKey,
                                        String type, LogoutContext logoutContext) throws ServletException, IOException {

        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

        CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(request);
        if (logoutContext.isAPIBasedLogout() && logoutContext.isAPIBasedLogoutWithoutCookies()) {
            // Setting this attribute as the framework checks for it to obtain the session id in an api based flow.
            request.setAttribute(FrameworkConstants.IS_API_BASED_AUTH_FLOW, true);
            requestWrapper.setParameter(FrameworkConstants.RequestParams.SESSION_ID, logoutContext.getSessionId());
        }
        requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
        requestWrapper.setParameter(FrameworkConstants.RequestParams.TYPE, type);

        CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(response);
        commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);

        Object object = request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);

        if (object != null) {
            AuthenticatorFlowStatus status = (AuthenticatorFlowStatus) object;
            if (status == AuthenticatorFlowStatus.INCOMPLETE) {
                if (responseWrapper.isRedirect()) {
                    response.sendRedirect(responseWrapper.getRedirectURL());
                } else if (responseWrapper.getContent().length > 0) {
                    responseWrapper.write();
                }
            } else {
                handleLogoutResponseFromFramework(requestWrapper, response, logoutContext);
            }
        } else {
            handleLogoutResponseFromFramework(requestWrapper, response, logoutContext);
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
     * Returns the OpenIDConnect User logout Consent.
     *
     * @param request Http Servlet Request.
     * @return True/False whether the user skip user consent or not.
     * @throws ParseException          Error in retrieving the clientId.
     * @throws IdentityOAuth2Exception Error in retrieving service provider associated with the OAuth clientId.
     */
    private boolean getOpenIDConnectSkipUserConsent(HttpServletRequest request) throws ParseException,
            IdentityOAuth2Exception {

        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);
        boolean skipLogoutConsent =
                OAuthServerConfiguration.getInstance().getOpenIDConnectSkipLogoutConsentConfig();
        if (skipLogoutConsent) {
            if (log.isDebugEnabled()) {
                log.debug("Server wide configuration is to skip the logout consent. So continue without " +
                        "checking for the service provider level configuration.");
            }
            return true;
        }
        if (StringUtils.isBlank(clientId) && StringUtils.isNotBlank(idTokenHint)) {
            clientId = getClientIdFromIdToken(request, idTokenHint);
        }
        if (StringUtils.isNotBlank(clientId)) {
            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
            if (serviceProvider != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Get the skip logout consent from service provider with client ID: " + clientId);
                }
                return FrameworkUtils.isLogoutConsentPageSkippedForSP(serviceProvider);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Could not able to identify the service provider, so prompting the logout consent.");
        }
        return false;
    }

    /**
     * Sends logout token to registered back-channel logout uris.
     *
     * @param opbsCookieValue OP browser state cookie value.
     * @param tenantDomain    Tenant Domain.
     */
    private void doBackChannelLogout(String opbsCookieValue, String tenantDomain) {

        LogoutRequestSender.getInstance().sendLogoutRequests(opbsCookieValue, tenantDomain);
        if (log.isDebugEnabled()) {
            log.debug("Sending backchannel logout request.");
        }
    }

    private void setSPAttributeToRequest(HttpServletRequest req, String spName, String tenantDomain) {

        req.setAttribute(REQUEST_PARAM_SP, spName);
        req.setAttribute(TENANT_DOMAIN, tenantDomain);
    }

    private String getServiceProviderName(String clientId, String tenantDomain) {

        String spName = null;
        try {
            spName = OIDCSessionManagementComponentServiceHolder.getApplicationMgtService()
                    .getServiceProviderNameByClientId(clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            log.error("Error while getting Service provider name for client Id:" + clientId + " in tenant: " +
                    tenantDomain, e);
        }
        return spName;
    }

    private void handleMissingSessionStateGracefully(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String redirectURL = OIDCSessionManagementUtil.getOIDCLogoutURL();
        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);
        String postLogoutRedirectUri = request.getParameter(OIDCSessionConstants.OIDC_POST_LOGOUT_REDIRECT_URI_PARAM);
        if ((StringUtils.isBlank(clientId) && StringUtils.isBlank(idTokenHint)) ||
                StringUtils.isBlank(postLogoutRedirectUri)) {
            String state = request
                    .getParameter(OIDCSessionConstants.OIDC_STATE_PARAM);
            redirectURL = appendStateQueryParam(redirectURL, state);
            response.sendRedirect(getRedirectURL(redirectURL, request));
            return;
        }
        if (StringUtils.isBlank(clientId)) {
            try {
                clientId = getClientIdFromIdToken(request, idTokenHint);
            } catch (ParseException e) {
                String msg = "Error occurred while extracting data from id token.";
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while retrieving client id from id token.", e);
                }
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            } catch (IdentityOAuth2Exception e) {
                String msg = "Error occurred while decrypting the id token (JWE).";
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while decrypting the id token (JWE).", e);
                }
                redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            }
            if (!validateIdToken(idTokenHint) && !OIDCSessionManagementUtil.isIDTokenEncrypted(idTokenHint)) {
                String msg = "ID token signature validation failed.";
                if (log.isDebugEnabled()) {
                    log.debug(msg + " Client id from id token: " + clientId);
                }
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                response.sendRedirect(getRedirectURL(redirectURL, request));
                return;
            }
        }
        try {
            String callbackUrl = OAuth2Util.getAppInformationByClientId(clientId).getCallbackUrl();
            if (validatePostLogoutUri(postLogoutRedirectUri, callbackUrl)) {
                redirectURL = postLogoutRedirectUri;
            } else {
                redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED,
                        "Post logout URI does not match with registered callback URI.");
            }
        } catch (InvalidOAuthClientException e) {
            String msg = "Error occurred while getting application information. Client id not found.";
            if (log.isDebugEnabled()) {
                log.debug(msg + " Client id from id token: " + clientId, e);
            }
            redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
        } catch (IdentityOAuth2Exception e) {
            String msg = "Error occurred while getting application information. Client id not found.";
            log.error(msg + " Client id from id token: " + clientId, e);
            redirectURL = getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
        }
        String state = request
                .getParameter(OIDCSessionConstants.OIDC_STATE_PARAM);
        redirectURL = appendStateQueryParam(redirectURL, state);
        response.sendRedirect(getRedirectURL(redirectURL, request));
    }

    private void clearTokenBindingElements(String clientId, HttpServletRequest request, HttpServletResponse response) {

        if (StringUtils.isBlank(clientId)) {
            log.debug("Logout request received without a client id. "
                    + "So skipping the clearing token binding element.");
            return;
        }

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception e) {
            log.error("Failed to load the app information for the client id: " + clientId, e);
            return;
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("The application with client id: " + clientId
                        + " does not exists. This application may be deleted after this session is created.", e);
            }
            return;
        }

        if (StringUtils.isBlank(oAuthAppDO.getTokenBindingType())) {
            return;
        }

        List<TokenBinder> tokenBinders = OIDCSessionManagementComponentServiceHolder.getInstance().getTokenBinders();
        if (tokenBinders.isEmpty()) {
            return;
        }

        tokenBinders.stream().filter(t -> oAuthAppDO.getTokenBindingType().equals(t.getBindingType())).findAny()
                .ifPresent(t -> t.clearTokenBindingElements(request, response));
    }

    private String buildRedirectURLAfterLogout(String redirectURL, HttpServletRequest request) {

        if (OIDCSessionManagementUtil.isAllowAdditionalParamsFromPostLogoutRedirectURIEnabled()) {
            return getRedirectURL(redirectURL, request);
        }
        return redirectURL;
    }

    private String getClientIdFromIdToken(HttpServletRequest request, String idToken)
            throws IdentityOAuth2Exception, ParseException {

        if (OIDCSessionManagementUtil.isIDTokenEncrypted(idToken)) {
            String appTenantDomain = request.getParameter(OIDCSessionConstants.OIDC_TENANT_DOMAIN_PARAM);
            if (StringUtils.isBlank(appTenantDomain)) {
                appTenantDomain = IdentityTenantUtil.resolveTenantDomain();
            }
            JWT decryptedIDToken = OIDCSessionManagementUtil.decryptWithRSA(appTenantDomain, idToken);
            return OIDCSessionManagementUtil.extractClientIDFromDecryptedIDToken(decryptedIDToken);
        } else {
            if (!validateIdToken(idToken)) {
                throw new IdentityOAuth2Exception(OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_ID_TOKEN,
                        "ID token signature validation failed.");
            }
            return extractClientFromIdToken(idToken);
        }
    }

    private String getSessionIdFromIdToken(HttpServletRequest request, String idToken)
            throws IdentityOAuth2Exception, ParseException {

        if (OIDCSessionManagementUtil.isIDTokenEncrypted(idToken)) {
            String appTenantDomain = request.getParameter(OIDCSessionConstants.OIDC_TENANT_DOMAIN_PARAM);
            if (StringUtils.isBlank(appTenantDomain)) {
                appTenantDomain = IdentityTenantUtil.resolveTenantDomain();
            }
            JWT decryptedIDToken = OIDCSessionManagementUtil.decryptWithRSA(appTenantDomain, idToken);
            return (String) decryptedIDToken.getJWTClaimsSet().getClaims()
                    .get(OAuthConstants.OIDCClaims.IDP_SESSION_KEY);
        } else {
            if (!validateIdToken(idToken)) {
                throw new IdentityOAuth2Exception(OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_ID_TOKEN,
                        "ID token signature validation failed.");
            }
            return (String) SignedJWT.parse(idToken).getJWTClaimsSet()
                    .getClaims().get(OAuthConstants.OIDCClaims.IDP_SESSION_KEY);
        }
    }

    private boolean canHandleAPIBasedLogoutFromCookies(HttpServletRequest request) {

        String opBrowserState = getOPBrowserState(request);
        if (StringUtils.isNotBlank(opBrowserState)) {
            return OIDCSessionManagementUtil.getSessionManager().sessionExists(opBrowserState,
                    OAuth2Util.resolveTenantDomain(request));
        }
        return false;
    }

    private boolean isAPIBasedLogoutFlow(HttpServletRequest request) throws AuthServiceException {

        boolean isAPIBasedRequest = OAuth2Util.isApiBasedAuthenticationFlow(request);
        if (isAPIBasedRequest) {
            String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
            String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);

            if (StringUtils.isBlank(clientId) && StringUtils.isNotBlank(idTokenHint)) {
                try {
                    clientId = getClientIdFromIdToken(request, idTokenHint);
                } catch (IdentityOAuth2Exception | ParseException e) {
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT.code(),
                            AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT.description(), e);
                }
            }
            if (StringUtils.isNotBlank(clientId)) {
                ServiceProvider serviceProvider;
                try {
                    serviceProvider = OAuth2Util.getServiceProvider(clientId);
                } catch (IdentityOAuth2Exception e) {
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT.code(),
                            AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT.description(), e);
                }
                if (serviceProvider != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Checking if API based authentication is enabled in the app: " + clientId);
                    }
                    if (serviceProvider.isAPIBasedAuthenticationEnabled()) {
                        return true;
                    } else {
                        throw new AuthServiceClientException(
                                AuthServiceConstants.ErrorMessage.ERROR_API_BASED_AUTH_NOT_ENABLED.code(),
                                "App native authentication should be enabled in the app to perform app native logout.");
                    }
                }
            } else {
                throw new AuthServiceClientException(
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_LOGOUT_REQUEST.code(),
                        "Unable to resolve client_id to perform app native logout.");
            }
        }

        return false;
    }

    private void populateAPIBasedLogoutContext(HttpServletRequest request, LogoutContext context)
            throws AuthServiceException {

        context.setAPIBasedLogout(true);
        boolean isAPIBasedLogoutWithCookies = canHandleAPIBasedLogoutFromCookies(request);
        if (isAPIBasedLogoutWithCookies) {
            context.setAPIBasedLogoutWithoutCookies(false);
        } else {
            String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
            if (StringUtils.isBlank(idTokenHint)) {
                throw new AuthServiceClientException(
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_LOGOUT_REQUEST.code(),
                        "App native logout required the session cookies or the id_token.");
            }
            try {
                String isk = getSessionIdFromIdToken(request, idTokenHint);
                context.setSessionId(isk);
                String clientId = getClientIdFromIdToken(request, idTokenHint);
                context.setClientId(clientId);
            } catch (IdentityOAuth2Exception | ParseException e) {
                throw new AuthServiceException(
                        AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT.code(),
                        AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT.description(), e);
            }
            context.setAPIBasedLogoutWithoutCookies(true);
            request.setAttribute(OAuthConstants.IS_API_BASED_LOGOUT_WITHOUT_COOKIES, true);
        }
    }

    private void handleAPIBasedLogoutErrorResponse(AuthServiceException exception, HttpServletResponse response)
            throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Error while handling logout request.", exception);
        }

        boolean isClientError = exception instanceof AuthServiceClientException;
        APIError apiError = new APIError();
        Optional<AuthServiceConstants.ErrorMessage> error =
                AuthServiceConstants.ErrorMessage.fromCode(exception.getErrorCode());

        String errorCode = exception.getErrorCode() != null ?
                exception.getErrorCode() : getDefaultError(isClientError).code();

        String errorMessage;
        if (error.isPresent()) {
            errorMessage = error.get().message();
        } else {
            errorMessage = getDefaultError(isClientError).message();
        }

        String errorDescription;
        if (StringUtils.isNotBlank(exception.getMessage())) {
            errorDescription = exception.getMessage();
        } else {
            if (error.isPresent()) {
                errorDescription = error.get().description();
            } else {
                errorDescription = getDefaultError(isClientError).description();
            }
        }

        apiError.setCode(errorCode);
        apiError.setMessage(errorMessage);
        apiError.setDescription(errorDescription);
        apiError.setTraceId(getCorrelationId());
        String jsonString = new Gson().toJson(apiError);

        int statusCode = isClientError ? HttpServletResponse.SC_BAD_REQUEST :
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

        response.setStatus(statusCode);
        response.setContentType(OAuthConstants.HTTP_RESP_CONTENT_TYPE_JSON);
        response.setCharacterEncoding(UTF_8);
        PrintWriter writer = response.getWriter();
        writer.write(jsonString);
        writer.flush();
        writer.close();
    }

    private static String getCorrelationId() {

        String ref;
        if (isCorrelationIDPresent()) {
            ref = MDC.get(FrameworkUtils.CORRELATION_ID_MDC);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Correlation id is not present in the log MDC.");
            }
            ref = StringUtils.EMPTY;
        }
        return ref;
    }

    private static boolean isCorrelationIDPresent() {

        return MDC.get(FrameworkUtils.CORRELATION_ID_MDC) != null;
    }

    private static AuthServiceConstants.ErrorMessage getDefaultError(boolean isClientError) {

        if (isClientError) {
            return AuthServiceConstants.ErrorMessage.ERROR_INVALID_LOGOUT_REQUEST;
        }
        return AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED_LOGOUT;
    }
}
