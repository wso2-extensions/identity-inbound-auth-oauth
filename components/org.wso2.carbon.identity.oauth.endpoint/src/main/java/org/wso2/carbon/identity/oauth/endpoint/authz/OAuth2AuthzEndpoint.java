/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.authz;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBindingContext;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBindingHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.openidconnect.OIDCRequestObjectFactory;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.INITIAL_REQUEST;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.PASSTHROUGH_TO_COMMONAUTH;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.USER_CONSENT_RESPONSE;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getApplicationManagementService;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getErrorPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getLoginPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuthServerConfiguration;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.startSuperTenantFlow;   
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;

@Path("/authorize")
public class OAuth2AuthzEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2AuthzEndpoint.class);
    private static final String APPROVE = "approve";
    private static final String CONSENT = "consent";
    private static final String AUTHENTICATED_ID_PS = "AuthenticatedIdPs";
    private static final String BEARER = "Bearer";
    private static final String ACR_VALUES = "acr_values";
    private static final String CLAIMS = "claims";
    private boolean isCacheAvailable = false;

    private static final String REDIRECT_URI = "redirect_uri";
    private static final String RESPONSE_MODE_FORM_POST = "form_post";
    private static final String RESPONSE_MODE = "response_mode";
    private static final String RETAIN_CACHE = "retainCache";
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";

    private static final String formPostRedirectPage = getFormPostRedirectPage();
    private static final String DISPLAY_NAME = "DisplayName";

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException {

        startSuperTenantFlow();
        OAuthMessage oAuthMessage = buildOAuthMessage(request, response);
        try {
            if (isPassthroughToFramework(oAuthMessage)) {
                return handleAuthFlowThroughFramework(oAuthMessage);
            } else if (isInitialRequestFromClient(oAuthMessage)) {
                return handleInitialAuthorizationRequest(oAuthMessage);
            } else if (isAuthenticationResponseFromFramework(oAuthMessage)) {
                return handleAuthenticationResponse(oAuthMessage);
            } else if (isConsentResponseFromUser(oAuthMessage)) {
                return handleResponseFromConsent(oAuthMessage);
            } else {
                return handleInvalidRequest();
            }
        } catch (OAuthProblemException e) {
            return handleOAuthProblemException(oAuthMessage, e);
        } catch (OAuthSystemException e) {
            return handleOAuthSystemException(oAuthMessage.getSessionDataCacheEntry(), e);
        } finally {
            handleRetainCache(oAuthMessage);
            PrivilegedCarbonContext.endTenantFlow();
        }
    }


    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response authorizePost(@Context HttpServletRequest request, @Context HttpServletResponse response, MultivaluedMap paramMap)
            throws URISyntaxException, InvalidRequestParentException {

        // Validate repeated parameters
        if (!validateParams(request, paramMap)) {
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).location(new URI(
                    getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid authorization request with repeated parameters", null))).build();
        }
        HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
        return authorize(httpRequest, response);
    }

    private Response handleInvalidRequest() throws URISyntaxException {
        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request");
        }

        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(getErrorPageURL
                (OAuth2ErrorCodes.INVALID_REQUEST, "Invalid authorization request", null))).build();
    }

    private void handleRetainCache(OAuthMessage oAuthMessage) {
        String sessionDataKeyFromConsent = oAuthMessage.getRequest().getParameter(OAuthConstants.SESSION_DATA_KEY_CONSENT);
        if (sessionDataKeyFromConsent != null) {
            /*
             * TODO Cache retaining is a temporary fix. Remove after Google fixes
             * http://code.google.com/p/gdata-issues/issues/detail?id=6628
             */
            String retainCache = System.getProperty(RETAIN_CACHE);

            if (retainCache == null) {
                clearCacheEntry(sessionDataKeyFromConsent);
            }
        }
    }

    private boolean isConsentResponseFromUser(OAuthMessage oAuthMessage) {
        return USER_CONSENT_RESPONSE.equals(oAuthMessage.getRequestType());
    }

    private boolean isAuthenticationResponseFromFramework(OAuthMessage oAuthMessage) {
        return AUTHENTICATION_RESPONSE.equals(oAuthMessage.getRequestType());
    }

    private boolean isInitialRequestFromClient(OAuthMessage oAuthMessage) {
        return INITIAL_REQUEST.equals(oAuthMessage.getRequestType());
    }

    private boolean isPassthroughToFramework(OAuthMessage oAuthMessage) {
        return PASSTHROUGH_TO_COMMONAUTH.equals(oAuthMessage.getRequestType());
    }

    private OAuthMessage buildOAuthMessage(HttpServletRequest request, HttpServletResponse response)
            throws InvalidRequestParentException {
        return new OAuthMessage.OAuthMessageBuilder()
                .setRequest(request)
                .setResponse(response)
                .build();
    }

    private Response handleOAuthSystemException(SessionDataCacheEntry sessionDataCacheEntry, OAuthSystemException e) throws URISyntaxException {
        OAuth2Parameters params = null;
        if (sessionDataCacheEntry != null) {
            params = sessionDataCacheEntry.getoAuth2Parameters();
        }
        if (log.isDebugEnabled()) {
            log.debug("Server error occurred while performing authorization", e);
        }
        OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.SERVER_ERROR,
                "Server error occurred while performing authorization");
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                EndpointUtil.getErrorRedirectURL(ex, params))).build();
    }

    private Response handleOAuthProblemException(OAuthMessage oAuthMessage, OAuthProblemException e) throws URISyntaxException {

        if (log.isDebugEnabled()) {
            log.debug(e.getError(), e);
        }

        String errorPageURL = getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST, e.getMessage(), null);
        String redirectURI = oAuthMessage.getRequest().getParameter(REDIRECT_URI);

        if (redirectURI != null) {
            try {
                errorPageURL = errorPageURL + "&" + REDIRECT_URI + "=" + URLEncoder
                        .encode(redirectURI, StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e1) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while encoding the error page url", e);
                }
            }
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(errorPageURL))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_TYPE).build();
    }

    private static String getFormPostRedirectPage() {

        java.nio.file.Path path = Paths.get(CarbonUtils.getCarbonHome(), "repository", "resources",
                "identity", "pages", "oauth_response.html");
        if (Files.exists(path)) {
            try {
                return new Scanner(Files.newInputStream(path), "UTF-8").useDelimiter("\\A").next();
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to find OAuth From post response page in : " + path.toString());
                }
            }
        }
        return null;
    }

    private Response handleResponseFromConsent(OAuthMessage oAuthMessage) throws OAuthSystemException,
            URISyntaxException {

        updateAuthTimeInSessionDataCacheEntry(oAuthMessage);
        String consent = getConsentFromRequest(oAuthMessage);

        if (consent != null) {
            if (OAuthConstants.Consent.DENY.equals(consent)) {
                return handleDenyConsent(oAuthMessage);
            }

            OIDCSessionState sessionState = new OIDCSessionState();
            String redirectURL = handleUserConsent(oAuthMessage, consent, sessionState);

            if (isFormPostResponseMode(oAuthMessage, redirectURL)) {
                return handleFormPostResponseMode(oAuthMessage, sessionState, redirectURL);
            }

            redirectURL = manageOIDCSessionState(oAuthMessage, sessionState, redirectURL);
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(redirectURL)).build();
        } else {
            return handleEmptyConsent(oAuthMessage);
        }
    }

    private String getConsentFromRequest(OAuthMessage oAuthMessage) {
        return oAuthMessage.getRequest().getParameter(CONSENT);
    }

    private Response handleEmptyConsent(OAuthMessage oAuthMessage) throws URISyntaxException {

        String appName = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters().getApplicationName();

        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request. \'sessionDataKey\' parameter found but \'consent\' " +
                    "parameter could not be found in request");
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid authorization " +
                        "request", appName))).build();
    }

    private String manageOIDCSessionState(OAuthMessage oAuthMessage, OIDCSessionState sessionState, String redirectURL) {

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());
        if (isOIDCRequest) {
            sessionState.setAddSessionState(true);
            return manageOIDCSessionState(oAuthMessage.getRequest(), oAuthMessage.getResponse(), sessionState, oauth2Params,
                    oAuthMessage.getSessionDataCacheEntry().getLoggedInUser().getAuthenticatedSubjectIdentifier(), redirectURL);
        }
        return redirectURL;
    }

    private Response handleFormPostResponseMode(OAuthMessage oAuthMessage,
                                                OIDCSessionState sessionState, String redirectURL) {

        String authenticatedIdPs = oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs();
        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());

        String sessionStateValue = null;
        if (isOIDCRequest) {
            sessionState.setAddSessionState(true);
            sessionStateValue = manageOIDCSessionState(oAuthMessage.getRequest(), oAuthMessage.getResponse(),
                    sessionState,
                    oauth2Params,
                    oAuthMessage.getSessionDataCacheEntry().getLoggedInUser().getAuthenticatedSubjectIdentifier(),
                    redirectURL);
        }

        return Response.ok(createFormPage(redirectURL, oauth2Params.getRedirectURI(),
                authenticatedIdPs, sessionStateValue)).build();
    }

    private Response handleDenyConsent(OAuthMessage oAuthMessage) throws OAuthSystemException, URISyntaxException {

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());

        OpenIDConnectUserRPStore.getInstance().putUserRPToStore(oAuthMessage.getSessionDataCacheEntry().getLoggedInUser(),
                oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters().getApplicationName(),
                false, oauth2Params.getClientId());
        // return an error if user denied
        OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.ACCESS_DENIED);
        String denyResponse = EndpointUtil.getErrorRedirectURL(ex, oauth2Params);

        if (isOIDCRequest) {
            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie
                    (oAuthMessage.getRequest());
            denyResponse = OIDCSessionManagementUtil
                    .addSessionStateToURL(denyResponse, oauth2Params.getClientId(),
                            oauth2Params.getRedirectURI(), opBrowserStateCookie,
                            oauth2Params.getResponseType());
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(denyResponse)).build();
    }

    private Response handleAuthenticationResponse(OAuthMessage oAuthMessage) throws OAuthSystemException, URISyntaxException {

        updateAuthTimeInSessionDataCacheEntry(oAuthMessage);

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        AuthenticationResult authnResult = getAuthenticationResult(oAuthMessage, oAuthMessage.getSessionDataKeyFromLogin());
        if (isAuthnResultFound(authnResult)) {
            removeAuthenticationResult(oAuthMessage, oAuthMessage.getSessionDataKeyFromLogin());

            if (authnResult.isAuthenticated()) {
                return handleSuccessAuthentication(oAuthMessage, oauth2Params, authnResult);
            } else {
                return handleFailedAuthentication(oAuthMessage, oauth2Params, authnResult);
            }
        } else {
            return handleEmptyAuthenticationResult(oAuthMessage);
        }
    }

    private boolean isAuthnResultFound(AuthenticationResult authnResult) {
        return authnResult != null;
    }

    private Response handleSuccessAuthentication(OAuthMessage oAuthMessage,
                                                 OAuth2Parameters oauth2Params, AuthenticationResult authnResult)
            throws OAuthSystemException, URISyntaxException {

        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());
        AuthenticatedUser authenticatedUser = authnResult.getSubject();
        if (authenticatedUser.getUserAttributes() != null) {
            authenticatedUser.setUserAttributes(new ConcurrentHashMap<>(
                    authenticatedUser.getUserAttributes()));
        }

        AddToSessionDataCache(oAuthMessage, authnResult, authenticatedUser);

        OIDCSessionState sessionState = new OIDCSessionState();
        String redirectURL = doUserAuthz(oAuthMessage, oAuthMessage.getSessionDataKeyFromLogin(), sessionState);

        if (isFormPostResponseMode(oAuthMessage, redirectURL)) {
            return handleFormPostMode(oAuthMessage, oauth2Params, redirectURL, isOIDCRequest, sessionState);
        }

        if (isOIDCRequest) {
            redirectURL = manageOIDCSessionState(oAuthMessage.getRequest(), oAuthMessage.getResponse(),
                    sessionState, oauth2Params, authenticatedUser.getAuthenticatedSubjectIdentifier(),
                    redirectURL);
        }

        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(redirectURL)).build();
    }

    private Response handleFailedAuthentication(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params,
                                                AuthenticationResult authnResult) throws URISyntaxException {

        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());
        OAuthProblemException oauthException = buildOAuthProblemException(authnResult);
        String redirectURL = EndpointUtil.getErrorRedirectURL(oauthException, oauth2Params);
        if (isOIDCRequest) {
            redirectURL = handleOIDCSessionState(oAuthMessage, oauth2Params, redirectURL);
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(redirectURL)).build();

    }

    private String handleOIDCSessionState(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params, String redirectURL) {
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie
                (oAuthMessage.getRequest());
        return OIDCSessionManagementUtil
                .addSessionStateToURL(redirectURL, oauth2Params.getClientId(),
                        oauth2Params.getRedirectURI(), opBrowserStateCookie,
                        oauth2Params.getResponseType());
    }

    private Response handleEmptyAuthenticationResult(OAuthMessage oAuthMessage) throws URISyntaxException {

        String appName = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters().getApplicationName();

        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request. \'sessionDataKey\' attribute found but " +
                    "corresponding AuthenticationResult does not exist in the cache.");
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid authorization request",
                        appName))).build();
    }

    private Response handleFormPostMode(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params, String redirectURL, boolean isOIDCRequest, OIDCSessionState sessionState) {
        String sessionStateValue = null;
        if (isOIDCRequest) {
            sessionState.setAddSessionState(true);
            sessionStateValue = manageOIDCSessionState(oAuthMessage.getRequest(), oAuthMessage.getResponse(),
                    sessionState,
                    oauth2Params,
                    oAuthMessage.getSessionDataCacheEntry().getLoggedInUser().getAuthenticatedSubjectIdentifier(),
                    redirectURL);
        }

        return Response.ok(createFormPage(redirectURL, oauth2Params.getRedirectURI(),
                StringUtils.EMPTY, sessionStateValue)).build();
    }

    private void AddToSessionDataCache(OAuthMessage oAuthMessage, AuthenticationResult authnResult, AuthenticatedUser authenticatedUser) {

        oAuthMessage.getSessionDataCacheEntry().setLoggedInUser(authenticatedUser);
        oAuthMessage.getSessionDataCacheEntry().setAuthenticatedIdPs(authnResult.getAuthenticatedIdPs());
        SessionDataCacheKey cacheKey = new SessionDataCacheKey(oAuthMessage.getSessionDataKeyFromLogin());
        SessionDataCache.getInstance().addToCache(cacheKey, oAuthMessage.getSessionDataCacheEntry());
    }

    private void updateAuthTimeInSessionDataCacheEntry(OAuthMessage oAuthMessage) {

        Cookie cookie = FrameworkUtils.getAuthCookie(oAuthMessage.getRequest());
        long authTime = getAuthenticatedTimeFromCommonAuthCookie(cookie);

        if (authTime > 0) {
            oAuthMessage.getSessionDataCacheEntry().setAuthTime(authTime);
        }
    }

    private boolean isFormPostResponseMode(OAuthMessage oAuthMessage, String redirectURL) {
        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        return RESPONSE_MODE_FORM_POST.equals(oauth2Params.getResponseMode()) && isJSON(redirectURL);
    }

    private Response handleInitialAuthorizationRequest(OAuthMessage oAuthMessage) throws OAuthSystemException,
            OAuthProblemException, URISyntaxException, InvalidRequestParentException {

        String redirectURL = handleOAuthAuthorizationRequest(oAuthMessage);
        String type = getRequestProtocolType(oAuthMessage);

        if (AuthenticatorFlowStatus.SUCCESS_COMPLETED == oAuthMessage.getFlowStatus()) {
            return handleAuthFlowThroughFramework(oAuthMessage, type);
        } else {
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(redirectURL)).build();
        }
    }

    private String getRequestProtocolType(OAuthMessage oAuthMessage) {
        String type = OAuthConstants.Scope.OAUTH2;
        String scopes = oAuthMessage.getRequest().getParameter(OAuthConstants.OAuth10AParams.SCOPE);
        if (scopes != null && scopes.contains(OAuthConstants.Scope.OPENID)) {
            type = OAuthConstants.Scope.OIDC;
        }
        return type;
    }

    private boolean isJSON(String redirectURL) {

        try {
            new JSONObject(redirectURL);
        } catch (JSONException ex) {
            return false;
        }
        return true;
    }

    private String createFormPage(String jsonPayLoad, String redirectURI, String authenticatedIdPs,
                                  String sessionStateValue) {

        if (StringUtils.isNotBlank(formPostRedirectPage)) {
            String newPage = formPostRedirectPage;
            String pageWithRedirectURI = newPage.replace("$redirectURI", redirectURI);
            return pageWithRedirectURI.replace("<!--$params-->", buildParams(jsonPayLoad, authenticatedIdPs, sessionStateValue));
        }

        String formHead = "<html>\n" +
                "   <head><title>Submit This Form</title></head>\n" +
                "   <body onload=\"javascript:document.forms[0].submit()\">\n" +
                "    <p>Click the submit button if automatic redirection failed.</p>" +
                "    <form method=\"post\" action=\"" + redirectURI + "\">\n";

        String formBottom = "<input type=\"submit\" value=\"Submit\">" +
                "</form>\n" +
                "</body>\n" +
                "</html>";

        StringBuilder form = new StringBuilder(formHead);
        form.append(buildParams(jsonPayLoad, authenticatedIdPs, sessionStateValue));
        form.append(formBottom);
        return form.toString();
    }

    private String buildParams(String jsonPayLoad, String authenticatedIdPs, String sessionStateValue) {

        JSONObject jsonObject = new JSONObject(jsonPayLoad);
        StringBuilder paramStringBuilder = new StringBuilder();

        for (Object key : jsonObject.keySet()) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"")
                    .append(key)
                    .append("\"" + "value=\"")
                    .append(jsonObject.get(key.toString()))
                    .append("\"/>\n");
        }

        if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"AuthenticatedIdPs\" value=\"")
                    .append(authenticatedIdPs)
                    .append("\"/>\n");
        }

        if (sessionStateValue != null && !sessionStateValue.isEmpty()) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"session_state\" value=\"")
                    .append(sessionStateValue)
                    .append("\"/>\n");
        }
        return paramStringBuilder.toString();
    }


    private void removeAuthenticationResult(OAuthMessage oAuthMessage, String sessionDataKey) {

        if (isCacheAvailable) {
            FrameworkUtils.removeAuthenticationResultFromCache(sessionDataKey);
        } else {
            oAuthMessage.getRequest().removeAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT);
        }
    }

    private String handleUserConsent(OAuthMessage oAuthMessage, String consent, OIDCSessionState sessionState)
            throws OAuthSystemException {

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        storeUserConsent(oAuthMessage, consent);
        OAuthResponse oauthResponse;
        String responseType = oauth2Params.getResponseType();
        // authorizing the request
        OAuth2AuthorizeRespDTO authzRespDTO = authorize(oauth2Params, oAuthMessage.getSessionDataCacheEntry());

        if (isSucessAuthorization(authzRespDTO)) {
            oauthResponse = handleSuccessAuthorization(oAuthMessage, sessionState, oauth2Params, responseType, authzRespDTO);
        } else if (isFailureAuthorizationWithErorrCode(authzRespDTO)) {
            // Authorization failure due to various reasons
            return handleFailureAuthorization(sessionState, oauth2Params, authzRespDTO);
        } else {
            // Authorization failure due to various reasons
            return handleServerErrorAuthorization(sessionState, oauth2Params);
        }

        //When response_mode equals to form_post, body parameter is passed back.
        if (isFormPostModeAndResponseBodyExists(oauth2Params, oauthResponse)) {
            return oauthResponse.getBody();
        } else {
            //When responseType equal to "id_token" the resulting token is passed back as a query parameter
            //According to the specification it should pass as URL Fragment
            if (OAuthConstants.ID_TOKEN.equalsIgnoreCase(responseType)) {
                return buildIdTokenQueryParam(oauthResponse, authzRespDTO);
            } else {
                return appendAuthenticatedIDPs(oAuthMessage.getSessionDataCacheEntry(), oauthResponse.getLocationUri());
            }
        }
    }

    private String buildIdTokenQueryParam(OAuthResponse oauthResponse, OAuth2AuthorizeRespDTO authzRespDTO) {
        if (authzRespDTO.getCallbackURI().contains("?")) {
            return authzRespDTO.getCallbackURI() + "#" + StringUtils.substring(oauthResponse.getLocationUri()
                    , authzRespDTO.getCallbackURI().length() + 1);
        } else {
            return oauthResponse.getLocationUri().replace("?", "#");
        }
    }

    private boolean isFailureAuthorizationWithErorrCode(OAuth2AuthorizeRespDTO authzRespDTO) {
        return authzRespDTO != null && authzRespDTO.getErrorCode() != null;
    }

    private boolean isSucessAuthorization(OAuth2AuthorizeRespDTO authzRespDTO) {
        return authzRespDTO != null && authzRespDTO.getErrorCode() == null;
    }

    private void storeUserConsent(OAuthMessage oAuthMessage, String consent) throws OAuthSystemException {

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        String applicationName = oauth2Params.getApplicationName();
        AuthenticatedUser loggedInUser = oAuthMessage.getSessionDataCacheEntry().getLoggedInUser();
        String clientId = oauth2Params.getClientId();

        boolean skipConsent = getOAuthServerConfiguration().getOpenIDConnectSkipeUserConsentConfig();
        if (!skipConsent) {
            boolean approvedAlways = OAuthConstants.Consent.APPROVE_ALWAYS.equals(consent);
            if (approvedAlways) {
                OpenIDConnectUserRPStore.getInstance().putUserRPToStore(loggedInUser, applicationName,
                        true, clientId);
            }
        }
    }

    private boolean isFormPostModeAndResponseBodyExists(OAuth2Parameters oauth2Params, OAuthResponse oauthResponse) {
        return RESPONSE_MODE_FORM_POST.equals(oauth2Params.getResponseMode())
                && StringUtils.isNotEmpty(oauthResponse.getBody());
    }

    private String handleServerErrorAuthorization(OIDCSessionState sessionState, OAuth2Parameters oauth2Params) {

        sessionState.setAuthenticated(false);
        String errorCode = OAuth2ErrorCodes.SERVER_ERROR;
        String errorMsg = "Error occurred while processing the request";
        OAuthProblemException oauthProblemException = OAuthProblemException.error(
                errorCode, errorMsg);
        return EndpointUtil.getErrorRedirectURL(oauthProblemException, oauth2Params);
    }

    private String handleFailureAuthorization(OIDCSessionState sessionState, OAuth2Parameters oauth2Params, OAuth2AuthorizeRespDTO authzRespDTO) {

        sessionState.setAuthenticated(false);
        String errorMsg;
        if (authzRespDTO.getErrorMsg() != null) {
            errorMsg = authzRespDTO.getErrorMsg();
        } else {
            errorMsg = "Error occurred while processing the request";
        }
        OAuthProblemException oauthProblemException = OAuthProblemException.error(
                authzRespDTO.getErrorCode(), errorMsg);
        return EndpointUtil.getErrorRedirectURL(oauthProblemException, oauth2Params);
    }

    private OAuthResponse handleSuccessAuthorization(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                                     OAuth2Parameters oauth2Params, String responseType,
                                                     OAuth2AuthorizeRespDTO authzRespDTO) throws OAuthSystemException {

        OAuthASResponse.OAuthAuthorizationResponseBuilder builder = OAuthASResponse.authorizationResponse(
                oAuthMessage.getRequest(), HttpServletResponse.SC_FOUND);
        // all went okay
        if (isAuthorizationCodeExists(authzRespDTO)) {
            setAuthorizationCode(oAuthMessage, authzRespDTO, builder);
        }
        if (isResponseTypeNotIdTokenOrNone(responseType, authzRespDTO)) {
            setAccessToken(authzRespDTO, builder);
        }
        if (isIdTokenExists(authzRespDTO)) {
            setIdToken(authzRespDTO, builder);
        }
        if (StringUtils.isNotBlank(oauth2Params.getState())) {
            builder.setParam(OAuth.OAUTH_STATE, oauth2Params.getState());
        }
        String redirectURL = authzRespDTO.getCallbackURI();

        OAuthResponse oauthResponse;

        if (RESPONSE_MODE_FORM_POST.equals(oauth2Params.getResponseMode())) {
            oauthResponse = handleFormPostMode(oAuthMessage, builder, redirectURL);
        } else {
            oauthResponse = builder.location(redirectURL).buildQueryMessage();
        }

        sessionState.setAuthenticated(true);
        return oauthResponse;
    }

    private OAuthResponse handleFormPostMode(OAuthMessage oAuthMessage,
                                             OAuthASResponse.OAuthAuthorizationResponseBuilder builder,
                                             String redirectURL) throws OAuthSystemException {

        OAuthResponse oauthResponse;
        String authenticatedIdPs = oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs();
        if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
            builder.setParam(AUTHENTICATED_ID_PS, oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs());
        }
        oauthResponse = builder.location(redirectURL).buildJSONMessage();
        return oauthResponse;
    }

    private boolean isIdTokenExists(OAuth2AuthorizeRespDTO authzRespDTO) {
        return StringUtils.isNotBlank(authzRespDTO.getIdToken());
    }

    private boolean isResponseTypeNotIdTokenOrNone(String responseType, OAuth2AuthorizeRespDTO authzRespDTO) {
        return StringUtils.isNotBlank(authzRespDTO.getAccessToken()) &&
                !OAuthConstants.ID_TOKEN.equalsIgnoreCase(responseType) &&
                !OAuthConstants.NONE.equalsIgnoreCase(responseType);
    }

    private boolean isAuthorizationCodeExists(OAuth2AuthorizeRespDTO authzRespDTO) {
        return StringUtils.isNotBlank(authzRespDTO.getAuthorizationCode());
    }

    private void setIdToken(OAuth2AuthorizeRespDTO authzRespDTO, OAuthASResponse.OAuthAuthorizationResponseBuilder builder) {
        builder.setParam(OAuthConstants.ID_TOKEN, authzRespDTO.getIdToken());
    }

    private void setAuthorizationCode(OAuthMessage oAuthMessage, OAuth2AuthorizeRespDTO authzRespDTO,
                                      OAuthASResponse.OAuthAuthorizationResponseBuilder builder) {
        builder.setCode(authzRespDTO.getAuthorizationCode());
        addUserAttributesToCache(oAuthMessage.getSessionDataCacheEntry(), authzRespDTO.getAuthorizationCode(),
                authzRespDTO.getCodeId());
    }

    private void setAccessToken(OAuth2AuthorizeRespDTO authzRespDTO, OAuthASResponse.OAuthAuthorizationResponseBuilder builder) {
        builder.setAccessToken(authzRespDTO.getAccessToken());
        builder.setExpiresIn(authzRespDTO.getValidityPeriod());
        builder.setParam(OAuth.OAUTH_TOKEN_TYPE, BEARER);
    }

    private void addUserAttributesToCache(SessionDataCacheEntry sessionDataCacheEntry, String code, String codeId) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(code);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(
                sessionDataCacheEntry.getLoggedInUser().getUserAttributes());

        ClaimMapping key = new ClaimMapping();
        Claim claimOfKey = new Claim();
        claimOfKey.setClaimUri(OAuth2Util.SUB);
        key.setRemoteClaim(claimOfKey);
        String sub = sessionDataCacheEntry.getLoggedInUser().getUserAttributes().get(key);

        if (StringUtils.isBlank(sub)) {
            sub = sessionDataCacheEntry.getLoggedInUser().getAuthenticatedSubjectIdentifier();
        }
        if (StringUtils.isNotBlank(sub)) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                log.debug("Setting subject: " + sub + " as the sub claim in cache against the authorization code.");
            }
            authorizationGrantCacheEntry.setSubjectClaim(sub);
        }
        //PKCE
        String[] pkceCodeChallengeArray = sessionDataCacheEntry.getParamMap().get(
                OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE);
        String[] pkceCodeChallengeMethodArray = sessionDataCacheEntry.getParamMap().get(
                OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD);
        String pkceCodeChallenge = null;
        String pkceCodeChallengeMethod = null;

        if (ArrayUtils.isNotEmpty(pkceCodeChallengeArray)) {
            pkceCodeChallenge = pkceCodeChallengeArray[0];
        }
        if (ArrayUtils.isNotEmpty(pkceCodeChallengeMethodArray)) {
            pkceCodeChallengeMethod = pkceCodeChallengeMethodArray[0];
        }
        authorizationGrantCacheEntry.setAcrValue(sessionDataCacheEntry.getoAuth2Parameters().getACRValues());
        authorizationGrantCacheEntry.setNonceValue(sessionDataCacheEntry.getoAuth2Parameters().getNonce());
        authorizationGrantCacheEntry.setCodeId(codeId);
        authorizationGrantCacheEntry.setPkceCodeChallenge(pkceCodeChallenge);
        authorizationGrantCacheEntry.setPkceCodeChallengeMethod(pkceCodeChallengeMethod);
        authorizationGrantCacheEntry.setEssentialClaims(
                sessionDataCacheEntry.getoAuth2Parameters().getEssentialClaims());
        authorizationGrantCacheEntry.setAuthTime(sessionDataCacheEntry.getAuthTime());
        authorizationGrantCacheEntry.setRequestObject(sessionDataCacheEntry.getoAuth2Parameters().
                getRequestObject());
        AuthorizationGrantCache.getInstance().addToCacheByCode(
                authorizationGrantCacheKey, authorizationGrantCacheEntry);
    }

    /**
     * http://tools.ietf.org/html/rfc6749#section-4.1.2
     * <p/>
     * 4.1.2.1. Error Response
     * <p/>
     * If the request fails due to a missing, invalid, or mismatching
     * redirection URI, or if the client identifier is missing or invalid,
     * the authorization server SHOULD inform the resource owner of the
     * error and MUST NOT automatically redirect the user-agent to the
     * invalid redirection URI.
     * <p/>
     * If the resource owner denies the access request or if the request
     * fails for reasons other than a missing or invalid redirection URI,
     * the authorization server informs the client by adding the following
     * parameters to the query component of the redirection URI using the
     * "application/x-www-form-urlencoded" format
     *
     * @param oAuthMessage oAuthMessage
     * @return String redirectURL
     * @throws OAuthSystemException OAuthSystemException
     * @throws OAuthProblemException OAuthProblemException
     */
    private String handleOAuthAuthorizationRequest(OAuthMessage oAuthMessage)
            throws OAuthSystemException, OAuthProblemException {

        OAuth2ClientValidationResponseDTO validationResponse = validateClient(oAuthMessage);

        if (!validationResponse.isValidClient()) {
            return getErrorPageURL(validationResponse.getErrorCode(), validationResponse.getErrorMsg(), null);
        }

        CarbonOAuthAuthzRequest oauthRequest = new CarbonOAuthAuthzRequest(oAuthMessage.getRequest());

        OAuth2Parameters params = new OAuth2Parameters();
        String redirectURI = populateOauthParameters(params, oAuthMessage, validationResponse, oauthRequest);
        if (redirectURI != null) {
            return redirectURI;
        }

        String prompt = oauthRequest.getParam(OAuthConstants.OAuth20Params.PROMPT);
        params.setPrompt(prompt);

        redirectURI = analyzePromptParameter(oAuthMessage, params, prompt);
        if (redirectURI != null) {
            return redirectURI;
        }

        String sessionDataKey = UUIDGenerator.generateUUID();
        addDataToSessionCache(oAuthMessage, params, sessionDataKey);

        try {
            oAuthMessage.getRequest().setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus
                    .SUCCESS_COMPLETED);
            oAuthMessage.getRequest().setAttribute(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
            return getLoginPageURL(oAuthMessage.getClientId(), sessionDataKey, oAuthMessage.isForceAuthenticate(),
                    oAuthMessage.isPassiveAuthentication(), oauthRequest.getScopes(), oAuthMessage.getRequest().getParameterMap());

        } catch (IdentityOAuth2Exception e) {
            return handleException(e);
        }
    }

    private String handleException(IdentityOAuth2Exception e) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Error while retrieving the login page url.", e);
        }
        throw new OAuthSystemException("Error when encoding login page URL");
    }

    private void addDataToSessionCache(OAuthMessage oAuthMessage, OAuth2Parameters params, String sessionDataKey) {

        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
        SessionDataCacheEntry sessionDataCacheEntryNew = new SessionDataCacheEntry();
        sessionDataCacheEntryNew.setoAuth2Parameters(params);
        sessionDataCacheEntryNew.setQueryString(oAuthMessage.getRequest().getQueryString());

        if (oAuthMessage.getRequest().getParameterMap() != null) {
            sessionDataCacheEntryNew.setParamMap(new ConcurrentHashMap<>(oAuthMessage.getRequest().getParameterMap()));
        }
        SessionDataCache.getInstance().addToCache(cacheKey, sessionDataCacheEntryNew);
    }

    private String analyzePromptParameter(OAuthMessage oAuthMessage, OAuth2Parameters params, String prompt) {

        List promptsList = getSupportedPromtsValues();
        boolean containsNone = (OAuthConstants.Prompt.NONE).equals(prompt);

        if (StringUtils.isNotBlank(prompt)) {
            List requestedPrompts = getRequestedPromptList(prompt);
            if (!CollectionUtils.containsAny(requestedPrompts, promptsList)) {
                String message = "Invalid prompt variables passed with the authorization request";
                return handleInvalidPromptValues(params, prompt, message);
            }

            if (requestedPrompts.size() > 1) {
                if (requestedPrompts.contains(OAuthConstants.Prompt.NONE)) {

                    String message = "Invalid prompt variable combination. The value 'none' cannot be used with others " +
                            "prompts. Prompt: ";
                    return handleInvalidPromptValues(params, prompt, message);

                } else if (requestedPrompts.contains(OAuthConstants.Prompt.LOGIN) &&
                        (requestedPrompts.contains(OAuthConstants.Prompt.CONSENT))) {
                    oAuthMessage.setForceAuthenticate(true);
                    oAuthMessage.setPassiveAuthentication(false);
                }
            } else {
                if ((OAuthConstants.Prompt.LOGIN).equals(prompt)) { // prompt for authentication
                    oAuthMessage.setForceAuthenticate(true);
                    oAuthMessage.setPassiveAuthentication(false);
                } else if (containsNone) {
                    oAuthMessage.setForceAuthenticate(false);
                    oAuthMessage.setPassiveAuthentication(true);
                } else if ((OAuthConstants.Prompt.CONSENT).equals(prompt)) {
                    oAuthMessage.setForceAuthenticate(false);
                    oAuthMessage.setPassiveAuthentication(false);
                }
            }
        }
        return null;
    }

    private String handleInvalidPromptValues(OAuth2Parameters params, String prompt, String message) {
        if (log.isDebugEnabled()) {
            log.debug(message + " " + prompt);
        }
        OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.INVALID_REQUEST, message);
        return EndpointUtil.getErrorRedirectURL(ex, params);
    }

    private List getRequestedPromptList(String prompt) {

        String[] prompts = prompt.trim().split("\\s");
        return Arrays.asList(prompts);
    }

    private List<String> getSupportedPromtsValues() {
        return Arrays.asList(OAuthConstants.Prompt.NONE, OAuthConstants.Prompt.LOGIN,
                OAuthConstants.Prompt.CONSENT, OAuthConstants.Prompt.SELECT_ACCOUNT);
    }

    private String validatePKCEParameters(OAuth2ClientValidationResponseDTO validationResponse,
                                          String pkceChallengeCode, String pkceChallengeMethod, HttpRequestHeader[] httpRequestHeaders) {
        // Check if PKCE is mandatory for the application

        //Iniate Token binding parameters
        TokenBindingHandler tokenBinding = new TokenBindingHandler();
        tokenBinding.settBSupportEnabled(validationResponse.isTbMandatory());
        tokenBinding.checkTokenBindingHeader(httpRequestHeaders, OAuthConstants
                .HTTP_TB_REFERRED_HEADER_NAME);
        TokenBindingContext tokenBindingContext = new TokenBindingContext();
        tokenBindingContext.setTokenBindingSupportEnabled(tokenBinding.istBSupportEnabled());
        tokenBindingContext.setTokenBindingSupportExists(tokenBinding.istBSupportExist());

        //check PKCE challenge for token binding
        if (tokenBindingContext.isTokenBindingSupportExists()) {
            if (tokenBindingContext.isTokenBindingSupportEnabled()) {
                if (notvalidTokenBindingPkce(pkceChallengeMethod, pkceChallengeCode)) {
                    return EndpointUtil.getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST,
                            "This PKCE is not suitable for Token binding. ", null);
                }
            } else {
                // Check if PKCE is mandatory for the application
                if (validationResponse.isPkceMandatory()) {
                    if (pkceChallengeCode == null || !OAuth2Util.validatePKCECodeChallenge(pkceChallengeCode, pkceChallengeMethod)) {
                        return EndpointUtil.getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST, "PKCE is mandatory for this application. " +
                                "PKCE Challenge is not provided " +
                                "or is not upto RFC 7636 specification.", null);
                    }
                }
                if (pkceChallengeCode != null) {
                    //Check if the code challenge method value is neither "plain" or "s256", if so return error
                    if (notValidCodeChallengeMethod(pkceChallengeMethod)) {
                        return EndpointUtil.getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST, "Unsupported PKCE Challenge Method"
                                , null);
                    }
                    // Check if "plain" transformation algorithm is disabled for the application
                    if (!validationResponse.isPkceSupportPlain() && OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(pkceChallengeCode)) {
                        return EndpointUtil.getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST, "This application does not " +
                                "support \"plain\" transformation algorithm.", null);
                    }
                    // If PKCE challenge code was sent, check if the code challenge is upto specifications
                    if (!OAuth2Util.validatePKCECodeChallenge(pkceChallengeCode, pkceChallengeMethod)) {
                        return EndpointUtil.getErrorPageURL(OAuth2ErrorCodes.INVALID_REQUEST,
                                "Code challenge used is not up to RFC 7636 specifications.", null);
                    }
                }
            }
        }
        return null;
    }

    private boolean isPkceSupportEnabled() {
        return getOAuth2Service().isPKCESupportEnabled();
    }

    private void addSPDisplayNameParam(String clientId, OAuth2Parameters params) throws OAuthSystemException {
        if (getOAuthServerConfiguration().isShowDisplayNameInConsentPage()) {
            ServiceProvider serviceProvider = getServiceProvider(clientId);
            ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
            for (ServiceProviderProperty serviceProviderProperty : serviceProviderProperties) {
                if (DISPLAY_NAME.equals(serviceProviderProperty.getName())) {
                    params.setDisplayName(serviceProviderProperty.getValue());
                    break;
                }
            }
        }
    }

    private String populateOauthParameters(OAuth2Parameters params, OAuthMessage oAuthMessage,
                                           OAuth2ClientValidationResponseDTO validationResponse,
                                           CarbonOAuthAuthzRequest oauthRequest) throws OAuthSystemException {

        addSPDisplayNameParam(oAuthMessage.getClientId(), params);
        params.setClientId(oAuthMessage.getClientId());
        params.setRedirectURI(validationResponse.getCallbackURL());
        params.setResponseType(oauthRequest.getResponseType());
        params.setResponseMode(oauthRequest.getParam(RESPONSE_MODE));
        params.setScopes(oauthRequest.getScopes());
        params.setHttpRequestHeaders(oauthRequest.getHttpRequestHeaders());
        if (params.getScopes() == null) { // to avoid null pointers
            Set<String> scopeSet = new HashSet<String>();
            scopeSet.add("");
            params.setScopes(scopeSet);
        }
        params.setState(oauthRequest.getState());
        params.setApplicationName(validationResponse.getApplicationName());

        String pkceChallengeCode = oAuthMessage.getOauthPKCECodeChallenge();
        String pkceChallengeMethod = oAuthMessage.getOauthPKCECodeChallengeMethod();

        if (isPkceSupportEnabled()) {
            String redirectURI = validatePKCEParameters(validationResponse, pkceChallengeCode, pkceChallengeMethod,oauthRequest.getHttpRequestHeaders());
            if (redirectURI != null) {
                return redirectURI;
            }
        }
        params.setPkceCodeChallenge(pkceChallengeCode);
        params.setPkceCodeChallengeMethod(pkceChallengeMethod);

        // OpenID Connect specific request parameters
        params.setNonce(oauthRequest.getParam(OAuthConstants.OAuth20Params.NONCE));
        params.setDisplay(oauthRequest.getParam(OAuthConstants.OAuth20Params.DISPLAY));
        params.setIDTokenHint(oauthRequest.getParam(OAuthConstants.OAuth20Params.ID_TOKEN_HINT));
        params.setLoginHint(oauthRequest.getParam(OAuthConstants.OAuth20Params.LOGIN_HINT));
        if (StringUtils.isNotEmpty(oauthRequest.getParam(MultitenantConstants.TENANT_DOMAIN))) {
            params.setTenantDomain(oauthRequest.getParam(MultitenantConstants.TENANT_DOMAIN));
        } else {
            params.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
        if (StringUtils.isNotBlank(oauthRequest.getParam(ACR_VALUES)) && !"null".equals(oauthRequest.getParam
                (ACR_VALUES))) {
            String[] acrValues = oauthRequest.getParam(ACR_VALUES).split(" ");
            LinkedHashSet list = new LinkedHashSet();
            for (String acrValue : acrValues) {
                list.add(acrValue);
            }
            params.setACRValues(list);
        }
        if (StringUtils.isNotBlank(oauthRequest.getParam(CLAIMS))) {
            params.setEssentialClaims(oauthRequest.getParam(CLAIMS));
        }
        try {
            handleOIDCRequestObject(oauthRequest, params);
        } catch (RequestObjectException e) {
            // All the error logs are specified at the time when throw the exception.
            return EndpointUtil.getErrorPageURL(e.getErrorCode(), e.getErrorMessage(), null);
        }
        return null;
    }

    private void handleOIDCRequestObject(OAuthAuthzRequest oauthRequest, OAuth2Parameters parameters)
            throws RequestObjectException {

        validateRequestObject(oauthRequest);
        if (isRequestUri(oauthRequest.getParam(REQUEST_URI))) {
            handleRequestObject(oauthRequest, parameters, oauthRequest.getParam(REQUEST_URI));
        } else if (isRequestParameter(oauthRequest.getParam(REQUEST))) {
            handleRequestObject(oauthRequest, parameters, oauthRequest.getParam(REQUEST));
        }
    }

    private void validateRequestObject(OAuthAuthzRequest oauthRequest) throws RequestObjectException {

        // With in the same request it can not be used both request parameter and request_uri parameter.
        if (StringUtils.isNotEmpty(oauthRequest.getParam(REQUEST)) && StringUtils.isNotEmpty(oauthRequest.getParam
                (REQUEST_URI))) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Both request and " +
                    "request_uri parameters can not be associated with the same authorization request.");
        }
    }

    private void handleRequestObject(OAuthAuthzRequest oauthRequest, OAuth2Parameters parameters,
                                     String requestParameterValue) throws RequestObjectException {

        if (StringUtils.isNotBlank(requestParameterValue)) {
            RequestObject requestObject = getRequestObject(oauthRequest, parameters);
            if (requestObject == null) {
                throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Can not build the request object as " +
                        "request object instance is null.");
            }
            validateSignatureAndContent(parameters, requestObject);
            /**
             * When the request parameter is used, the OpenID Connect request parameter values contained in the JWT supersede
             * those passed using the OAuth 2.0 request syntax
             */
            overrideAuthzParameters(parameters, oauthRequest.getParam(REQUEST), oauthRequest.getParam(REQUEST_URI),
                    requestObject);
        }
    }

    private void validateSignatureAndContent(OAuth2Parameters params, RequestObject requestObject) throws
            RequestObjectException {

        if (requestObject.isSignatureValid()) {
            params.setRequestObject(requestObject);
            if (log.isDebugEnabled()) {
                log.debug("The request Object is valid. Hence storing the request object value in oauth params.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The request signature validation failed as the json is invalid.");
            }
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Request object signature " +
                    "validation failed.");
        }
    }

    private RequestObject getRequestObject(OAuthAuthzRequest oauthRequest, OAuth2Parameters parameters)
            throws RequestObjectException {

        RequestObject requestObject = new RequestObject();
        OIDCRequestObjectFactory.buildRequestObject(oauthRequest, parameters, requestObject);
        return requestObject;
    }

    private void overrideAuthzParameters(OAuth2Parameters params, String requestParameterValue,
                                         String requestURIParameterValue, RequestObject requestObject) {

        if (StringUtils.isNotBlank(requestParameterValue) || StringUtils.isNotBlank(requestURIParameterValue)) {
            if (StringUtils.isNotBlank(requestObject.getRedirectUri())) {
                params.setRedirectURI(requestObject.getRedirectUri());
            }
            if (StringUtils.isNotBlank(requestObject.getNonce())) {
                params.setNonce(requestObject.getNonce());
            }
            if (StringUtils.isNotBlank(requestObject.getState())) {
                params.setState(requestObject.getState());
            }
            if (ArrayUtils.isNotEmpty(requestObject.getScopes())) {
                params.setScopes(new HashSet<>(Arrays.asList(requestObject.getScopes())));
            }
        }
    }

    private static boolean isRequestUri(String param) {
        return StringUtils.isNotBlank(param);
    }

    private static boolean isRequestParameter(String param) {
        return StringUtils.isNotBlank(param);
    }

    private OAuth2ClientValidationResponseDTO validateClient(OAuthMessage oAuthMessage) {

        String redirectUri = oAuthMessage.getRequest().getParameter(REDIRECT_URI);
        return getOAuth2Service().validateClientInfo(oAuthMessage.getClientId(), redirectUri);
    }

    /**
     * Return ServiceProvider for the given clientId
     *
     * @param clientId clientId
     * @return ServiceProvider ServiceProvider
     * @throws OAuthSystemException if couldn't retrieve ServiceProvider Information
     */
    private ServiceProvider getServiceProvider(String clientId) throws OAuthSystemException {
        ApplicationManagementService applicationManagementService = getApplicationManagementService();
        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            return applicationManagementService.getServiceProvider(oAuthAppDO.getApplicationName(), tenantDomain);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException | IdentityApplicationManagementException e) {
            String msg = "Couldn't retrieve Service Provider for clientId:" + clientId;
            log.error(msg, e);
            throw new OAuthSystemException(msg, e);
        }
    }

    /**
     * prompt : none
     * The Authorization Server MUST NOT display any authentication
     * or consent user interface pages. An error is returned if the
     * End-User is not already authenticated or the Client does not
     * have pre-configured consent for the requested scopes. This
     * can be used as a method to check for existing authentication
     * and/or consent.
     * <p/>
     * prompt : consent
     * The Authorization Server MUST prompt the End-User for consent before
     * returning information to the Client.
     * <p/>
     * prompt Error : consent_required
     * The Authorization Server requires End-User consent. This
     * error MAY be returned when the prompt parameter in the
     * Authorization Request is set to none to request that the
     * Authorization Server should not display any user
     * interfaces to the End-User, but the Authorization Request
     * cannot be completed without displaying a user interface
     * for End-User consent.
     *
     * @return String URL
     * @throws OAuthSystemException OAuthSystemException
     */
    private String doUserAuthz(OAuthMessage oAuthMessage, String sessionDataKey, OIDCSessionState sessionState)
            throws OAuthSystemException {

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        AuthenticatedUser user = oAuthMessage.getSessionDataCacheEntry().getLoggedInUser();
        String loggedInUser = user.getAuthenticatedSubjectIdentifier();
        boolean hasUserApproved = isUserAlreadyApproved(oauth2Params, user);

        if (hasPromptContainsConsent(oauth2Params)) {
            return getUserConsentURL(sessionDataKey, oauth2Params, loggedInUser);

        } else if (isPromptNone(oauth2Params)) {
            if (isUserSessionNotExists(user)) {
                return getErrorRedirectURL(oauth2Params, OAuth2ErrorCodes.LOGIN_REQUIRED);
            }

            if (isIdTokenHintExists(oauth2Params)) {
                return handleIdTokenHint(oAuthMessage, sessionState, oauth2Params, loggedInUser, hasUserApproved);
            } else {
                sessionState.setAddSessionState(true);
                if (hasUserApprovedOrSkipConsent(hasUserApproved)) {
                    return handleUserConsent(oAuthMessage, APPROVE, sessionState);
                } else {
                    return getErrorRedirectURL(oauth2Params, OAuth2ErrorCodes.CONSENT_REQUIRED);
                }
            }
        } else if (isPromptEqualLoginOrNoPrompt(oauth2Params)) {
            if (hasUserApprovedOrSkipConsent(hasUserApproved)) {
                sessionState.setAddSessionState(true);
                return handleUserConsent(oAuthMessage, APPROVE, sessionState);
            } else {
                return getUserConsentURL(sessionDataKey, oauth2Params, loggedInUser);
            }
        } else {
            return StringUtils.EMPTY;
        }

    }

    private boolean isPromptEqualLoginOrNoPrompt(OAuth2Parameters oauth2Params) {
        return (OAuthConstants.Prompt.LOGIN).equals(oauth2Params.getPrompt()) || StringUtils.isBlank(oauth2Params.getPrompt());
    }

    private String handleIdTokenHint(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                     OAuth2Parameters oauth2Params, String loggedInUser,
                                     boolean hasUserApproved) throws OAuthSystemException {
        try {
            String idTokenHint = oauth2Params.getIDTokenHint();
            if (isIdTokenValidationFailed(idTokenHint)) {
                return getErrorRedirectURL(oauth2Params, OAuth2ErrorCodes.ACCESS_DENIED);
            }

            if (isIdTokenSubjectEqualsToLoggedInUser(loggedInUser, idTokenHint)) {
                if (hasUserApprovedOrSkipConsent(hasUserApproved)) {
                    return handleUserConsent(oAuthMessage, APPROVE, sessionState);
                } else {
                    return getErrorRedirectURL(oauth2Params, OAuth2ErrorCodes.CONSENT_REQUIRED);
                }
            } else {
                return getErrorRedirectURL(oauth2Params, OAuth2ErrorCodes.LOGIN_REQUIRED);
            }
        } catch (ParseException e) {
            String msg = "Error while getting clientId from the IdTokenHint.";
            log.error(msg, e);
            return getErrorRedirectURL(oauth2Params, OAuth2ErrorCodes.ACCESS_DENIED);
        }
    }

    private boolean isIdTokenHintExists(OAuth2Parameters oauth2Params) {
        return StringUtils.isNotEmpty(oauth2Params.getIDTokenHint());
    }

    private boolean isUserAlreadyApproved(OAuth2Parameters oauth2Params, AuthenticatedUser user) throws OAuthSystemException {
        return OpenIDConnectUserRPStore.getInstance().hasUserApproved(user, oauth2Params.getApplicationName(),
                oauth2Params.getClientId());
    }

    private boolean hasUserApprovedOrSkipConsent(boolean hasUserApproved) {
        return getOAuthServerConfiguration().getOpenIDConnectSkipeUserConsentConfig() || hasUserApproved;
    }

    private boolean isIdTokenSubjectEqualsToLoggedInUser(String loggedInUser, String idTokenHint) throws ParseException {

        String subjectValue = getSubjectFromIdToken(idTokenHint);
        return StringUtils.isNotEmpty(loggedInUser) && loggedInUser.equals(subjectValue);
    }

    private String getSubjectFromIdToken(String idTokenHint) throws ParseException {
        return SignedJWT.parse(idTokenHint).getJWTClaimsSet().getSubject();
    }

    private boolean isIdTokenValidationFailed(String idTokenHint) {

        if (!OAuth2Util.validateIdToken(idTokenHint)) {
            log.error("ID token signature validation failed.");
            return true;
        }
        return false;
    }

    private boolean isUserSessionNotExists(AuthenticatedUser user) {
        return user == null;
    }

    private boolean isPromptNone(OAuth2Parameters oauth2Params) {
        return (OAuthConstants.Prompt.NONE).equals(oauth2Params.getPrompt());
    }

    private String getErrorRedirectURL(OAuth2Parameters oauth2Params, String errorCode) {
        OAuthProblemException ex = OAuthProblemException.error(errorCode);
        return EndpointUtil.getErrorRedirectURL(ex, oauth2Params);
    }

    private boolean hasPromptContainsConsent(OAuth2Parameters oauth2Params) {

        String[] prompts = null;
        if (StringUtils.isNotBlank(oauth2Params.getPrompt())) {
            prompts = oauth2Params.getPrompt().trim().split("\\s");
        }
        return prompts != null && Arrays.asList(prompts).contains(OAuthConstants.Prompt.CONSENT);
    }

    private String getUserConsentURL(String sessionDataKey, OAuth2Parameters oauth2Params, String loggedInUser) throws OAuthSystemException {
        return EndpointUtil.getUserConsentURL(oauth2Params, loggedInUser, sessionDataKey,
                OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes()));
    }

    /**
     * Here we set the authenticated user to the session data
     *
     * @param oauth2Params
     * @return
     */
    private OAuth2AuthorizeRespDTO authorize(OAuth2Parameters oauth2Params
            , SessionDataCacheEntry sessionDataCacheEntry) {

        OAuth2AuthorizeReqDTO authzReqDTO = buildAuthRequest(oauth2Params, sessionDataCacheEntry);
        return getOAuth2Service().authorize(authzReqDTO);
    }

    private OAuth2AuthorizeReqDTO buildAuthRequest(OAuth2Parameters oauth2Params, SessionDataCacheEntry sessionDataCacheEntry) {

        OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
        authzReqDTO.setCallbackUrl(oauth2Params.getRedirectURI());
        authzReqDTO.setConsumerKey(oauth2Params.getClientId());
        authzReqDTO.setResponseType(oauth2Params.getResponseType());
        authzReqDTO.setScopes(oauth2Params.getScopes().toArray(new String[oauth2Params.getScopes().size()]));
        authzReqDTO.setUser(sessionDataCacheEntry.getLoggedInUser());
        authzReqDTO.setACRValues(oauth2Params.getACRValues());
        authzReqDTO.setNonce(oauth2Params.getNonce());
        authzReqDTO.setPkceCodeChallenge(oauth2Params.getPkceCodeChallenge());
        authzReqDTO.setPkceCodeChallengeMethod(oauth2Params.getPkceCodeChallengeMethod());
        authzReqDTO.setTenantDomain(oauth2Params.getTenantDomain());
        authzReqDTO.setAuthTime(oauth2Params.getAuthTime());
        authzReqDTO.setEssentialClaims(oauth2Params.getEssentialClaims());
        authzReqDTO.setHttpRequestHeaders(oauth2Params.getHttpRequestHeaders());
        return authzReqDTO;
    }

    private void clearCacheEntry(String sessionDataKey) {
        if (sessionDataKey != null) {
            SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
            SessionDataCacheEntry result = SessionDataCache.getInstance().getValueFromCache(cacheKey);
            if (result != null) {
                SessionDataCache.getInstance().clearCacheEntry(cacheKey);
            }
        }
    }


    private AuthenticationResult getAuthenticationResult(OAuthMessage oAuthMessage, String sessionDataKey) {

        AuthenticationResult result = getAuthenticationResultFromRequest(oAuthMessage.getRequest());
        if (result == null) {
            isCacheAvailable = true;
            result = getAuthenticationResultFromCache(sessionDataKey);
        }
        return result;
    }

    private AuthenticationResult getAuthenticationResultFromCache(String sessionDataKey) {
        AuthenticationResult authResult = null;
        AuthenticationResultCacheEntry authResultCacheEntry = FrameworkUtils
                .getAuthenticationResultFromCache(sessionDataKey);
        if (authResultCacheEntry != null) {
            authResult = authResultCacheEntry.getResult();
        } else {
            log.error("Cannot find AuthenticationResult from the cache");
        }
        return authResult;
    }

    /**
     * Get authentication result from request
     *
     * @param request Http servlet request
     * @return  AuthenticationResult
     */
    private AuthenticationResult getAuthenticationResultFromRequest(HttpServletRequest request) {

        return (AuthenticationResult) request.getAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT);
    }

    private Response handleAuthFlowThroughFramework(OAuthMessage oAuthMessage) throws URISyntaxException, InvalidRequestParentException {

        try {
            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(oAuthMessage.getResponse());
            invokeCommonauthFlow(oAuthMessage, responseWrapper);
            return processAuthResponseFromFramework(oAuthMessage, responseWrapper);
        } catch (ServletException | IOException e) {
            log.error("Error occurred while sending request to authentication framework.");
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }


    private Response processAuthResponseFromFramework(OAuthMessage oAuthMessage, CommonAuthResponseWrapper
            responseWrapper) throws IOException, InvalidRequestParentException, URISyntaxException {

        if (isAuthFlowStateExists(oAuthMessage)) {
            if (isFlowStateIncomplete(oAuthMessage)) {
                return handleIncompleteFlow(oAuthMessage, responseWrapper);
            } else {
                return handleSuccessfullyCompletedFlow(oAuthMessage);
            }
        } else {
            return handleUnknownFlowState(oAuthMessage);
        }
    }

    private Response handleUnknownFlowState(OAuthMessage oAuthMessage) throws URISyntaxException, InvalidRequestParentException {
        oAuthMessage.getRequest().setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus
                .UNKNOWN);
        return authorize(oAuthMessage.getRequest(), oAuthMessage.getResponse());
    }

    private Response handleSuccessfullyCompletedFlow(OAuthMessage oAuthMessage) throws URISyntaxException, InvalidRequestParentException {
        return authorize(oAuthMessage.getRequest(), oAuthMessage.getResponse());
    }

    private boolean isFlowStateIncomplete(OAuthMessage oAuthMessage) {
        return AuthenticatorFlowStatus.INCOMPLETE.equals(oAuthMessage.getFlowStatus());
    }

    private Response handleIncompleteFlow(OAuthMessage oAuthMessage, CommonAuthResponseWrapper responseWrapper) throws IOException {
        if (responseWrapper.isRedirect()) {
            oAuthMessage.getResponse().sendRedirect(responseWrapper.getRedirectURL());
            return null;
        } else {
            return Response.status(HttpServletResponse.SC_OK).entity(responseWrapper.getContent()).build();
        }
    }

    private boolean isAuthFlowStateExists(OAuthMessage oAuthMessage) {
        return oAuthMessage.getFlowStatus() != null;
    }

    private void invokeCommonauthFlow(OAuthMessage oAuthMessage, CommonAuthResponseWrapper responseWrapper)
            throws ServletException, IOException {
        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();
        commonAuthenticationHandler.doGet(oAuthMessage.getRequest(), responseWrapper);
    }

    /**
     * This method use to call authentication framework directly via API other than using HTTP redirects.
     * Sending wrapper request object to doGet method since other original request doesn't exist required parameters
     * Doesn't check SUCCESS_COMPLETED since taking decision with INCOMPLETE status
     *
     * @param type authenticator type
     * @throws URISyntaxException
     * @throws InvalidRequestParentException
     * @Param type OAuthMessage
     */
    private Response handleAuthFlowThroughFramework(OAuthMessage oAuthMessage, String type) throws URISyntaxException,
            InvalidRequestParentException {

        try {
            String sessionDataKey = (String) oAuthMessage.getRequest().getAttribute(FrameworkConstants.SESSION_DATA_KEY);

            CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

            CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(oAuthMessage.getRequest());
            requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
            requestWrapper.setParameter(FrameworkConstants.RequestParams.TYPE, type);

            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(oAuthMessage.getResponse());
            commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);

            Object attribute = oAuthMessage.getRequest().getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
            if (attribute != null) {
                if (attribute == AuthenticatorFlowStatus.INCOMPLETE) {

                    if (responseWrapper.isRedirect()) {
                        oAuthMessage.getResponse().sendRedirect(responseWrapper.getRedirectURL());
                    } else {
                        return Response.status(HttpServletResponse.SC_OK).entity(responseWrapper.getContent()).build();
                    }
                } else {
                    return authorize(requestWrapper, responseWrapper);
                }
            } else {
                requestWrapper.setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
                return authorize(requestWrapper, responseWrapper);
            }
        } catch (ServletException | IOException e) {
            log.error("Error occurred while sending request to authentication framework.");
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
        return null;
    }

    private String manageOIDCSessionState(HttpServletRequest request, HttpServletResponse response,
                                          OIDCSessionState sessionStateObj, OAuth2Parameters oAuth2Parameters,
                                          String authenticatedUser, String redirectURL) {
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (sessionStateObj.isAuthenticated()) { // successful user authentication
            if (opBrowserStateCookie == null) { // new browser session
                if (log.isDebugEnabled()) {
                    log.debug("User authenticated. Initiate OIDC browser session.");
                }
                opBrowserStateCookie = OIDCSessionManagementUtil.addOPBrowserStateCookie(response);

                sessionStateObj.setAuthenticatedUser(authenticatedUser);
                sessionStateObj.addSessionParticipant(oAuth2Parameters.getClientId());
                OIDCSessionManagementUtil.getSessionManager()
                        .storeOIDCSessionState(opBrowserStateCookie.getValue(), sessionStateObj);
            } else { // browser session exists
                OIDCSessionState previousSessionState =
                        OIDCSessionManagementUtil.getSessionManager()
                                .getOIDCSessionState(opBrowserStateCookie.getValue());
                if (previousSessionState != null) {
                    if (!previousSessionState.getSessionParticipants().contains(oAuth2Parameters.getClientId())) {
                        // User is authenticated to a new client. Restore browser session state
                        if (log.isDebugEnabled()) {
                            log.debug("User is authenticated to a new client. Restore browser session state.");
                        }
                        String oldOPBrowserStateCookieId = opBrowserStateCookie.getValue();
                        opBrowserStateCookie = OIDCSessionManagementUtil.addOPBrowserStateCookie(response);
                        String newOPBrowserStateCookieId = opBrowserStateCookie.getValue();
                        previousSessionState.addSessionParticipant(oAuth2Parameters.getClientId());
                        OIDCSessionManagementUtil.getSessionManager().restoreOIDCSessionState
                                (oldOPBrowserStateCookieId, newOPBrowserStateCookieId, previousSessionState);
                    }
                } else {
                    log.warn("No session state found for the received Session ID : " + opBrowserStateCookie.getValue());
                    if (log.isDebugEnabled()) {
                        log.debug("Restore browser session state.");
                    }
                    opBrowserStateCookie = OIDCSessionManagementUtil.addOPBrowserStateCookie(response);
                    sessionStateObj.setAuthenticatedUser(authenticatedUser);
                    sessionStateObj.addSessionParticipant(oAuth2Parameters.getClientId());
                    OIDCSessionManagementUtil.getSessionManager()
                            .storeOIDCSessionState(opBrowserStateCookie.getValue(), sessionStateObj);
                }
            }
        }

        if (sessionStateObj.isAddSessionState()) {
            String sessionStateParam = OIDCSessionManagementUtil.getSessionStateParam(oAuth2Parameters.getClientId(),
                    oAuth2Parameters.getRedirectURI(),
                    opBrowserStateCookie == null ?
                            null :
                            opBrowserStateCookie.getValue());
            redirectURL = OIDCSessionManagementUtil.addSessionStateToURL(redirectURL, sessionStateParam,
                    oAuth2Parameters.getResponseType());

            if (RESPONSE_MODE_FORM_POST.equals(oAuth2Parameters.getResponseMode()) && isJSON(redirectURL)) {
                return sessionStateParam;
            }
        }

        return redirectURL;
    }

    private boolean notValidCodeChallengeMethod(String pkceChallengeMethod) {
        if (pkceChallengeMethod != null && !OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(pkceChallengeMethod) &&
                !OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(pkceChallengeMethod)) {
            return true;
        }
        return false;

    }

    private boolean notvalidTokenBindingPkce(String pkceChallengeCodeMethod, String pkceChallengeCode) {
        if (!OAuthConstants.OAUTH_PKCE_REFERRED_TB_CHALLENGE.equals(pkceChallengeCodeMethod) || !OAuthConstants
                .OAUTH_PKCE_REFERRED_TB_CHALLENGE.equals(pkceChallengeCode)) {
            return true;
        }
        return false;
    }

    private String appendAuthenticatedIDPs(SessionDataCacheEntry sessionDataCacheEntry, String redirectURL) {
        if (sessionDataCacheEntry != null) {
            String authenticatedIdPs = sessionDataCacheEntry.getAuthenticatedIdPs();

            if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
                try {
                    String IDPAppendedRedirectURL = redirectURL + "&AuthenticatedIdPs=" + URLEncoder.encode
                            (authenticatedIdPs, "UTF-8");
                    return IDPAppendedRedirectURL;
                } catch (UnsupportedEncodingException e) {
                    //this exception should not occur
                    log.error("Error while encoding the url", e);
                }
            }
        }
        return redirectURL;
    }


    /**
     * Gets the last authenticated value from the commonAuthId cookie
     *
     * @param cookie CommonAuthId cookie
     * @return the last authenticated timestamp
     */
    private long getAuthenticatedTimeFromCommonAuthCookie(Cookie cookie) {
        long authTime = 0;
        if (cookie != null) {
            String sessionContextKey = DigestUtils.sha256Hex(cookie.getValue());
            SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(sessionContextKey);
            if (sessionContext != null) {
                if (sessionContext.getProperty(FrameworkConstants.UPDATED_TIMESTAMP) != null) {
                    authTime = Long.parseLong(
                            sessionContext.getProperty(FrameworkConstants.UPDATED_TIMESTAMP).toString());
                } else {
                    authTime = Long.parseLong(
                            sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP).toString());
                }
            }
        }
        return authTime;
    }


    /**
     * Build OAuthProblem exception based on error details sent by the Framework as properties in the
     * AuthenticationResult object.
     *
     * @param authenticationResult
     * @return
     */
    private OAuthProblemException buildOAuthProblemException(AuthenticationResult authenticationResult) {

        final String DEFAULT_ERROR_MSG = "Authentication required";
        String errorCode = String.valueOf(authenticationResult.getProperty(FrameworkConstants.AUTH_ERROR_CODE));
        String errorMessage = String.valueOf(authenticationResult.getProperty(FrameworkConstants.AUTH_ERROR_MSG));
        String errorUri = String.valueOf(authenticationResult.getProperty(FrameworkConstants.AUTH_ERROR_URI));

        if (IdentityUtil.isBlank(errorCode)) {
            // if there is no custom error code sent from framework we set our default error code
            errorCode = OAuth2ErrorCodes.LOGIN_REQUIRED;
        }

        if (IdentityUtil.isBlank(errorMessage)) {
            // if there is no custom error message sent from framework we set our default error message
            errorMessage = DEFAULT_ERROR_MSG;
        }

        if (IdentityUtil.isNotBlank(errorUri)) {
            // if there is a error uri sent in the authentication result we add that to the exception
            return OAuthProblemException.error(errorCode, errorMessage).uri(errorUri);
        } else {
            return OAuthProblemException.error(errorCode, errorMessage);
        }
    }
}
