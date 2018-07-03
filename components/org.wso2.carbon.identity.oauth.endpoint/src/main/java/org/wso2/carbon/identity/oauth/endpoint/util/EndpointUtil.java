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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.DefaultOIDCProviderRequestBuilder;
import org.wso2.carbon.identity.discovery.builders.OIDCProviderRequestBuilder;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedMap;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_REQ_HEADER_AUTH_METHOD_BASIC;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.getRedirectURL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;

public class EndpointUtil {

    private static final Log log = LogFactory.getLog(EndpointUtil.class);
    private static final String OAUTH2 = "oauth2";
    private static final String OPENID = "openid";
    private static final String OIDC = "oidc";
    private static final String OAUTH2_AUTHORIZE = "/oauth2/authorize";
    private static final String UTF_8 = "UTF-8";

    private EndpointUtil() {

    }

    /**
     * Returns the registered {@code {@link SSOConsentService}} instance
     *
     * @return
     */
    public static SSOConsentService getSSOConsentService() {
        return (SSOConsentService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(SSOConsentService.class, null);
    }

    /**
     * Returns the {@code DefaultWebFingerProcessor} instance
     *
     * @return DefaultWebFingerProcessor
     */
    public static DefaultWebFingerProcessor getWebFingerService() {
        return (DefaultWebFingerProcessor) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService
                (WebFingerProcessor.class, null);
    }

    /**
     * Returns the {@code OIDCProviderRequestBuilder} instance
     *
     * @return DefaultOIDCProviderRequestBuilder
     */
    public static DefaultOIDCProviderRequestBuilder getOIDProviderRequestValidator() {
        return (DefaultOIDCProviderRequestBuilder) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService
                (OIDCProviderRequestBuilder.class, null);
    }

    /**
     * Returns the {@code DefaultOIDCProcessor} instance
     *
     * @return DefaultOIDCProcessor
     */
    public static DefaultOIDCProcessor getOIDCService() {
        return (DefaultOIDCProcessor) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService
                (OIDCProcessor.class, null);
    }

    /**
     * Returns the {@code RequestObjectService} instance
     *
     * @return RequestObjectService
     */
    public static RequestObjectService getRequestObjectService() {

        return (RequestObjectService) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService
                (RequestObjectService.class, null);
    }

    /**
     * Returns the {@code OAuth2Service} instance
     *
     * @return OAuth2Service
     */
    public static OAuth2Service getOAuth2Service() {
        return (OAuth2Service) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(OAuth2Service.class, null);
    }

    /**
     * Returns the {@code OAuthServerConfiguration} instance
     *
     * @return OAuthServerConfiguration
     */
    public static OAuthServerConfiguration getOAuthServerConfiguration() {
        return (OAuthServerConfiguration) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(OAuthServerConfiguration.class, null);
    }

    /**
     * Returns the {@code OAuthServerConfiguration} instance
     *
     * @return OAuth2TokenValidationService
     */
    public static OAuth2TokenValidationService getOAuth2TokenValidationService() {
        return (OAuth2TokenValidationService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(OAuth2TokenValidationService.class, null);
    }

    /**
     * Returns the request validator class name
     *
     * @return UserInfoEndpointRequestValidator
     */
    public static String getUserInfoRequestValidator() throws OAuthSystemException {
        return getOAuthServerConfiguration().getOpenIDConnectUserInfoEndpointRequestValidator();
    }

    /**
     * Returns the access token validator class name
     *
     * @return AccessTokenValidator
     */
    public static String getAccessTokenValidator() {
        return getOAuthServerConfiguration().getOpenIDConnectUserInfoEndpointAccessTokenValidator();
    }

    /**
     * Returns the response builder class name
     *
     * @return UserInfoResponseBuilder
     */
    public static String getUserInfoResponseBuilder() {
        return getOAuthServerConfiguration().getOpenIDConnectUserInfoEndpointResponseBuilder();
    }

    /**
     * Returns the claim retriever class name
     *
     * @return UserInfoClaimRetriever
     */
    public static String getUserInfoClaimRetriever() {
        return getOAuthServerConfiguration().getOpenIDConnectUserInfoEndpointClaimRetriever();
    }

    /**
     * Return the claim dialect for the claim retriever
     *
     * @return UserInfoClaimDialect
     */
    public static String getUserInfoClaimDialect() {
        return getOAuthServerConfiguration().getOpenIDConnectUserInfoEndpointClaimDialect();
    }

    /**
     * Extracts the username and password info from the HTTP Authorization Header
     *
     * @param authorizationHeader "Basic " + base64encode(username + ":" + password)
     * @return String array with client id and client secret.
     * @throws OAuthClientException If the decoded data is null.
     */
    public static String[] extractCredentialsFromAuthzHeader(String authorizationHeader)
            throws OAuthClientException {

        if (authorizationHeader == null) {
            throw new OAuthClientException("Authorization header value is null");
        }
        String errMsg = "Error decoding authorization header. Space delimited \"<authMethod> <base64encoded" +
                "(username:password)>\" format violated.";
        String[] splitValues = authorizationHeader.trim().split(" ");
        if (splitValues.length == 2) {
            if (HTTP_REQ_HEADER_AUTH_METHOD_BASIC.equals(splitValues[0])) {
                byte[] decodedBytes = Base64Utils.decode(splitValues[1].trim());
                String userNamePassword = new String(decodedBytes, Charsets.UTF_8);
                String[] credentials = userNamePassword.split(":");
                if (credentials.length == 2) {
                    return credentials;
                }
            } else {
                errMsg = "Error decoding authorization header.Unsupported authentication type:" + splitValues[0] + "" +
                        " is provided in the Authorization Header.";
            }
        }
        throw new OAuthClientException(errMsg);
    }

    /**
     * Returns the error page URL. If appName is not <code>null</code> it will be added as query parameter
     * to be displayed to the user. If redirect_uri is <code>null</code> the common error page URL will be returned.
     *
     * @param errorCode : Error Code
     * @param errorMessage : Error Message
     * @param appName : Application Name
     * @return ErrorPageURL
     */
    public static String getErrorPageURL(String errorCode, String errorMessage, String appName) {

        String errorPageUrl = OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl();
        try {

            if (StringUtils.isNotBlank(errorCode)) {
                errorPageUrl = FrameworkUtils.appendQueryParamsStringToUrl(errorPageUrl,
                        OAuthConstants.OAUTH_ERROR_CODE + "=" + URLEncoder.encode(errorCode, UTF_8));
            }

            if (StringUtils.isNotBlank(errorMessage)) {
                errorPageUrl = FrameworkUtils.appendQueryParamsStringToUrl(errorPageUrl,
                        OAuthConstants.OAUTH_ERROR_MESSAGE + "=" + URLEncoder.encode(errorMessage, UTF_8));
            }

        } catch (UnsupportedEncodingException e) {
            //ignore
            if (log.isDebugEnabled()){
                log.debug("Error while encoding the error page url", e);
            }
        }

        if (appName != null) {
            try {
                errorPageUrl += "&application" + "=" + URLEncoder.encode(appName, UTF_8);
            } catch (UnsupportedEncodingException e) {
                //ignore
                if (log.isDebugEnabled()){
                    log.debug("Error while encoding the error page url", e);
                }
            }
        }

        return errorPageUrl;
    }

    /**
     * Returns the error page URL. If appName is not <code>null</code> it will be added as query parameter
     * to be displayed to the user. If redirect_uri is <code>null</code> the common error page URL will be returned.
     * If sp name and tenant domain available in the request (as a parameter or using the referer header) those will
     * be added as query params.
     *
     * @param request      HttpServletRequest
     * @param errorCode    Error Code.
     * @param errorMessage Error Message.
     * @param appName      Application Name.
     * @return redirect error page url.
     */
    public static String getErrorPageURL(HttpServletRequest request, String errorCode, String errorMessage, String
            appName) {

        String redirectURL = getErrorPageURL(errorCode, errorMessage, appName);
        if (request == null) {
            return redirectURL;
        }
        return getRedirectURL(redirectURL, request);
    }

    /**
     * Returns the error page URL. If sp name and tenant domain available in the request (as a parameter or using the
     * referer header) those will be added as query params.
     *
     * @param request HttpServletRequest.
     * @param ex      OAuthProblemException.
     * @param params  oAuth2 Parameters.
     * @return redirect error page url
     */
    public static String getErrorRedirectURL(HttpServletRequest request, OAuthProblemException ex, OAuth2Parameters
            params) {

        String redirectURL = getErrorRedirectURL(ex, params);
        if (request == null) {
            return redirectURL;
        }
        return getRedirectURL(redirectURL, request);
    }

    public static String getErrorRedirectURL(OAuthProblemException ex, OAuth2Parameters params) {

        String redirectURL = null;
        try {
            if (params != null) {
                if (StringUtils.isNotBlank(params.getRedirectURI())) {
                    if (OAuth2Util.isImplicitResponseType(params.getResponseType())) {
                        if (OAuthServerConfiguration.getInstance().isImplicitErrorFragment()) {
                            redirectURL = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
                                    .error(ex).location(params.getRedirectURI())
                                    .setState(params.getState()).setParam(OAuth.OAUTH_ACCESS_TOKEN, null)
                                    .buildQueryMessage().getLocationUri();
                        }
                    }
                    if (StringUtils.isBlank(redirectURL)) {
                        redirectURL = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
                                .error(ex).location(params.getRedirectURI())
                                .setState(params.getState()).buildQueryMessage()
                                .getLocationUri();
                    }
                } else {
                    redirectURL = getErrorPageURL(ex.getError(), ex.getMessage(), params.getApplicationName());
                }
            } else {
                redirectURL = getErrorPageURL(ex.getError(), ex.getMessage(), null);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Server error occurred while building error redirect url", e);
            }
            redirectURL = getErrorPageURL(ex.getError(), ex.getMessage(), params.getApplicationName());
        }
        return redirectURL;
    }

    /**
     * Returns the login page URL.
     *
     * @param checkAuthentication : True if Passive Authentication
     * @param forceAuthenticate : True if need to authenticate forcefully
     * @param scopes : Scopes set
     * @return LoginPageURL
     */
    public static String getLoginPageURL(String clientId, String sessionDataKey,
                                         boolean forceAuthenticate, boolean checkAuthentication, Set<String> scopes)
            throws IdentityOAuth2Exception {

        try {
            SessionDataCacheEntry entry = SessionDataCache.getInstance()
                    .getValueFromCache(new SessionDataCacheKey(sessionDataKey));

            return getLoginPageURL(clientId, sessionDataKey, forceAuthenticate,
                    checkAuthentication, scopes, entry.getParamMap());
        } finally {
            OAuth2Util.clearClientTenantId();
        }
    }

    /**
     * Returns the login page URL.
     *
     * @param clientId
     * @param sessionDataKey
     * @param reqParams
     * @param forceAuthenticate
     * @param checkAuthentication
     * @param scopes
     * @return LoginPageURL
     * @throws java.io.UnsupportedEncodingException
     */
    public static String getLoginPageURL(String clientId, String sessionDataKey,
                                         boolean forceAuthenticate, boolean checkAuthentication, Set<String> scopes,
                                         Map<String, String[]> reqParams) throws IdentityOAuth2Exception {

        try {

            AuthenticationRequestCacheEntry authRequest = buildAuthenticationRequestCacheEntry(clientId,
                    forceAuthenticate, checkAuthentication, reqParams);
            FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);
            // Build new query param with only type and session data key
            return buildQueryString(sessionDataKey, scopes);
        } catch (UnsupportedEncodingException e) {
            throw new IdentityOAuth2Exception("Error encoding the session key : ", e);
        } finally {
            OAuth2Util.clearClientTenantId();
        }
    }

    private static String buildQueryString(String sessionDataKey, Set<String> scopes) throws UnsupportedEncodingException {

        String type = getProtocolType(scopes);
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, false, true);

        StringBuilder queryStringBuilder = new StringBuilder();
        queryStringBuilder.append(commonAuthURL).
                append("?").
                append(FrameworkConstants.SESSION_DATA_KEY).
                append("=").
                append(URLEncoder.encode(sessionDataKey, UTF_8)).
                append("&").
                append(FrameworkConstants.RequestParams.TYPE).
                append("=").
                append(type);

        return queryStringBuilder.toString();
    }

    private static AuthenticationRequestCacheEntry buildAuthenticationRequestCacheEntry(String clientId,
                 boolean forceAuthenticate, boolean checkAuthentication, Map<String, String[]> reqParams)
            throws IdentityOAuth2Exception {

        String selfPath = OAUTH2_AUTHORIZE;
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();

        int tenantId = OAuth2Util.getClientTenatId();

        //Build the authentication request context.
        authenticationRequest.setCommonAuthCallerPath(selfPath);
        authenticationRequest.setForceAuth(forceAuthenticate);
        authenticationRequest.setPassiveAuth(checkAuthentication);
        authenticationRequest.setRelyingParty(clientId);
        authenticationRequest.setTenantDomain(OAuth2Util.getTenantDomain(tenantId));
        authenticationRequest.setRequestQueryParams(reqParams);

        //Build an AuthenticationRequestCacheEntry which wraps AuthenticationRequestContext
        return new AuthenticationRequestCacheEntry(authenticationRequest);
    }

    private static String getProtocolType(Set<String> scopes) {
        String type = OAUTH2;

        if (scopes != null && scopes.contains(OPENID)) {
            type = OIDC;
        }
        return type;
    }

    /**
     * Returns the consent page URL.
     *
     * @param params
     * @param loggedInUser
     * @return
     */
    public static String getUserConsentURL(OAuth2Parameters params, String loggedInUser, String sessionDataKey,
                                           boolean isOIDC) throws OAuthSystemException {
        String queryString = "";
        if (log.isDebugEnabled()) {
            log.debug("Received Session Data Key is :  " + sessionDataKey);
            if (params == null) {
                log.debug("Received OAuth2 params are Null for UserConsentURL");
            }
        }
        SessionDataCache sessionDataCache = SessionDataCache.getInstance();
        SessionDataCacheEntry entry = sessionDataCache.getValueFromCache(new SessionDataCacheKey(sessionDataKey));
        String consentPage = null;
        String sessionDataKeyConsent = UUID.randomUUID().toString();
        try {
            if (entry == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Cache Entry is Null from SessionDataCache ");
                }
            } else {
                entry.setValidityPeriod(TimeUnit.MINUTES.toNanos(IdentityUtil.getTempDataCleanUpTimeout()));
                sessionDataCache.addToCache(new SessionDataCacheKey(sessionDataKeyConsent),entry);
                if (entry.getQueryString() != null) {
                    queryString = URLEncoder.encode(entry.getQueryString(), UTF_8);
                }
            }


            if (isOIDC) {
                consentPage = OAuth2Util.OAuthURL.getOIDCConsentPageUrl();
            } else {
                consentPage = OAuth2Util.OAuthURL.getOAuth2ConsentPageUrl();
            }
            if (params != null) {
                consentPage += "?" + OAuthConstants.OIDC_LOGGED_IN_USER + "=" + URLEncoder.encode(loggedInUser,
                        UTF_8) + "&application=";

                if (StringUtils.isNotEmpty(params.getDisplayName())) {
                    consentPage += URLEncoder.encode(params.getDisplayName(), UTF_8);
                } else {
                    consentPage += URLEncoder.encode(params.getApplicationName(), UTF_8);
                }
                consentPage += "&tenantDomain=" + getSPTenantDomainFromClientId(params.getClientId());

                consentPage = consentPage + "&" + OAuthConstants.OAuth20Params.SCOPE + "=" + URLEncoder.encode
                        (EndpointUtil.getScope(params), UTF_8) + "&" + OAuthConstants.SESSION_DATA_KEY_CONSENT
                        + "=" + URLEncoder.encode(sessionDataKeyConsent, UTF_8) + "&spQueryParams=" + queryString;
            } else {
                throw new OAuthSystemException("Error while retrieving the application name");
            }
        } catch (UnsupportedEncodingException e) {
            throw new OAuthSystemException("Error while encoding the url", e);
        }

        return consentPage;
    }

    public static String getScope(OAuth2Parameters params) {
        StringBuilder scopes = new StringBuilder();
        for (String scope : params.getScopes()) {
            scopes.append(scope).append(" ");
        }
        return scopes.toString().trim();
    }

    /**
     * Returns the {@code ApplicationAuthenticationService} instance
     *
     * @return
     */
    public static ApplicationManagementService getApplicationManagementService() {
        return (ApplicationManagementService) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService
                (ApplicationManagementService.class, null);
    }
    public static String getRealmInfo() {
        return "Basic realm=" + getHostName();
    }

    public static String getHostName() {
        return ServerConfiguration.getInstance().getFirstProperty("HostName");
    }

    @Deprecated
    public static boolean validateParams(HttpServletRequest request, HttpServletResponse response,
                                         MultivaluedMap<String, String> paramMap) {
        return validateParams(request, paramMap);
    }

    public static boolean validateParams(HttpServletRequest request, MultivaluedMap<String, String> paramMap) {

        if (paramMap != null) {
            for (Map.Entry<String, List<String>> paramEntry : paramMap.entrySet()) {
                if (paramEntry.getValue().size() > 1) {
                    if (log.isDebugEnabled()) {
                        log.debug("Repeated param found:" + paramEntry.getKey());
                    }
                    return false;
                }
            }
        }
        if (request.getParameterMap() != null) {
            Map<String, String[]> map = request.getParameterMap();
            for (Map.Entry<String, String[]> entry : map.entrySet()) {
                if (entry.getValue().length > 1) {
                    if (log.isDebugEnabled()) {
                        log.debug("Repeated param found:" + entry.getKey());
                    }
                    return false;
                }
            }
        }
        return true;
    }

    public static boolean validateParams(OAuthMessage oAuthMessage, MultivaluedMap<String, String> paramMap) {
        return validateParams(oAuthMessage.getRequest(), paramMap);
    }

    /**
     * This method will start a super tenant flow
     */
    public static void startSuperTenantFlow() {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
        carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * This API validate the oauth application. Check whether an application exits for given cosumerKey and check
     * it's status
     * @param consumerKey clientId
     * @throws InvalidApplicationClientException
     */
    public static void validateOauthApplication(String consumerKey) throws InvalidApplicationClientException {

        String appState = EndpointUtil.getOAuth2Service().getOauthApplicationState(consumerKey);

        if (StringUtils.isEmpty(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("A valid OAuth client could not be found for client_id: " + consumerKey);
            }

            throw new InvalidApplicationClientException("A valid OAuth client could not be found for client_id: " + consumerKey);
        }

        if (isNotActiveState(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("App is not in active state in client ID: " + consumerKey + ". App state is:" + appState);
            }
            throw new InvalidApplicationClientException("Oauth application is not in active state");
        }

        if (log.isDebugEnabled()) {
            log.debug("Oauth App validation success for consumer key: " + consumerKey);
        }
    }

    private static boolean isNotActiveState(String appState) {
        return !APP_STATE_ACTIVE.equalsIgnoreCase(appState);
    }

    public static String getSPTenantDomainFromClientId(String clientId) {

        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            return OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error while getting oauth app for client Id: " + clientId, e);
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
    }
}
