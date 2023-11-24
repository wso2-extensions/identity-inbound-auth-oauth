/*
 * Copyright (c) 2013, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.owasp.encoder.Encode;
import org.slf4j.MDC;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.DefaultOIDCProviderRequestBuilder;
import org.wso2.carbon.identity.discovery.builders.OIDCProviderRequestBuilder;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.exception.BadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointBadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.par.core.ParAuthService;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeConsentException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.model.OAuth2ScopeConsentResponse;
import org.wso2.carbon.identity.oauth2.scopeservice.OAuth2Resource;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCRequestObjectUtil;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidator;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.ws.rs.core.MultivaluedMap;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.getRedirectURL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.CODE_IDTOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_REQ_HEADER_AUTH_METHOD_BASIC;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ResponseModes.JWT;

/**
 * Util class which contains common methods used by all the OAuth endpoints.
 */
public class EndpointUtil {

    private static final Log log = LogFactory.getLog(EndpointUtil.class);
    private static final String OAUTH2 = "oauth2";
    private static final String OPENID = "openid";
    private static final String OIDC = "oidc";
    private static final String OAUTH2_AUTHORIZE = "/oauth2/authorize";
    public static final String OAUTH2_CIBA_ENDPOINT = "oauth2/ciba";
    private static final String UTF_8 = "UTF-8";
    public static final String PROP_CLIENT_ID = "client_id";
    private static final String PROP_GRANT_TYPE = "response_type";
    private static final String PROP_RESPONSE_TYPE = "response_type";
    private static final String PROP_SCOPE = "scope";
    private static final String PROP_OIDC_SCOPE = "requested_oidc_scopes";
    private static final String PROP_ERROR = "error";
    private static final String PROP_ERROR_DESCRIPTION = "error_description";
    private static final String PROP_REDIRECT_URI = "redirect_uri";
    private static final String REQUEST_URI = "request_uri";
    private static final String NOT_AVAILABLE = "N/A";
    private static final String UNKNOWN_ERROR = "unknown_error";
    private static OAuth2Service oAuth2Service;
    private static OAuth2ScopeService oAuth2ScopeService;
    private static OAuthAdminServiceImpl oAuthAdminService;
    private static ScopeMetadataService scopeMetadataService;
    private static SSOConsentService ssoConsentService;
    private static OAuthServerConfiguration oauthServerConfiguration;
    private static RequestObjectService requestObjectService;
    private static CibaAuthServiceImpl cibaAuthService;
    private static ParAuthService parAuthService;
    private static IdpManager idpManager;
    private static final String ALLOW_ADDITIONAL_PARAMS_FROM_ERROR_URL = "OAuth.AllowAdditionalParamsFromErrorUrl";
    private static final String IDP_ENTITY_ID = "IdPEntityId";
    private static Class<? extends OAuthAuthzRequest> oAuthAuthzRequestClass;

    public static void setIdpManager(IdpManager idpManager) {

        EndpointUtil.idpManager = idpManager;
    }

    public static void setOAuth2Service(OAuth2Service oAuth2Service) {

        EndpointUtil.oAuth2Service = oAuth2Service;
    }

    public static void setOAuth2ScopeService(OAuth2ScopeService oAuth2ScopeService) {

        EndpointUtil.oAuth2ScopeService = oAuth2ScopeService;
    }

    public static void setOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        EndpointUtil.oAuthAdminService = oAuthAdminService;
    }

    public static void setSSOConsentService(SSOConsentService ssoConsentService) {

        EndpointUtil.ssoConsentService = ssoConsentService;
    }

    public static void setOauthServerConfiguration(OAuthServerConfiguration oauthServerConfiguration) {

        EndpointUtil.oauthServerConfiguration = oauthServerConfiguration;
    }

    public static void setRequestObjectService(RequestObjectService requestObjectService) {

        EndpointUtil.requestObjectService = requestObjectService;
    }

    public static ScopeMetadataService getScopeMetadataService() {

        return scopeMetadataService;
    }

    public static void setScopeMetadataService(ScopeMetadataService scopeMetadataService) {

        EndpointUtil.scopeMetadataService = scopeMetadataService;
    }

    private EndpointUtil() {

    }

    /**
     * Returns the registered {@code {@link SSOConsentService}} instance
     *
     * @return
     */
    public static SSOConsentService getSSOConsentService() {

        return ssoConsentService;
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

        return requestObjectService;
    }

    /**
     * Returns the {@code OAuth2Service} instance
     *
     * @return OAuth2Service
     */
    public static OAuth2Service getOAuth2Service() {

        return oAuth2Service;
    }

    /**
     * Returns the {@code OAuthServerConfiguration} instance
     *
     * @return OAuthServerConfiguration
     */
    public static OAuthServerConfiguration getOAuthServerConfiguration() {

        return oauthServerConfiguration;
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
     * @param errorCode    : Error Code
     * @param errorMessage : Error Message
     * @param appName      : Application Name
     * @return ErrorPageURL
     */
    public static String getErrorPageURL(String errorCode, String errorMessage, String appName) {

        String errorPageUrl = OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl();
        String correlationId = MDC.get(OAuthConstants.CORRELATION_ID_MDC);
        try {

            if (isNotBlank(errorCode)) {
                errorPageUrl = FrameworkUtils.appendQueryParamsStringToUrl(errorPageUrl,
                        OAuthConstants.OAUTH_ERROR_CODE + "=" + URLEncoder.encode(errorCode, UTF_8));
            }

            if (isNotBlank(errorMessage)) {
                errorPageUrl = FrameworkUtils.appendQueryParamsStringToUrl(errorPageUrl,
                        OAuthConstants.OAUTH_ERROR_MESSAGE + "=" + URLEncoder.encode(errorMessage, UTF_8));
            }

            if (isNotBlank(correlationId)) {
                errorPageUrl = FrameworkUtils.appendQueryParamsStringToUrl(errorPageUrl,
                        FrameworkConstants.RequestParams.CORRELATION_ID + "=" + URLEncoder.encode(correlationId,
                                UTF_8));
            }

        } catch (UnsupportedEncodingException e) {
            //ignore
            if (log.isDebugEnabled()) {
                log.debug("Error while encoding the error page url", e);
            }
        }

        if (appName != null) {
            try {
                errorPageUrl += "&application" + "=" + URLEncoder.encode(appName, UTF_8);
            } catch (UnsupportedEncodingException e) {
                //ignore
                if (log.isDebugEnabled()) {
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
        if (request == null || !isAllowAdditionalParamsFromErrorUrlEnabled()) {
            return redirectURL;
        }
        return getRedirectURL(redirectURL, request);
    }

    /**
     * Returns the error page URL.
     * If RedirectToRequestedRedirectUri property is true and if the resource owner denies the access request or if the
     * request fails for reasons other than a missing or invalid redirection URI, the authorization server informs
     * the client by adding the error code, error message and state parameters to the query component of the
     * redirection URI.
     * <p>
     * If RedirectToRequestedRedirectUri property is false OR if the request fails due to a missing, invalid, or
     * mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD
     * inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid
     * redirection URI.
     *
     * @param request      HttpServletRequest
     * @param errorCode    Error Code
     * @param subErrorCode Sub error code to identify the exact reason for invalid request
     * @param errorMessage Message of the error
     * @param appName      Application Name
     * @return url of the redirect error page
     */
    public static String getErrorPageURL(HttpServletRequest request, String errorCode, String subErrorCode, String
            errorMessage, String appName) {

        return getErrorPageURL(request, errorCode, subErrorCode, errorMessage, appName, new OAuth2Parameters());
    }

    /**
     * Returns the error page URL.
     * If RedirectToRequestedRedirectUri property is true and if the resource owner denies the access request or if the
     * request fails for reasons other than a missing or invalid redirection URI, the authorization server informs
     * the client by adding the error code, error message and state parameters to the query component of the
     * redirection URI.
     * <p>
     * If RedirectToRequestedRedirectUri property is false OR if the request fails due to a missing, invalid, or
     * mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD
     * inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid
     * redirection URI.
     *
     * @param request           HttpServletRequest
     * @param errorCode         Error Code
     * @param subErrorCode      Sub error code to identify the exact reason for invalid request
     * @param errorMessage      Message of the error
     * @param appName           Application Name
     * @param oAuth2Parameters  OAuth2Parameters
     * @return url of the redirect error page
     */
    public static String getErrorPageURL(HttpServletRequest request, String errorCode, String subErrorCode, String
            errorMessage, String appName, OAuth2Parameters oAuth2Parameters) {
        // By default RedirectToRequestedRedirectUri property is set to true. Therefore by default error page
        // is returned to the uri given in the request.
        // For the backward compatibility, this property can be set to false and then the error page is
        // redirected to a common OAuth Error page.
        if (!OAuthServerConfiguration.getInstance().isRedirectToRequestedRedirectUriEnabled()) {
            return getErrorPageURL(request, errorCode, errorMessage, appName);
        } else if (subErrorCode.equals(OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REDIRECT_URI) ||
                subErrorCode.equals(OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_CLIENT) ||
                StringUtils.isBlank(request.getParameter(PROP_REDIRECT_URI))) {
            return getErrorPageURL(request, errorCode, errorMessage, appName);
        } else {
            String redirectUri = request.getParameter(OAuthConstants.OAuth20Params.REDIRECT_URI);

            // If the redirect url is not set in the request, page is redirected to common OAuth error page.
            if (StringUtils.isBlank(redirectUri)) {
                redirectUri = getErrorPageURL(request, errorCode, errorMessage, appName);
            } else {
                String state = retrieveStateForErrorURL(request, oAuth2Parameters);
                redirectUri = getUpdatedRedirectURL(request, redirectUri, errorCode, errorMessage, state, appName);
            }
            return redirectUri;
        }

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
        if (isAllowAdditionalParamsFromErrorUrlEnabled() || isRedirectToCommonErrorPage(params, redirectURL)) {
            // Appending additional parameters if the <AllowAdditionalParamsFromErrorUrl> config is enabled or
            // the error is redirected to the common error page.
            return getRedirectURL(redirectURL, request);
        } else {
            return redirectURL;
        }
    }

    public static String getErrorRedirectURL(OAuthProblemException ex, OAuth2Parameters params) {

        String redirectURL = null;
        try {
            if (params != null) {
                if (isNotBlank(params.getRedirectURI())) {
                    if (OAuth2Util.isImplicitResponseType(params.getResponseType()) ||
                            OAuth2Util.isHybridResponseType(params.getResponseType())) {
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
     * @param forceAuthenticate   : True if need to authenticate forcefully
     * @param scopes              : Scopes set
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
     * @deprecated use {@link #getLoginPageURL(String, String, boolean, boolean, Set, Map, HttpServletRequest)} instead.
     */
    @Deprecated
    public static String getLoginPageURL(String clientId, String sessionDataKey,
                                         boolean forceAuthenticate, boolean checkAuthentication, Set<String> scopes,
                                         Map<String, String[]> reqParams)
            throws IdentityOAuth2Exception {

            return getLoginPageURL(clientId, sessionDataKey, forceAuthenticate, checkAuthentication, scopes,
                    reqParams, null);
    }

    /**
     * Returns the login page URL.
     *
     * @param clientId                  Client id of the application.
     * @param sessionDataKey            Session Data key.
     * @param reqParams                 Parameters from the authentication request.
     * @param forceAuthenticate         Whether it is a force authentication or not.
     * @param checkAuthentication       Whether to check the authentication or not.
     * @param scopes                    Request scopes.
     * @return                          Login Page URL.
     * @throws IdentityOAuth2Exception  IdentityOAuth2Exception.
     */
    public static String getLoginPageURL(String clientId, String sessionDataKey,
                                         boolean forceAuthenticate, boolean checkAuthentication, Set<String> scopes,
                                         Map<String, String[]> reqParams, HttpServletRequest request)
            throws IdentityOAuth2Exception {

        try {

            AuthenticationRequestCacheEntry authRequest = buildAuthenticationRequestCacheEntry(clientId,
                    forceAuthenticate, checkAuthentication, reqParams);
            if (request != null) {
                request.setAttribute(FrameworkConstants.RequestAttribute.AUTH_REQUEST, authRequest);
            } else {
                FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);
            }
            // Build new query param with only type and session data key
            return buildQueryString(sessionDataKey, scopes);
        } catch (UnsupportedEncodingException | URLBuilderException e) {
            throw new IdentityOAuth2Exception("Error building query string for login.", e);
        } finally {
            OAuth2Util.clearClientTenantId();
        }
    }

    private static String buildQueryString(String sessionDataKey, Set<String> scopes)
            throws UnsupportedEncodingException, URLBuilderException {

        String type = getProtocolType(scopes);
        String commonAuthURL = ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build()
                .getAbsolutePublicURL();

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
                                                                                        boolean forceAuthenticate,
                                                                                        boolean checkAuthentication,
                                                                                        Map<String, String[]> reqParams)
            throws IdentityOAuth2Exception, URLBuilderException {

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();

        int tenantId = OAuth2Util.getClientTenatId();

        //Build the authentication request context.
        String commonAuthCallerPath =
                ServiceURLBuilder.create().addPath(OAUTH2_AUTHORIZE).build().getRelativeInternalURL();
        authenticationRequest.setCommonAuthCallerPath(commonAuthCallerPath);
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
     * @deprecated use {{@link #getUserConsentURL(OAuth2Parameters, String, String, boolean, OAuthMessage)}}
     */
    @Deprecated
    public static String getUserConsentURL(OAuth2Parameters params, String loggedInUser, String sessionDataKey,
                                           boolean isOIDC) throws OAuthSystemException {

        return getUserConsentURL(params, loggedInUser, sessionDataKey, isOIDC, null);
    }

    /**
     * Returns the consent page URL.
     *
     * @param params            OAuth2 Parameters.
     * @param loggedInUser      The logged in user
     * @param isOIDC            Whether the flow is an OIDC or not.
     * @param oAuthMessage      oAuth Message.
     * @return                  The consent url.
     * @deprecated use {{@link #getUserConsentURL(OAuth2Parameters, String, String, OAuthMessage, String)}} instead.
     */
    @Deprecated
    public static String getUserConsentURL(OAuth2Parameters params, String loggedInUser, String sessionDataKey,
                                           boolean isOIDC, OAuthMessage oAuthMessage) throws OAuthSystemException {

        return getUserConsentURL(params, loggedInUser, sessionDataKey, null, StringUtils.EMPTY);
    }

    /**
     * Returns the consent page URL.
     *
     * @param params                OAuth2 Parameters.
     * @param loggedInUser          The logged in user
     * @param oAuthMessage          oAuth Message.
     * @param additionalQueryParams Additional query params to be appended to the consent page url.
     * @return                      The consent url.
     */
    public static String getUserConsentURL(OAuth2Parameters params, String loggedInUser, String sessionDataKey,
                                           OAuthMessage oAuthMessage, String additionalQueryParams)
            throws OAuthSystemException {

        String queryString = "";
        String clientId = "";
        if (log.isDebugEnabled()) {
            log.debug("Received Session Data Key is: " + sessionDataKey);
            if (params == null) {
                log.debug("Received OAuth2 params are Null for UserConsentURL");
            }
        }

        boolean isOIDC = false;
        if (params != null) {
            isOIDC = OAuth2Util.isOIDCAuthzRequest(params.getScopes());
            clientId = params.getClientId();
        }

        SessionDataCache sessionDataCache = SessionDataCache.getInstance();
        SessionDataCacheEntry entry;
        if (oAuthMessage != null) {
            entry = oAuthMessage.getResultFromLogin();
        } else {
            entry = sessionDataCache.getValueFromCache(new SessionDataCacheKey(sessionDataKey));
        }

        AuthenticatedUser user = null;
        String consentPageUrl = null;
        String sessionDataKeyConsent = UUID.randomUUID().toString();
        try {
            if (entry != null && entry.getQueryString() != null) {
                queryString = getQueryString(params, entry);
            }

            ServiceProvider sp = getServiceProvider(params);
            if (sp == null) {
                throw new OAuthSystemException("Unable to find a service provider with client_id: " + clientId);
            }

            if (isExternalConsentPageEnabledForSP(sp)) {
                consentPageUrl = OAuth2Util.resolveExternalConsentPageUrl(sp.getTenantDomain());
            } else if (isOIDC) {
                consentPageUrl = OAuth2Util.OAuthURL.getOIDCConsentPageUrl();
            } else {
                consentPageUrl = OAuth2Util.OAuthURL.getOAuth2ConsentPageUrl();
            }
            if (params != null) {
                consentPageUrl += "?" + OAuthConstants.OIDC_LOGGED_IN_USER + "=" + URLEncoder.encode(loggedInUser,
                        UTF_8) + "&application=";

                if (StringUtils.isNotEmpty(params.getDisplayName())) {
                    consentPageUrl += URLEncoder.encode(params.getDisplayName(), UTF_8);
                } else {
                    consentPageUrl += URLEncoder.encode(params.getApplicationName(), UTF_8);
                }
                consentPageUrl += "&tenantDomain=" + getSPTenantDomainFromClientId(clientId);

                if (entry != null) {
                    user = entry.getLoggedInUser();
                }
                List<String> consentRequiredScopesList = filterConsentRequiredScopes(user, params);
                params.setConsentRequiredScopes(new HashSet<>(consentRequiredScopesList));
                String consentRequiredScopes = getConsentRequiredScopesAsString(params.getConsentRequiredScopes());

                consentPageUrl = consentPageUrl + "&" + OAuthConstants.OAuth20Params.SCOPE + "=" + URLEncoder.encode
                        (consentRequiredScopes, UTF_8) + "&" + OAuthConstants.SESSION_DATA_KEY_CONSENT
                        + "=" + URLEncoder.encode(sessionDataKeyConsent, UTF_8) + "&" + "&spQueryParams=" + queryString;

                // Append scope metadata to additionalQueryParams.
                String scopeMetadataQueryParam = getScopeMetadataQueryParam(params.getConsentRequiredScopes(),
                        params.getTenantDomain());
                if (StringUtils.isNotBlank(scopeMetadataQueryParam)) {
                    additionalQueryParams = StringUtils.isNotBlank(additionalQueryParams) ? additionalQueryParams +
                            "&" + scopeMetadataQueryParam : scopeMetadataQueryParam;
                }

                // Append additional query params to the consent page url.
                consentPageUrl = FrameworkUtils.appendQueryParamsStringToUrl(consentPageUrl, additionalQueryParams);

                if (entry != null) {
                    // Filter the query parameters from the consent page url.
                    consentPageUrl = filterQueryParamsFromConsentPageUrl(entry.getEndpointParams(), consentPageUrl,
                            sessionDataKeyConsent);
                    if (isExternalConsentPageEnabledForSP(sp)) {
                        entry.setRemoveOnConsume(true);
                    }
                    entry.setValidityPeriod(TimeUnit.MINUTES.toNanos(IdentityUtil.getTempDataCleanUpTimeout()));
                    sessionDataCache.addToCache(new SessionDataCacheKey(sessionDataKeyConsent), entry);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Cache Entry is Null from SessionDataCache.");
                    }
                }
            } else {
                throw new OAuthSystemException("Error while retrieving the application name");
            }
        } catch (UnsupportedEncodingException e) {
            throw new OAuthSystemException("Error while encoding the url", e);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException("Error retrieve Service Provider for clientId:" + clientId , e);
        }

        return consentPageUrl;
    }


    private static ServiceProvider getServiceProvider(OAuth2Parameters params) throws IdentityOAuth2Exception {

        ServiceProvider sp = null;
        if (params != null) {
            sp = OAuth2Util.getServiceProvider(params.getClientId());
        }
        return sp;
    }

    private static String getScopeMetadataQueryParam(Set<String> scopes, String tenantDomain) {

        try {
            List<String> oidcScopeList = oAuthAdminService.getRegisteredOIDCScope(tenantDomain);
            List<String> nonOidcScopeList = new ArrayList<>();
            oidcScopeList.retainAll(scopes);
            nonOidcScopeList.addAll(scopes.stream().filter(scope ->
                    !oidcScopeList.contains(scope)).collect(Collectors.toList()));

            if (nonOidcScopeList.isEmpty()) {
                return null;
            }
            List<OAuth2Resource> scopesMetaData = scopeMetadataService.getMetadata(nonOidcScopeList);
            String scopeMetadata = new Gson().toJson(scopesMetaData);
            return "scopeMetadata=" + URLEncoder.encode(scopeMetadata, UTF_8);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving scope metadata for scopes: " + scopes, e);
            }
        }
        return null;
    }

    private static String filterQueryParamsFromConsentPageUrl(Map<String, Serializable> endpointParams,
                                                              String consentPageUrl, String sessionDataKeyConsent)
            throws OAuthSystemException {

        if (isAuthEndpointRedirectParamsFilterConfigAvailable()) {
            return FrameworkUtils.getRedirectURLWithFilteredParams(consentPageUrl,
                    endpointParams);
        } else if (isConsentPageRedirectParamsAllowed()) {
            // Return the consent url without filtering the query params for backward compatibility.
            return consentPageUrl;
        } else {
            return EndpointUtil.getRedirectURLWithFilteredParams(consentPageUrl,
                    endpointParams, sessionDataKeyConsent);
        }
    }

    private static String getConsentRequiredScopesAsString(Set<String> consentRequiredScopesSet) {

        String consentRequiredScopes = StringUtils.EMPTY;
        if (CollectionUtils.isNotEmpty(consentRequiredScopesSet)) {
            consentRequiredScopes = String.join(" ", consentRequiredScopesSet).trim();
        }
        return consentRequiredScopes;
    }

    private static String getQueryString(OAuth2Parameters params, SessionDataCacheEntry entry) throws
            UnsupportedEncodingException, OAuthSystemException {

        String queryString;
        queryString = entry.getQueryString();
        if (queryString.contains(REQUEST_URI) && params != null) {
            // When request_uri requests come without redirect_uri, we need to append it to the SPQueryParams
            // to be used in storing consent data
            queryString = queryString +
                    "&" + PROP_REDIRECT_URI + "=" + URLEncoder.encode(params.getRedirectURI(), UTF_8);
        }

        if (params != null) {
            queryString = queryString + "&" + PROP_OIDC_SCOPE +
                    "=" + URLEncoder.encode(StringUtils.join(getRequestedOIDCScopes(params), " "), UTF_8);
        }
        entry.setQueryString(queryString);
        queryString = URLEncoder.encode(queryString, UTF_8);
        return queryString;
    }

    private static boolean isAuthEndpointRedirectParamsFilterConfigAvailable() {

        return FileBasedConfigurationBuilder.getInstance().isAuthEndpointRedirectParamsConfigAvailable();
    }

    /**
     * Returns the consent page URL after filtering the query params.
     *
     * @param redirectUrl           The redirect URL.
     * @param endpointParams        The map for store filtered params.
     * @param sessionDataKeyConsent The value of sessionDataKeyConsent.
     * @return redirect URL after filtering the query params except the sessionDataKeyConsent.
     */
    private static String getRedirectURLWithFilteredParams(String redirectUrl,
                                                          Map<String, Serializable> endpointParams, String
                                                                   sessionDataKeyConsent) throws OAuthSystemException {

        URIBuilder uriBuilder;

        try {
            uriBuilder = new URIBuilder(redirectUrl);
        } catch (URISyntaxException e) {
            log.warn("Unable to filter redirect params for url." + redirectUrl, e);
            throw new OAuthSystemException("Unable to filter redirect params for url: " + redirectUrl, e);
        }

        List<NameValuePair> queryParamsList = uriBuilder.getQueryParams();
        // Store query params in the endpointParams map.
        if (!queryParamsList.isEmpty()) {
            endpointParams.putAll(queryParamsList.stream()
                    .filter(queryParam -> !queryParam.getName().equals(OAuthConstants.SESSION_DATA_KEY_CONSENT))
                    .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue)));
        }

        // Remove all the query params from the consent URL
        uriBuilder.clearParameters();
        // Set the sessionDataKeyConsent to redirect URL.
        if (sessionDataKeyConsent != null) {
            uriBuilder.setParameter(OAuthConstants.SESSION_DATA_KEY_CONSENT, sessionDataKeyConsent);
        }

        return uriBuilder.toString();

    }

    /**
     * Check if the user has already given consent to required OAuth scopes.
     *
     * @param user              Authenticated user.
     * @param oAuth2Parameters  OAuth2 parameters.
     * @return  True if user has given consent to all the requested OAuth scopes.
     * @throws IdentityOAuth2ScopeConsentException
     * @throws IdentityOAuthAdminException
     */
    public static boolean isUserAlreadyConsentedForOAuthScopes(AuthenticatedUser user,
                                                               OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2ScopeException, IdentityOAuthAdminException, OAuthSystemException {

        List<String> scopesToBeConsented = new ArrayList<>(oAuth2Parameters.getScopes());
        if (log.isDebugEnabled()) {
            log.debug("Checking if user has already provided the consent for requested scopes : " +
                    scopesToBeConsented.stream().collect(Collectors.joining(" ")) + " for client : " +
                    oAuth2Parameters.getClientId());
        }
        // Remove OIDC scopes.
        scopesToBeConsented.removeAll(getOIDCScopeNames());
        String userId = getUserIdOfAuthenticatedUser(user);
        String appId = getAppIdFromClientId(oAuth2Parameters.getClientId());
        return oAuth2ScopeService.hasUserProvidedConsentForAllRequestedScopes(userId, appId,
                IdentityTenantUtil.getTenantId(user.getTenantDomain()), scopesToBeConsented);
    }

    /**
     * Store consent given for OAuth scopes by the user for the application.
     *
     * @param user                      Authenticated user.
     * @param params                    OAuth2 parameters.
     * @param overrideExistingConsent   True to override existing consent, otherwise merge the new consent with
     *                                  existing consent.
     * @throws OAuthSystemException
     */
    public static void storeOAuthScopeConsent(AuthenticatedUser user, OAuth2Parameters params,
                                              boolean overrideExistingConsent) throws OAuthSystemException {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.PERSIST_OAUTH_SCOPE_CONSENT);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        try {
            Set<String> userApprovedScopesSet = params.getConsentRequiredScopes();
            if (CollectionUtils.isNotEmpty(userApprovedScopesSet)) {
                if (log.isDebugEnabled()) {
                    log.debug("Storing user consent for approved scopes : " + userApprovedScopesSet.stream()
                            .collect(Collectors.joining(" ")) + " of client : " + params.getClientId());
                }
                List<String> userApprovedScopes = new ArrayList<>(userApprovedScopesSet);
                // Remove OIDC scopes.
                userApprovedScopes.removeAll(getOIDCScopeNames());
                String userId = getUserIdOfAuthenticatedUser(user);
                String appId = getAppIdFromClientId(params.getClientId());
                if (overrideExistingConsent) {
                    if (log.isDebugEnabled()) {
                        log.debug("Overriding existing consents of the user : " + userId + " for application : " +
                                appId);
                    }
                    oAuth2ScopeService.addUserConsentForApplication(userId, appId,
                            IdentityTenantUtil.getTenantId(user.getTenantDomain()),
                            userApprovedScopes, null);
                } else {
                    boolean isUserConsentExist = oAuth2ScopeService.isUserHasAnExistingConsentForApp(
                            userId, appId, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
                    if (isUserConsentExist) {
                        if (log.isDebugEnabled()) {
                            log.debug("Updating existing consents of the user : " + userId + " for application : " +
                                    appId);
                        }
                        oAuth2ScopeService.updateUserConsentForApplication(userId, appId,
                                IdentityTenantUtil.getTenantId(user.getTenantDomain()),
                                userApprovedScopes, null);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Adding new consent to the user : " + userId + " for application : " + appId);
                        }
                        oAuth2ScopeService.addUserConsentForApplication(userId, appId,
                                IdentityTenantUtil.getTenantId(user.getTenantDomain()),
                                userApprovedScopes, null);
                    }
                }
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is null when diagnostic logs are disabled.
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, params.getClientId())
                            .inputParam("approved scopes", userApprovedScopes)
                            .inputParam(LogConstants.InputKeys.USER_ID, userId)
                            .inputParam("override existing consent", overrideExistingConsent)
                            .resultMessage("Successfully persisted oauth scopes.")
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            }
        } catch (IdentityOAuthAdminException e) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null when diagnostic logs are disabled.
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("Error occurred while removing OIDC scopes from approved OAuth scopes.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new OAuthSystemException(
                    "Error occurred while removing OIDC scopes from approved OAuth scopes.", e);
        } catch (IdentityOAuth2ScopeException e) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null when diagnostic logs are disabled.
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("Error occurred while storing OAuth scope consent.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new OAuthSystemException("Error occurred while storing OAuth scope consent.", e);
        }
    }

    private static List<String> getOIDCScopeNames() throws IdentityOAuthAdminException {

        return Arrays.asList(ArrayUtils.nullToEmpty(oAuthAdminService.getScopeNames()));
    }

    /**
     * Return a list of consent requested OIDC scopes
     *
     * @param params OAuth2 parameters.
     * @return consent requested OIDC scopes in lower case
     * @throws OAuthSystemException If retrieving OIDC scopes failed.
     */
    private static List<String> getRequestedOIDCScopes(OAuth2Parameters params)
            throws OAuthSystemException {

        Set<String> allowedScopes = params.getScopes();
        List<String> requestedOIDCScopes = new ArrayList<>();
        try {
            // Get registered OIDC scopes.
            List<String> oidcScopeList = oAuthAdminService.getRegisteredOIDCScope(params.getTenantDomain());
            for (String scope : allowedScopes) {
                if (oidcScopeList.contains(scope)) {
                    requestedOIDCScopes.add(scope.toLowerCase());
                }
            }
        } catch (IdentityOAuthAdminException e) {
            throw new OAuthSystemException("Error while retrieving OIDC scopes.", e);
        }
        return requestedOIDCScopes;
    }

    /**
     * Drop unregistered scopes from consent required scopes.
     *
     * @param params OAuth2 parameters.
     * @return consent required scopes
     * @throws OAuthSystemException If dropping unregistered scopes failed.
     */
    private static List<String> dropUnregisteredScopesFromConsentRequiredScopes(OAuth2Parameters params)
            throws OAuthSystemException {

        Set<String> allowedScopes = params.getScopes();
        List<String> allowedRegisteredScopes = new ArrayList<>();
        if (CollectionUtils.isNotEmpty(allowedScopes)) {
            try {
                startTenantFlow(params.getTenantDomain());
                /* If DropUnregisteredScopes scopes config is enabled then any unregistered scopes(excluding internal
                 scopes and allowed scopes) will be dropped. Therefore, they will not be shown in the user consent
                 screen.*/
                if (oauthServerConfiguration.isDropUnregisteredScopes()) {
                    if (log.isDebugEnabled()) {
                        log.debug("DropUnregisteredScopes config is enabled. Attempting to drop unregistered scopes.");
                    }
                    allowedScopes = dropUnregisteredScopes(params);
                }
                for (String scope : allowedScopes) {
                    allowedRegisteredScopes.add(scope);
                }
            } catch (OAuthSystemException e) {
                throw new OAuthSystemException("Error while dropping unregistered scopes.", e);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Allowed registered scopes : " + allowedRegisteredScopes.stream()
                    .collect(Collectors.joining(" ")) + " for client : " + params.getClientId());
        }
        return allowedRegisteredScopes;
    }

    private static List<String> filterConsentRequiredScopes(AuthenticatedUser user, OAuth2Parameters params)
            throws OAuthSystemException {

        try {
            //Filter out unregistered scopes to prevent those scopes prompt for consent in the consent page.
            List<String> consentRequiredScopes = dropUnregisteredScopesFromConsentRequiredScopes(params);

            if (user != null && !isPromptContainsConsent(params)) {
                String userId = getUserIdOfAuthenticatedUser(user);
                String appId = getAppIdFromClientId(params.getClientId());
                OAuth2ScopeConsentResponse existingUserConsent = oAuth2ScopeService.getUserConsentForApp(
                        userId, appId, IdentityTenantUtil.getTenantId(user.getTenantDomain()));
                if (existingUserConsent != null) {
                    if (CollectionUtils.isNotEmpty(existingUserConsent.getApprovedScopes())) {
                        consentRequiredScopes.removeAll(existingUserConsent.getApprovedScopes());
                    }
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Consent required scopes : " + StringUtils.join(consentRequiredScopes, " ")
                        + " for request from client : " + params.getClientId());
            }
            return consentRequiredScopes;
        } catch (IdentityOAuth2ScopeException e) {
            throw new OAuthSystemException("Error occurred while retrieving user consents OAuth scopes.");
        }
    }

    private static String getUserIdOfAuthenticatedUser(AuthenticatedUser user) throws OAuthSystemException {

        try {
            return user.getUserId();
        } catch (UserIdNotFoundException e) {
            throw new OAuthSystemException("User id not found for user: " + user.getLoggableMaskedUserId(), e);
        }
    }

    private static String getAppIdFromClientId(String clientId) throws OAuthSystemException {

        try {
            ServiceProvider sp = OAuth2Util.getServiceProvider(clientId);
            if (sp != null) {
                return sp.getApplicationResourceId();
            }
            throw new OAuthSystemException("Unable to find an service provider with client Id : " + clientId);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException("Error occurred while resolving application Id using the client Id : "
                    + clientId, e);
        }
    }

    private static boolean isPromptContainsConsent(OAuth2Parameters oauth2Params) {

        String[] prompts = null;
        if (StringUtils.isNotBlank(oauth2Params.getPrompt())) {
            prompts = oauth2Params.getPrompt().trim().split("\\s");
        }
        return prompts != null && Arrays.asList(prompts).contains(OAuthConstants.Prompt.CONSENT);
    }

    private static void startTenantFlow(String tenantDomain) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantDomain(tenantDomain, true);
    }

    private static Set<String> dropUnregisteredScopes(OAuth2Parameters params) throws OAuthSystemException {

        Set<String> requestedScopes = new HashSet<>(params.getScopes());
        Set<String> registeredScopes = getRegisteredScopes(requestedScopes);
        List<String> allowedScopesFromConfig = oauthServerConfiguration.getAllowedScopes();
        Set<String> filteredScopes = new HashSet<>();

        // Filtering allowed scopes.
        requestedScopes.forEach(scope -> {
            if (StringUtils.isBlank(scope)) {
                return;
            }
            if (scope.startsWith("internal_") // Check for internal scopes.
                    || scope.equalsIgnoreCase(Oauth2ScopeConstants.SYSTEM_SCOPE) // Check for SYSTEM scope.
                    || OAuth2Util.isAllowedScope(allowedScopesFromConfig, scope) // Check for allowed scopes config.
                    || registeredScopes.contains(scope)) { // Check for registered scopes.

                filteredScopes.add(scope);
            }
        });

        if (log.isDebugEnabled()) {
            log.debug(String.format("Dropping unregistered scopes(excluding internal and allowed scopes). " +
                            "Requested scopes: %s | Filtered result: %s",
                    requestedScopes,
                    StringUtils.join(filteredScopes, " ")));
        }

        return filteredScopes;
    }

    private static Set<String> getRegisteredScopes(Set<String> requestedScopes) throws OAuthSystemException {

        try {
            String requestedScopesStr = StringUtils.join(requestedScopes, " ");
            Set<String> registeredScopes = new HashSet<>();
            Set<Scope> registeredScopeSet = oAuth2ScopeService.getScopes(null, null, true, requestedScopesStr);
            registeredScopeSet.forEach(scope -> registeredScopes.add(scope.getName()));
            return registeredScopes;
        } catch (IdentityOAuth2ScopeServerException e) {
            throw new OAuthSystemException("Error occurred while retrieving registered scopes.", e);
        }
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

    @Deprecated
    public static boolean validateParams(HttpServletRequest request, MultivaluedMap<String, String> paramMap) {

        return validateParams(request, (Map<String, List<String>>) paramMap);
    }

    public static boolean validateParams(HttpServletRequest request, Map<String, List<String>> paramMap) {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        if (paramMap != null) {
            for (Map.Entry<String, List<String>> paramEntry : paramMap.entrySet()) {
                if (paramEntry.getValue().size() > 1) {
                    if (log.isDebugEnabled()) {
                        log.debug("Repeated param found:" + paramEntry.getKey());
                    }
                    if (diagnosticLogBuilder != null) {
                        // diagnosticLogBuilder is null when diagnostic logs are disabled.
                        diagnosticLogBuilder.inputParam("param keys", paramMap.keySet())
                                .resultMessage("Parameter with name: '" + paramEntry.getKey() + "' is repeated in " +
                                        "the request.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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
                    if (diagnosticLogBuilder != null) {
                        // diagnosticLogBuilder is null when diagnostic logs are disabled.
                        diagnosticLogBuilder.inputParam("param keys", map.keySet())
                                .resultMessage("Parameter with name: '" + entry.getKey() + "' is repeated in the " +
                                        "request.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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

    public static Map<String, List<String>> parseJsonTokenRequest(String jsonPayload) throws
            TokenEndpointBadRequestException {

        JsonFactory factory = new JsonFactory();
        Map<String, List<String>> requestParams = new HashMap<>();
        try {
            JsonParser parser  = factory.createParser(jsonPayload);
            // Skip the first START_OBJECT token. i.e the beginning of the payload: '{'.
            parser.nextToken();
            while (!parser.isClosed()) {
                JsonToken currentToken = parser.nextToken();
                if (currentToken == null) {
                    continue;
                }
                if (currentToken.isScalarValue()) {
                    // If the current token is a scalar value, add it to a map along with the corresponding json key.
                    String key = parser.currentName();
                    String value = parser.getValueAsString();
                    requestParams.computeIfAbsent(key, val -> new ArrayList<>()).add(value);
                } else if (currentToken != JsonToken.FIELD_NAME && currentToken != JsonToken.END_OBJECT) {
                    // If the current token is a complex value (array or object), flatten the value and add it to map
                    // with the corresponding json key.
                    String key = parser.currentName();
                    String value = (new ObjectMapper()).readTree(parser).toString();
                    requestParams.computeIfAbsent(key, val -> new ArrayList<>()).add(value);
                }
            }
        } catch (IOException e) {
            throw new TokenEndpointBadRequestException("Malformed or unsupported request payload", e);
        }
        return requestParams;
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
     *
     * @param consumerKey clientId
     * @throws InvalidApplicationClientException
     */
    public static void validateOauthApplication(String consumerKey) throws InvalidApplicationClientException {

        String appState = EndpointUtil.getOAuth2Service().getOauthApplicationState(consumerKey);

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, consumerKey)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        if (StringUtils.isEmpty(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("A valid OAuth client could not be found for client_id: " + consumerKey);
            }
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null when diagnostic logs are disabled.
                diagnosticLogBuilder.resultMessage("A valid OAuth application could not be found for the given " +
                        "client_id.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new InvalidApplicationClientException("A valid OAuth client could not be found for client_id: " +
                    Encode.forHtml(consumerKey));
        }

        if (isNotActiveState(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("App is not in active state in client ID: " + consumerKey + ". App state is:" + appState);
            }
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null when diagnostic logs are disabled.
                diagnosticLogBuilder.inputParam(OAuthConstants.LogConstants.InputKeys.APP_STATE, appState)
                        .resultMessage("OAuth application is not in active state.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new InvalidApplicationClientException("Oauth application is not in active state");
        }

        if (log.isDebugEnabled()) {
            log.debug("Oauth App validation success for consumer key: " + consumerKey);
        }
        if (diagnosticLogBuilder != null) {
            // diagnosticLogBuilder is null when diagnostic logs are disabled.
            diagnosticLogBuilder.inputParam(OAuthConstants.LogConstants.InputKeys.APP_STATE, appState)
                    .resultMessage("OAuth application is in active state.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private static boolean isNotActiveState(String appState) {

        return !APP_STATE_ACTIVE.equalsIgnoreCase(appState);
    }

    /**
     * This method retrieves the service provider tenant domain using the client ID.
     * However, internally it uses the tenant present in the carbon context.
     *
     * @param clientId Client id of the application.
     * @return Tenant domain of the service provider.
     */
    public static String getSPTenantDomainFromClientId(String clientId) {

        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            return OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while getting oauth app for client Id: " + clientId, e);
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting oauth app for client Id: " + clientId, e);
            }
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
    }

    /**
     * Extract information related to the token request and exception and publish the event to listeners.
     *
     * @param exception Exception occurred.
     * @param request   Token servlet request
     * @param paramMap  Additional parameters.
     */
    public static void triggerOnTokenExceptionListeners(Exception exception, HttpServletRequest request,
                                                        MultivaluedMap<String, String> paramMap) {

        triggerOnTokenExceptionListeners(exception, request, (Map<String, List<String>>) paramMap);
    }

    /**
     * Extract information related to the token request and exception and publish the event to listeners.
     *
     * @param exception Exception occurred.
     * @param request   Token servlet request
     * @param paramMap  Additional parameters.
     */
    public static void triggerOnTokenExceptionListeners(Exception exception, HttpServletRequest request,
                                                        Map<String, List<String>> paramMap) {

        Map<String, Object> params = new HashMap<>();
        Object oauthClientAuthnContextObj = request.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT);
        String clientId;
        if (oauthClientAuthnContextObj instanceof OAuthClientAuthnContext) {
            clientId = ((OAuthClientAuthnContext) oauthClientAuthnContextObj).getClientId();
        } else {
            clientId = NOT_AVAILABLE;
        }
        addStringToMap(PROP_CLIENT_ID, clientId, params);

        if (paramMap != null) {
            String grantType = getFirstParamValue(paramMap, PROP_GRANT_TYPE);
            String scopeString = getFirstParamValue(paramMap, PROP_SCOPE);
            addStringToMap(PROP_GRANT_TYPE, grantType, params);
            addStringToMap(PROP_SCOPE, scopeString, params);
        }

        if (exception != null) {
            params.put(PROP_ERROR_DESCRIPTION, exception.getMessage());
            params.put(PROP_ERROR, getErrorCodeFromException(exception));
        }

        OAuth2Util.triggerOnTokenExceptionListeners(exception, params);
    }

    private static String getFirstParamValue(Map<String, List<String>> paramMap, String paramName) {

        String paramValue = null;
        if (CollectionUtils.isNotEmpty(paramMap.get(paramName))) {
            paramValue = paramMap.get(paramName).get(0);
        }
        return paramValue;
    }

    /**
     * Extract information related to the token request and token validation error and publish the event to listeners.
     *
     * @param oAuthMessage       OAuth message.
     * @param validationResponse token validation response.
     */
    public static void triggerOnRequestValidationFailure(OAuthMessage oAuthMessage,
                                                         OAuth2ClientValidationResponseDTO validationResponse) {

        Map<String, Object> params = new HashMap<>();

        String clientId = oAuthMessage.getRequest().getParameter(PROP_CLIENT_ID);
        String responseType = oAuthMessage.getRequest().getParameter(PROP_RESPONSE_TYPE);
        String scope = oAuthMessage.getRequest().getParameter(PROP_SCOPE);

        addStringToMap(PROP_CLIENT_ID, clientId, params);
        addStringToMap(PROP_RESPONSE_TYPE, responseType, params);
        addStringToMap(PROP_SCOPE, scope, params);

        params.put(PROP_ERROR, validationResponse.getErrorCode());
        String errorDesc;
        errorDesc = validationResponse.getErrorMsg();
        if (OAuth2ErrorCodes.INVALID_CALLBACK.equals(validationResponse.getErrorCode())) {

            errorDesc = validationResponse.getErrorMsg() + " Callback URL: " +
                    oAuthMessage.getRequest().getParameter(PROP_REDIRECT_URI);
        }
        params.put(PROP_ERROR_DESCRIPTION, errorDesc);
        OAuth2Util.triggerOnTokenExceptionListeners(null, params);
    }

    /**
     * Extract information related to the authorization request and authorization request error and publish the event
     * to listeners.
     *
     * @param exception
     * @param request
     */
    public static void triggerOnAuthzRequestException(Exception exception, HttpServletRequest request) {

        Map<String, Object> params = new HashMap<>();

        String clientId = request.getParameter(PROP_CLIENT_ID);
        String scope = request.getParameter(PROP_SCOPE);
        String responseType = request.getParameter(PROP_RESPONSE_TYPE);

        addStringToMap(PROP_CLIENT_ID, clientId, params);
        addStringToMap(PROP_SCOPE, scope, params);
        addStringToMap(PROP_RESPONSE_TYPE, responseType, params);

        if (exception != null) {
            params.put(PROP_ERROR_DESCRIPTION, exception.getMessage());
            params.put(PROP_ERROR, getErrorCodeFromException(exception));
        }

        OAuth2Util.triggerOnTokenExceptionListeners(exception, params);
    }

    private static String getErrorCodeFromException(Exception exception) {

        if (exception instanceof TokenEndpointBadRequestException) {
            return OAuth2ErrorCodes.INVALID_REQUEST;
        } else if (exception instanceof InvalidApplicationClientException) {
            return OAuth2ErrorCodes.INVALID_CLIENT;
        } else if (exception instanceof OAuthSystemException) {
            return OAuth2ErrorCodes.SERVER_ERROR;
        } else if (exception instanceof InvalidRequestException) {
            return OAuth2ErrorCodes.INVALID_REQUEST;
        } else if (exception instanceof BadRequestException) {
            return OAuth2ErrorCodes.INVALID_REQUEST;
        } else if (exception instanceof OAuthProblemException) {
            return OAuth2ErrorCodes.INVALID_REQUEST;
        } else {
            return UNKNOWN_ERROR;
        }
    }

    private static void addStringToMap(String name, String value, Map<String, Object> map) {

        if (isNotBlank(name) && isNotBlank(value)) {
            map.put(name, value);
        }
    }

    public static CibaAuthServiceImpl getCibaAuthService() {

        return cibaAuthService;
    }

    public static void setCibaAuthService(CibaAuthServiceImpl cibaAuthService) {

        EndpointUtil.cibaAuthService = cibaAuthService;
    }

    /**
     * Get instance of parAuthService.
     *
     * @return parAuthService
     */
    public static ParAuthService getParAuthService() {

        return parAuthService;
    }

    /**
     * Set instance of parAuthService.
     *
     * @param parAuthService parAuthService
     */
    public static void setParAuthService(ParAuthService parAuthService) {

        EndpointUtil.parAuthService = parAuthService;
    }

    /**
     * This method retrieve the state to append to the error page URL.
     * If the state is available in OAuth2Parameters it will retrieve state from OAuth2Parameters.
     * If the state is not available in OAuth2Parameters, then the state will be retrieved from request object.
     * If the state is not available in OAuth2Parameters and request object then state will be retrieved
     * from query params.
     *
     * @param request Http servlet request.
     * @param oAuth2Parameters OAuth2 parameters.
     * @return state
     */
    public static String retrieveStateForErrorURL(HttpServletRequest request, OAuth2Parameters oAuth2Parameters) {

        String state = null;

        if (request.getParameter(OAuthConstants.OAuth20Params.REQUEST) != null) {
            String stateInsideRequestObj = getStateFromRequestObject(request, oAuth2Parameters);
            if (StringUtils.isNotBlank(stateInsideRequestObj)) {
                state = stateInsideRequestObj;
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved state value " + state + " from request object.");
                }
            }
        }

        if (StringUtils.isBlank(state) && oAuth2Parameters != null && oAuth2Parameters.getState() != null) {
            state = oAuth2Parameters.getState();
            if (log.isDebugEnabled()) {
                log.debug("Retrieved state value " + state + " from OAuth2Parameters.");
            }
        }
        if (StringUtils.isEmpty(state)) {
            state = request.getParameter(OAuthConstants.OAuth20Params.STATE);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved state value " + state + " from request query params.");
            }
        }
        return state;
    }

    private static String getStateFromRequestObject(HttpServletRequest request, OAuth2Parameters oAuth2Parameters) {

        try {
            RequestObjectValidator requestObjectValidator = OAuthServerConfiguration.getInstance()
                    .getRequestObjectValidator();
            RequestObjectBuilder requestObjectBuilder = OAuthServerConfiguration.getInstance()
                    .getRequestObjectBuilders().get(OIDCRequestObjectUtil.REQUEST_PARAM_VALUE_BUILDER);
            RequestObject requestObject =
                    requestObjectBuilder.buildRequestObject(request.getParameter(OAuthConstants.OAuth20Params.REQUEST),
                            oAuth2Parameters);
            if (StringUtils.isBlank(oAuth2Parameters.getClientId())) {
                // Set client id and tenant domain required for signature validation if not already set.
                String clientId = request.getParameter(PROP_CLIENT_ID);
                oAuth2Parameters.setClientId(clientId);
                oAuth2Parameters.setTenantDomain(getSPTenantDomainFromClientId(clientId));
            }
            // Validate request object signature to ensure request object is not tampered.
            OIDCRequestObjectUtil.validateRequestObjectSignature(oAuth2Parameters, requestObject,
                    requestObjectValidator);
            return requestObject.getClaimValue(OAuthConstants.OAuth20Params.STATE);
        } catch (RequestObjectException e) {
            /* If request object signature validation fails, logs and return null from this method and the state value
            will be overridden from oauth2 parameters or request parameters if present inside the
            retrieveStateForErrorURL method. */
            log.debug("Error while retrieving state from request object.", e);
        }
        return null;
    }

    /**
     * Return updated redirect URL.
     *
     * @param request       HttpServletRequest
     * @param redirectUri   Redirect Uri
     * @param errorCode     Error Code
     * @param errorMessage  Message of the error
     * @param state         State from the request
     * @param appName       Application Name
     * @return Updated Redirect URL
     */
    private static String getUpdatedRedirectURL(HttpServletRequest request, String redirectUri, String errorCode,
                                                String errorMessage, String state, String appName) {

        String updatedRedirectUri = redirectUri;
        try {
            OAuthProblemException ex = OAuthProblemException.error(errorCode).description(errorMessage);
            if (OAuth2Util.isImplicitResponseType(request.getParameter(OAuthConstants.OAuth20Params.RESPONSE_TYPE))
                    || OAuth2Util.isHybridResponseType(request.getParameter(OAuthConstants.OAuth20Params.
                    RESPONSE_TYPE))) {
                updatedRedirectUri = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
                        .error(ex).location(redirectUri).setState(state).setParam(OAuth.OAUTH_ACCESS_TOKEN, null)
                        .buildQueryMessage().getLocationUri();
            } else {
                updatedRedirectUri = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
                        .error(ex).location(redirectUri).setState(state).buildQueryMessage().getLocationUri();
            }

        } catch (OAuthSystemException e) {
            log.error("Server error occurred while building error redirect url for application: " + appName, e);
        }
        return updatedRedirectUri;
    }

    /**
     * Method to retrieve the <AllowAdditionalParamsFromErrorUrl> config from the OAuth Configuration.
     * @return Retrieved config (true or false)
     */
    private static boolean isAllowAdditionalParamsFromErrorUrlEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ALLOW_ADDITIONAL_PARAMS_FROM_ERROR_URL));
    }

    /**
     * Method to check whether the error is redirected to the common error page.
     *
     * @param params       OAuth2Parameters
     * @param redirectURL  Constructed redirect URL
     * @return Whether the error is redirected to the common error page (true or false)
     */
    private static boolean isRedirectToCommonErrorPage(OAuth2Parameters params, String redirectURL) {

        // Verifying whether the error is redirecting to the redirect url by checking whether the constructed redirect
        // url contains the redirect url from the request if the params from request is not null and params from
        // request contains redirect url.
        return !(params != null && StringUtils.isNotBlank(params.getRedirectURI()) &&
                StringUtils.startsWith(redirectURL, params.getRedirectURI()));
    }

    /**
     * Used to get the issuer identifier url for a given service provider.
     *
     * @param clientId Client Id.
     * @return Issuer identifier url.
     * @throws IdentityProviderManagementException IdentityProviderManagementException.
     */
    public static String getIssuerIdentifierFromClientId(String clientId) throws IdentityProviderManagementException {

        IdentityProvider identityProvider = IdentityProviderManager.getInstance()
                .getResidentIdP(getSPTenantDomainFromClientId(clientId));
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        return IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(), IDP_ENTITY_ID)
                .getValue();
    }

    /**
     * Used to check whether the external consent page is enabled in service provider.
     *
     * @param serviceProvider Service Provider.
     * @return True if the external consent page is enabled.
     */
    public static boolean isExternalConsentPageEnabledForSP(ServiceProvider serviceProvider) {

        boolean isEnabled = false;
        if (serviceProvider == null) {
            return isEnabled;
        }
        LocalAndOutboundAuthenticationConfig config = serviceProvider.getLocalAndOutBoundAuthenticationConfig();

        if (config != null) {
            isEnabled = config.isUseExternalConsentPage();
        }
        if (log.isDebugEnabled()) {
            log.debug("External consent page: " + isEnabled + " for application: " +
                    serviceProvider.getApplicationName() + " with id: " + serviceProvider.getApplicationID());
        }
        return isEnabled;
    }

    public static boolean isConsentPageRedirectParamsAllowed() {
        return FileBasedConfigurationBuilder.getInstance().isConsentPageRedirectParamsAllowed();
    }

    /**
     * Returns an instance of OAuthAuthzRequest. If the configured classname is invalid the default implementation
     * will be returned.
     *
     * @param request http servlet request.
     * @return instance of OAuthAuthzRequest.
     * @throws OAuthProblemException thrown when initializing the OAuthAuthzRequestClass instance.
     * @throws OAuthSystemException  thrown when initializing the OAuthAuthzRequestClass instance.
     */
    public static OAuthAuthzRequest getOAuthAuthzRequest(HttpServletRequest request)
            throws OAuthProblemException, OAuthSystemException {

        if (isDefaultOAuthAuthzRequestClassConfigured()) {
            return new CarbonOAuthAuthzRequest(request);
        }
        try {
            Class<? extends OAuthAuthzRequest> clazz = getOAuthAuthzRequestClass();
            // Validations will be performed when initializing the class instance.
            Constructor<?> constructor = clazz.getConstructor(HttpServletRequest.class);
            return (OAuthAuthzRequest) constructor.newInstance(request);
        } catch (InvocationTargetException e) {
            // Handle OAuthProblemException & OAuthSystemException thrown from extended class.
            if (e.getTargetException() instanceof OAuthProblemException) {
                throw (OAuthProblemException) e.getTargetException();
            } else if (e.getTargetException() instanceof OAuthSystemException) {
                throw (OAuthSystemException) e.getTargetException();
            } else {
                log.warn("Failed to initiate OAuthAuthzRequest from identity.xml. ");
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException |
                 NoSuchMethodException e) {
            log.warn("Failed to initiate OAuthAuthzRequest from identity.xml. ");
        }
        log.debug("Initiating the default OAuthAuthzRequest implementation");
        return new CarbonOAuthAuthzRequest(request);
    }

    /**
     * Method to check whether the configured OAuthAuthzRequestImplementation is the default implementation.
     *
     * @return boolean whether the default class name is configured.
     */
    private static boolean isDefaultOAuthAuthzRequestClassConfigured() {

        String oauthAuthzRequestClassName = OAuthServerConfiguration.getInstance().getOAuthAuthzRequestClassName();
        return OAuthServerConfiguration.DEFAULT_OAUTH_AUTHZ_REQUEST_CLASSNAME.equals(oauthAuthzRequestClassName);
    }

    /**
     * Load OAuthAuthzRequest class.
     *
     * @return OAuthAuthzRequest Class.
     * @throws ClassNotFoundException when configured class name is invalid.
     */
    private static Class<? extends OAuthAuthzRequest> getOAuthAuthzRequestClass() throws ClassNotFoundException {

        if (oAuthAuthzRequestClass == null) {

            String oauthAuthzRequestClassName =
                    OAuthServerConfiguration.getInstance().getOAuthAuthzRequestClassName();
            oAuthAuthzRequestClass = (Class<? extends OAuthAuthzRequest>) Thread.currentThread()
                    .getContextClassLoader().loadClass(oauthAuthzRequestClassName);
        }
        return oAuthAuthzRequestClass;
    }

    /**
     * Validate the response mode against the response type as per FAPI spec.
     * shall require;
     * 1. the response_type value code id_token, or
     * 2. the response_type value code in conjunction with the response_mode value jwt;
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server">5.2.2-2.2</a>
     *
     * @param responseType response mode
     * @param responseMode response type
     * @throws OAuthProblemException when response mode is not valid
     */
    public static void validateFAPIAllowedResponseTypeAndMode(String responseType, String responseMode)
            throws OAuthProblemException {

        if (!(CODE_IDTOKEN.equals(responseType) || (CODE.equals(responseType) && JWT.equals(responseMode)))) {
            throw OAuthProblemException.error(OAuth2ErrorCodes.INVALID_REQUEST)
                    .description("Invalid response mode provided.");
        }
    }

    /**
     * Cast HttpServletResponse and return as HttpServletResponseWrapper .
     *
     * @return HttpServletResponseWrapper Class.
     */
    public static HttpServletResponseWrapper getHttpServletResponseWrapper (HttpServletResponse response) {

        return (HttpServletResponseWrapper) response;
    }
}
