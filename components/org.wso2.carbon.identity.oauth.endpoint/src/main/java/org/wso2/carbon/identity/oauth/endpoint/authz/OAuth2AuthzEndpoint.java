/*
 * Copyright (c) 2013-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.authz;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsLogger;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.ClaimMetaData;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.ConsentClaimsData;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.exception.SSOConsentServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedToken;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.client.attestation.filter.ClientAttestationProxy;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.UserAgent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnHandler;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnUtils;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.SuccessCompleteAuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.exception.ConsentHandlingFailedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;
import org.wso2.carbon.identity.oauth.extension.utils.EngineUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2UnauthorizedScopeException;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.FederatedTokenDO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeaderHandler;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.OIDCRequestObjectUtil;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
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

import static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.MANDATORY_CLAIMS;
import static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.REQUESTED_CLAIMS;
import static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.USER_CLAIMS_CONSENT_ONLY;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.REQUEST_PARAM_SP;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.CLIENT_ATTESTATION_CONTEXT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.InputKeys.RESPONSE_TYPE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REDIRECT_URI;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.USERINFO;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.INITIAL_REQUEST;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.PASSTHROUGH_TO_COMMONAUTH;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.USER_CONSENT_RESPONSE;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getErrorPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getLoginPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuthAuthzRequest;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuthServerConfiguration;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getSSOConsentService;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.retrieveStateForErrorURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.CLIENT_REQUEST;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.ACCESS_TOKEN_JS_OBJECT;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.DYNAMIC_TOKEN_DATA_FUNCTION;
import static org.wso2.carbon.identity.openidconnect.model.Constants.AUTH_TIME;
import static org.wso2.carbon.identity.openidconnect.model.Constants.DISPLAY;
import static org.wso2.carbon.identity.openidconnect.model.Constants.ID_TOKEN_HINT;
import static org.wso2.carbon.identity.openidconnect.model.Constants.LOGIN_HINT;
import static org.wso2.carbon.identity.openidconnect.model.Constants.MAX_AGE;
import static org.wso2.carbon.identity.openidconnect.model.Constants.NONCE;
import static org.wso2.carbon.identity.openidconnect.model.Constants.PROMPT;
import static org.wso2.carbon.identity.openidconnect.model.Constants.SCOPE;
import static org.wso2.carbon.identity.openidconnect.model.Constants.SERVICE_PROVIDER_ID;
import static org.wso2.carbon.identity.openidconnect.model.Constants.STATE;

/**
 * Rest implementation of OAuth2 authorize endpoint.
 */
@Path("/authorize")
@InInterceptors(classes = {OAuthClientAuthenticatorProxy.class, ClientAttestationProxy.class})
public class OAuth2AuthzEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2AuthzEndpoint.class);
    private static final String APPROVE = "approve";
    private static final String CONSENT = "consent";
    private static final String AUTHENTICATED_ID_PS = "AuthenticatedIdPs";
    private static final String BEARER = "Bearer";
    private static final String ACR_VALUES = "acr_values";
    private static final String CLAIMS = "claims";
    public static final String COMMA_SEPARATOR = ",";
    public static final String SPACE_SEPARATOR = " ";
    private static final String RESPONSE_MODE_FORM_POST = "form_post";
    private boolean isCacheAvailable = false;
    private static final String RESPONSE_MODE = "response_mode";
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    private static final String CODE_CHALLENGE = "code_challenge";
    private static final String CODE_CHALLENGE_METHOD = "code_challenge_method";

    private static final String formPostRedirectPage = getFormPostRedirectPage();
    private static final String DISPLAY_NAME = "DisplayName";
    private static final String ID_TOKEN = "id_token";
    private static final String ACCESS_CODE = "code";
    private static final String DEFAULT_ERROR_DESCRIPTION = "User denied the consent";
    private static final String DEFAULT_ERROR_MSG_FOR_FAILURE = "Authentication required";
    private static final String COMMONAUTH_COOKIE = "commonAuthId";
    private static final String SET_COOKIE_HEADER = "Set-Cookie";
    private static final String REGEX_PATTERN = "regexp";
    private static final String OIDC_SESSION_ID = "OIDC_SESSION_ID";

    private static final String PARAMETERS = "params";
    private static final String FORM_POST_REDIRECT_URI = "redirectURI";
    private static final String SERVICE_PROVIDER = "serviceProvider";
    private static final String TENANT_DOMAIN = "tenantDomain";
    private static final String USER_TENANT_DOMAIN = "userTenantDomain";
    private static final String AUTHENTICATION_ENDPOINT = "/authenticationendpoint";
    private static final String OAUTH_RESPONSE_JSP_PAGE = "/oauth_response.jsp";

    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    private static OpenIDConnectClaimFilterImpl openIDConnectClaimFilter;

    private static ScopeMetadataService scopeMetadataService;

    private static DeviceAuthService deviceAuthService;
    private static final String AUTH_SERVICE_RESPONSE = "authServiceResponse";
    private static final String IS_API_BASED_AUTH_HANDLED = "isApiBasedAuthHandled";
    private static final ApiAuthnHandler API_AUTHN_HANDLER = new ApiAuthnHandler();

    public static OpenIDConnectClaimFilterImpl getOpenIDConnectClaimFilter() {

        return openIDConnectClaimFilter;
    }

    public static void setOpenIDConnectClaimFilter(OpenIDConnectClaimFilterImpl openIDConnectClaimFilter) {

        OAuth2AuthzEndpoint.openIDConnectClaimFilter = openIDConnectClaimFilter;
    }

    public static ScopeMetadataService getScopeMetadataService() {

        return scopeMetadataService;
    }

    public static void setScopeMetadataService(ScopeMetadataService scopeMetadataService) {

        OAuth2AuthzEndpoint.scopeMetadataService = scopeMetadataService;
    }

    private static Class<? extends OAuthAuthzRequest> oAuthAuthzRequestClass;

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException {

        OAuthMessage oAuthMessage;

        // TODO: 2021-01-22 Check for the flag in request.
        setCommonAuthIdToRequest(request, response);

        // Using a separate try-catch block as this next try block has operations in the final block.
        try {
            request = RequestUtil.buildRequest(request);
            oAuthMessage = buildOAuthMessage(request, response);

        } catch (InvalidRequestParentException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            throw e;
        } catch (IdentityException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return handleIdentityException(request, e);
        }

        // Perform request authentication for API based auth flow.
        if (OAuth2Util.isApiBasedAuthenticationFlow(request)) {
            OAuthClientAuthnContext oAuthClientAuthnContext = getClientAuthnContext(request);
            if (!oAuthClientAuthnContext.isAuthenticated()) {
                return handleAuthFailureResponse(oAuthClientAuthnContext);
            }

            ClientAttestationContext clientAttestationContext = getClientAttestationContext(request);
            if (clientAttestationContext.isAttestationEnabled() && !clientAttestationContext.isAttested()) {
                return handleAttestationFailureResponse(clientAttestationContext);
            }

            if (!OAuth2Util.isApiBasedAuthSupportedGrant(request)) {
                return handleUnsupportedGrantForApiBasedAuth();
            }
        }

        try {
            // Start tenant domain flow if the tenant configuration is not enabled.
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                String tenantDomain = null;
                if (StringUtils.isNotEmpty(oAuthMessage.getClientId())) {
                    tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
                } else if (oAuthMessage.getSessionDataCacheEntry() != null) {
                    OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
                    tenantDomain = oauth2Params.getTenantDomain();
                }
                FrameworkUtils.startTenantFlow(tenantDomain);
            }

            Response oauthResponse;
            if (isPassthroughToFramework(oAuthMessage)) {
                oauthResponse = handleAuthFlowThroughFramework(oAuthMessage);
            } else if (isInitialRequestFromClient(oAuthMessage)) {
                oauthResponse = handleInitialAuthorizationRequest(oAuthMessage);
            } else if (isAuthenticationResponseFromFramework(oAuthMessage)) {
                oauthResponse = handleAuthenticationResponse(oAuthMessage);
            } else if (isConsentResponseFromUser(oAuthMessage)) {
                oauthResponse = handleResponseFromConsent(oAuthMessage);
            } else {
                oauthResponse = handleInvalidRequest(oAuthMessage);
            }

            if (isApiBasedAuthenticationFlow(oAuthMessage)) {
                oauthResponse = handleApiBasedAuthenticationResponse(oAuthMessage, oauthResponse);
            }

            return oauthResponse;
        } catch (OAuthProblemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return handleOAuthProblemException(oAuthMessage, e);
        } catch (OAuthSystemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return handleOAuthSystemException(oAuthMessage, e);
        } finally {
            handleCachePersistence(oAuthMessage);
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    /**
     * Add the federated tokens comes with the authentication result to the session data cache.
     *
     * @param oAuthMessage         The OAuthMessage with the session data cache entry.
     * @param authenticationResult The authentication result of authorization call.
     */
    private void addFederatedTokensToSessionCache(OAuthMessage oAuthMessage,
                                                  AuthenticationResult authenticationResult) {

        if (!(authenticationResult.getProperty(FrameworkConstants.FEDERATED_TOKENS) instanceof List)) {
            return;
        }
        List<FederatedToken> federatedTokens =
                (List<FederatedToken>) authenticationResult.getProperty(FrameworkConstants.FEDERATED_TOKENS);

        SessionDataCacheEntry sessionDataCacheEntry = oAuthMessage.getSessionDataCacheEntry();
        if (sessionDataCacheEntry == null || CollectionUtils.isEmpty(federatedTokens)) {
            return;
        }
        sessionDataCacheEntry.setFederatedTokens(getFederatedTokenDO(federatedTokens));
        if (log.isDebugEnabled() && authenticationResult.getSubject() != null) {
            log.debug("Added the federated tokens to the session data cache. Session context identifier: " +
                    sessionDataCacheEntry.getSessionContextIdentifier() + " for the user: " +
                    authenticationResult.getSubject().getLoggableMaskedUserId());
        }
    }

    /**
     * Add mapped remote claims to session cache.
     *
     * @param oAuthMessage         The OAuthMessage with the session data cache entry.
     * @param authenticationResult The authentication result of authorization call.
     */
    private void addMappedRemoteClaimsToSessionCache(OAuthMessage oAuthMessage,
                                                  AuthenticationResult authenticationResult) {

        Optional<Map<String, String>> mappedRemoteClaims = authenticationResult.getMappedRemoteClaims();
        if (!mappedRemoteClaims.isPresent()) {
            return;
        }

        SessionDataCacheEntry sessionDataCacheEntry = oAuthMessage.getSessionDataCacheEntry();
        if (sessionDataCacheEntry == null || mappedRemoteClaims.get().isEmpty()) {
            return;
        }
        Map<ClaimMapping, String> mappedRemoteClaimsMap = new HashMap<>();
        mappedRemoteClaims.get().forEach(
                (key, value) -> mappedRemoteClaimsMap.put(ClaimMapping.build(key, key, null,
                        false), value));
        sessionDataCacheEntry.setMappedRemoteClaims(mappedRemoteClaimsMap);
        if (log.isDebugEnabled() && authenticationResult.getSubject() != null) {
            log.debug("Added the mapped remote claims to the session data cache. " +
                    "Session context identifier: " + sessionDataCacheEntry.getSessionContextIdentifier()
                    + " for the user: " + authenticationResult.getSubject().getLoggableMaskedUserId());
        }
    }

    /**
     * This method creates a list of FederatedTokenDO objects from the list of FederatedToken objects.
     *
     * @param federatedTokens List of FederatedToken objects to be transformed as a list of FederatedTokenDO.
     * @return List of FederatedTokenDO objects.
     */
    private List<FederatedTokenDO> getFederatedTokenDO(List<FederatedToken> federatedTokens) {

        if (CollectionUtils.isEmpty(federatedTokens)) {
            return null;
        }

        List<FederatedTokenDO>  federatedTokenDOs = federatedTokens.stream().map(federatedToken -> {
            FederatedTokenDO federatedTokenDO =
                    new FederatedTokenDO(federatedToken.getIdp(), federatedToken.getAccessToken());
            federatedTokenDO.setRefreshToken(federatedToken.getRefreshToken());
            federatedTokenDO.setScope(federatedToken.getScope());
            federatedTokenDO.setTokenValidityPeriod(federatedToken.getTokenValidityPeriod());
            return federatedTokenDO;
        }).collect(Collectors.toList());

        return federatedTokenDOs;
    }

    private void setCommonAuthIdToRequest(HttpServletRequest request, HttpServletResponse response) {

        // Issue https://github.com/wso2/product-is/issues/11065 needs to addressed.
        response.getHeaders(SET_COOKIE_HEADER).stream()
                .filter(value -> value.contains(COMMONAUTH_COOKIE))
                // TODO: 2021-01-22 Refactor this logic - Check kernel Cookie.
                .map(cookieValue -> cookieValue.split(COMMONAUTH_COOKIE + "=")[1])
                .map(cookieValue -> cookieValue.split(";")[0])
                .findAny().ifPresent(s -> request.setAttribute(COMMONAUTH_COOKIE, s));
    }

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorizePost(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                  MultivaluedMap paramMap)
            throws URISyntaxException, InvalidRequestParentException {

        // Validate repeated parameters
        if (!validateParams(request, paramMap)) {
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).location(new URI(getErrorPageURL(request,
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes
                            .INVALID_AUTHORIZATION_REQUEST, "Invalid authorization request with repeated parameters",
                    null)))
                    .build();
        }
        HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
        return authorize(httpRequest, response);
    }

    private Response handleInvalidRequest(OAuthMessage oAuthMessage) throws URISyntaxException {

        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request");
        }

        OAuth2Parameters oAuth2Parameters = getOAuth2ParamsFromOAuthMessage(oAuthMessage);
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(getErrorPageURL
                (oAuthMessage.getRequest(), OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes
                        .INVALID_AUTHORIZATION_REQUEST, "Invalid authorization request", null,
                oAuth2Parameters))).build();
    }

    private void handleCachePersistence(OAuthMessage oAuthMessage) {

        AuthorizationGrantCacheEntry entry = oAuthMessage.getAuthorizationGrantCacheEntry();
        if (entry != null) {
            AuthorizationGrantCache.getInstance().addToCacheByCode(
                    new AuthorizationGrantCacheKey(entry.getAuthorizationCode()), entry);
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

    private Response handleOAuthSystemException(OAuthMessage oAuthMessage, OAuthSystemException e)
            throws URISyntaxException {

        OAuth2Parameters params = null;
        if (oAuthMessage.getSessionDataCacheEntry() != null) {
            params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        }
        log.error("Server error occurred while performing authorization", e);
        OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.SERVER_ERROR,
                "Server error occurred while performing authorization");
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                EndpointUtil.getErrorRedirectURL(oAuthMessage.getRequest(), ex, params))).build();
    }

    private Response handleIdentityException(HttpServletRequest request, IdentityException e)
            throws URISyntaxException {

        if (OAuth2ErrorCodes.SERVER_ERROR.equals(e.getErrorCode())) {
            log.error("Server error occurred while performing authorization", e);
            OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Server error occurred while performing authorization");
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                    EndpointUtil.getErrorRedirectURL(request, ex, null))).build();
        }
        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request", e);
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(EndpointUtil.getErrorPageURL(request,
                e.getErrorCode(), OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST,
                e.getMessage(), null))).build();
    }

    private Response handleOAuthProblemException(OAuthMessage oAuthMessage, OAuthProblemException e) throws
            URISyntaxException {

        if (log.isDebugEnabled()) {
            log.debug(e.getError(), e);
        }

        OAuth2Parameters oAuth2Parameters = getOAuth2ParamsFromOAuthMessage(oAuthMessage);

        if (StringUtils.equals(oAuthMessage.getRequest().getParameter(RESPONSE_MODE), RESPONSE_MODE_FORM_POST)) {
            e.state(retrieveStateForErrorURL(oAuthMessage.getRequest(), oAuth2Parameters));
            if (OAuthServerConfiguration.getInstance().isOAuthResponseJspPageAvailable()) {
                String params = buildErrorParams(e);
                String redirectURI = oAuthMessage.getRequest().getParameter(REDIRECT_URI);
                return forwardToOauthResponseJSP(oAuthMessage, params, redirectURI);
            } else {
                return Response.ok(createErrorFormPage(oAuthMessage.getRequest().getParameter(REDIRECT_URI), e))
                        .build();
            }
        }

        String errorCode = StringUtils.isNotBlank(e.getError()) ? e.getError() : OAuth2ErrorCodes.INVALID_REQUEST;
        String errorDescription = StringUtils.isNotBlank(e.getDescription()) ? e.getDescription() : e.getMessage();
        String state = e.getState();

        if (StringUtils.isBlank(oAuth2Parameters.getState()) && StringUtils.isNotBlank(state)) {
            oAuth2Parameters.setState(state);
        }
        String errorPageURL = getErrorPageURL(oAuthMessage.getRequest(), errorCode,
                OAuth2ErrorCodes.OAuth2SubErrorCodes.UNEXPECTED_SERVER_ERROR, errorDescription, null,
                oAuth2Parameters);
        if (OAuthServerConfiguration.getInstance().isRedirectToRequestedRedirectUriEnabled()) {
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(errorPageURL)).build();

        } else {
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
    }

    private static String getFormPostRedirectPage() {

        java.nio.file.Path path = Paths.get(CarbonUtils.getCarbonHome(), "repository", "resources",
                "identity", "pages", "oauth_response.html");
        if (Files.exists(path)) {
            try {
                return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to find OAuth From post response page in : " + path);
                }
            }
        }
        return null;
    }

    /**
     * This method creates and returns AuthorizationResponseDTO instance.
     * @param oauth2Params Oauth2 params
     * @return AuthorizationResponseDTO DTO
     */
    private AuthorizationResponseDTO getAuthResponseDTO(OAuth2Parameters oauth2Params) {

        AuthorizationResponseDTO authorizationResponseDTO = new AuthorizationResponseDTO();

        authorizationResponseDTO.setClientId(oauth2Params.getClientId());
        authorizationResponseDTO.setSigningTenantDomain(oauth2Params.getTenantDomain());
        authorizationResponseDTO.setRedirectUrl(oauth2Params.getRedirectURI());
        authorizationResponseDTO.setState(oauth2Params.getState());
        authorizationResponseDTO.setResponseMode(oauth2Params.getResponseMode());
        authorizationResponseDTO.setResponseType(oauth2Params.getResponseType());
        authorizationResponseDTO.setMtlsRequest(oauth2Params.isMtlsRequest());

        return authorizationResponseDTO;
    }

    /**
     * This returns the ResponseModeProvider that can handle a given authorize response.
     * @param authorizationResponseDTO AuthorizationResponseDTO instance
     * @return ResponseModeProvider
     */
    private ResponseModeProvider getResponseModeProvider(AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthProblemException {

        validateResponseModeWithResponseType(authorizationResponseDTO);
        Map<String, ResponseModeProvider> responseModeProviders =
                OAuth2ServiceComponentHolder.getResponseModeProviders();
        for (Map.Entry<String, ResponseModeProvider> entry : responseModeProviders.entrySet()) {
            ResponseModeProvider responseModeProvider = entry.getValue();
            if (responseModeProvider.canHandle(authorizationResponseDTO)) {
                return responseModeProvider;
            }
        }
        return OAuth2ServiceComponentHolder.getResponseModeProvider(OAuthConstants.ResponseModes.DEFAULT);
    }

    private void validateResponseModeWithResponseType(AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthProblemException {

        String responseType = authorizationResponseDTO.getResponseType();
        String responseMode = authorizationResponseDTO.getResponseMode();

        // Response mode query.jwt should not be used in conjunction with the response types token and/or id_token.
        if (hasIDTokenOrTokenInResponseType(responseType) &&
                OAuthConstants.ResponseModes.QUERY_JWT.equals(responseMode)) {

            throw OAuthProblemException.error(OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.INVALID_RESPONSE_TYPE_FOR_QUERY_JWT);
        }
    }

    /**
     * This returns the QueryResponseModeProvider.
     * @return ResponseModeProvider: QueryResponseModeProvider
     */
    private ResponseModeProvider getQueryResponseModeProvider() {

        return OAuth2ServiceComponentHolder.getResponseModeProvider(OAuthConstants.ResponseModes.QUERY);
    }

    /**
     * Method to check a successful form_post flow
     * @param oAuthMessage OAuthMessage instance
     * @param authorizationResponseDTO AuthorizationResponseDTO instance
     * @return true if response mode is form_post without errors
     */
    private boolean isFormPostWithoutErrors (OAuthMessage oAuthMessage, AuthorizationResponseDTO
            authorizationResponseDTO) {

        return isFormPostResponseMode(oAuthMessage, authorizationResponseDTO.getRedirectUrl()) ||
                (!authorizationResponseDTO.isError() && isFormPostResponseMode(oAuthMessage,
                        authorizationResponseDTO.getSuccessResponseDTO().getFormPostBody()));
    }

    /**
     * Method to check form_post flow with error
     * @param authorizationResponseDTO AuthorizationResponseDTO instance
     * @param responseModeProvider ResponseModeProvider instance
     * @return true if response mode is form_post with errors
     */
    private boolean isFormPostWithErrors(AuthorizationResponseDTO authorizationResponseDTO,
                                         ResponseModeProvider responseModeProvider) {
        return authorizationResponseDTO.isError() &&
                (ResponseModeProvider.AuthResponseType.POST_RESPONSE.equals
                        (responseModeProvider.getAuthResponseType()))
                && !isJSON(authorizationResponseDTO.getRedirectUrl());
    }

    private Response handleResponseFromConsent(OAuthMessage oAuthMessage) throws OAuthSystemException,
            URISyntaxException, ConsentHandlingFailedException, OAuthProblemException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.RECEIVE_CONSENT_RESPONSE);
            if (oAuthMessage.getRequest() != null && MapUtils.isNotEmpty(oAuthMessage.getRequest().getParameterMap())) {
                oAuthMessage.getRequest().getParameterMap().forEach((key, value) -> {
                    if (ArrayUtils.isNotEmpty(value)) {
                        diagnosticLogBuilder.inputParam(key, Arrays.asList(value));
                    }
                });
            }
            diagnosticLogBuilder.resultMessage("Successfully received consent response.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        updateAuthTimeInSessionDataCacheEntry(oAuthMessage);
        addSessionDataKeyToSessionDataCacheEntry(oAuthMessage);

        String consent = getConsentFromRequest(oAuthMessage);

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        AuthorizationResponseDTO authorizationResponseDTO = getAuthResponseDTO(oauth2Params);
        ResponseModeProvider responseModeProvider = getResponseModeProvider(authorizationResponseDTO);
        authorizationResponseDTO.setFormPostRedirectPage(formPostRedirectPage);

        if (consent != null) {
            if (OAuthConstants.Consent.DENY.equals(consent)) {
                handleDeniedConsent(oAuthMessage, authorizationResponseDTO, responseModeProvider);
                if (ResponseModeProvider.AuthResponseType.REDIRECTION.equals
                        (responseModeProvider.getAuthResponseType())) {
                    return Response.status(authorizationResponseDTO.getResponseCode())
                            .location(new URI(responseModeProvider.getAuthResponseRedirectUrl
                                    (authorizationResponseDTO))).build();
                } else {
                    return Response.ok(responseModeProvider.getAuthResponseBuilderEntity(authorizationResponseDTO))
                            .build();
                }
            }

            /*
                Get the user consented claims from the consent response and create a consent receipt.
            */
            handlePostConsent(oAuthMessage);

            OIDCSessionState sessionState = new OIDCSessionState();

            /*
                Update authorization DTO and setFormPostBody in authorization DTO if form post.
             */
            handleUserConsent(oAuthMessage, consent, sessionState, oauth2Params, authorizationResponseDTO);

            if (isFormPostWithoutErrors(oAuthMessage, authorizationResponseDTO)) {
                handleFormPostResponseMode(oAuthMessage, sessionState, authorizationResponseDTO, null);
                if (authorizationResponseDTO.getIsForwardToOAuthResponseJSP()) {
                    return Response.ok().build();
                }
                return Response.ok(responseModeProvider.getAuthResponseBuilderEntity(authorizationResponseDTO)).build();

            } else {
                if (isFormPostWithErrors(authorizationResponseDTO, responseModeProvider)) {

                    /* Error message is added as query parameters to the redirect URL if response mode is form post
                     * or form post jwt but redirect url is not a json object.
                     */
                    return Response.status(authorizationResponseDTO.getResponseCode())
                            .location(new URI((getQueryResponseModeProvider())
                                    .getAuthResponseRedirectUrl(authorizationResponseDTO))).build();
                }
                // Update authorization DTO.
                manageOIDCSessionState(oAuthMessage, sessionState, authorizationResponseDTO);
            }
        } else {
            // Empty consent error message is added as query parameters to the redirect URL.
            responseModeProvider = getQueryResponseModeProvider();
            handleEmptyConsent(authorizationResponseDTO);
        }
        return Response.status(authorizationResponseDTO.getResponseCode())
                .location(new URI(responseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO))).build();
    }

    private boolean isConsentHandlingFromFrameworkSkipped(OAuth2Parameters oAuth2Parameters)
            throws OAuthSystemException {

        ServiceProvider sp = getServiceProvider(oAuth2Parameters.getClientId());
        boolean consentMgtDisabled = isConsentMgtDisabled(sp);
        if (consentMgtDisabled) {
            if (log.isDebugEnabled()) {
                String clientId = oAuth2Parameters.getClientId();
                String spTenantDomain = oAuth2Parameters.getTenantDomain();
                log.debug("Consent Management disabled for client_id: " + clientId + " of tenantDomain: "
                        + spTenantDomain + ". Therefore skipping consent handling for user.");
            }
        }

        return isNotOIDCRequest(oAuth2Parameters) || consentMgtDisabled;
    }

    private boolean isNotOIDCRequest(OAuth2Parameters oAuth2Parameters) {

        return !OAuth2Util.isOIDCAuthzRequest(oAuth2Parameters.getScopes());
    }

    private boolean isConsentMgtDisabled(ServiceProvider sp) {

        return !getSSOConsentService().isSSOConsentManagementEnabled(sp);
    }

    private void handlePostConsent(OAuthMessage oAuthMessage) throws ConsentHandlingFailedException {

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        String tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oauth2Params.getClientId());
        setSPAttributeToRequest(oAuthMessage.getRequest(), oauth2Params.getApplicationName(), tenantDomain);
        String spTenantDomain = oauth2Params.getTenantDomain();
        AuthenticatedUser loggedInUser = getLoggedInUser(oAuthMessage);
        String clientId = oauth2Params.getClientId();
        ServiceProvider serviceProvider;

        if (log.isDebugEnabled()) {
            log.debug("Initiating post user consent handling for user: " + loggedInUser.toFullQualifiedUsername()
                    + " for client_id: " + clientId + " of tenantDomain: " + spTenantDomain);
        }
        try {
            if (isConsentHandlingFromFrameworkSkipped(oauth2Params)) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Consent handling from framework skipped for client_id: " + clientId + " of tenantDomain: "
                                    + spTenantDomain + " for user: " + loggedInUser.toFullQualifiedUsername() + ". " +
                                    "Therefore handling post consent is not applicable.");
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, "handle-consent")
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                            .configParam("skip consent", "true")
                            .resultMessage("Consent is disabled for the OAuth client.")
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
                }
                return;
            }

            List<Integer> approvedClaimIds = getUserConsentClaimIds(oAuthMessage);
            serviceProvider = getServiceProvider(clientId);
            /*
                With the current implementation of the SSOConsentService we need to send back the original
                ConsentClaimsData object we got during pre consent stage. Currently we are repeating the API call
                during post consent handling to get the original ConsentClaimsData object (Assuming there is no
                change in SP during pre-consent and post-consent).

                The API on the SSO Consent Service will be improved to avoid having to send the original
                ConsentClaimsData object.
             */
            ConsentClaimsData value = getConsentRequiredClaims(loggedInUser, serviceProvider, oauth2Params);
            /*
                It is needed to pitch the consent required claims with the OIDC claims. otherwise the consent of the
                the claims which are not in the OIDC claims will be saved as consent denied.
            */
            if (value != null) {
                // Remove the claims which dont have values given by the user.
                value.setRequestedClaims(removeConsentRequestedNullUserAttributes(value.getRequestedClaims(),
                        loggedInUser.getUserAttributes(), spTenantDomain));
                List<ClaimMetaData> requestedOidcClaimsList =
                        getRequestedOidcClaimsList(value, oauth2Params, spTenantDomain);
                value.setRequestedClaims(requestedOidcClaimsList);
            }

            // Call framework and create the consent receipt.
            if (log.isDebugEnabled()) {
                log.debug("Creating user consent receipt for user: " + loggedInUser.toFullQualifiedUsername() +
                        " for client_id: " + clientId + " of tenantDomain: " + spTenantDomain);
            }

            Map<String, Object> params;
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.HAND_OVER_TO_CONSENT_SERVICE)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .inputParam(OAuthConstants.LogConstants.InputKeys.PROMPT, oauth2Params.getPrompt())
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            }
            if (hasPromptContainsConsent(oauth2Params)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    diagnosticLogBuilder.resultMessage("Prompt for consent is enabled. Overriding the existing " +
                            "consent and handing over to consent service.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                getSSOConsentService().processConsent(approvedClaimIds, serviceProvider,
                        loggedInUser, value, true);
            } else {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    if (diagnosticLogBuilder != null) {
                        // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                        diagnosticLogBuilder.resultMessage("Prompt for consent is not enabled. Handing over to " +
                                "consent service.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                }
                getSSOConsentService().processConsent(approvedClaimIds, serviceProvider,
                        loggedInUser, value, false);
            }

        } catch (OAuthSystemException | SSOConsentServiceException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.PROCESS_CONSENT)
                        .resultMessage("System error occurred.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
            }
            String msg = "Error while processing consent of user: " + loggedInUser.toFullQualifiedUsername() + " for " +
                    "client_id: " + clientId + " of tenantDomain: " + spTenantDomain;
            throw new ConsentHandlingFailedException(msg, e);
        } catch (ClaimMetadataException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.PROCESS_CONSENT)
                        .resultMessage(String.format("Error occurred while getting claim mappings for %s.",
                                OIDC_DIALECT))
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
            }
            throw new ConsentHandlingFailedException("Error while getting claim mappings for " + OIDC_DIALECT, e);
        } catch (RequestObjectException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {

                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.PROCESS_CONSENT)
                        .resultMessage(String.format("Error occurred while getting essential claims " +
                                                "for the session data key : %s.", oauth2Params.getSessionDataKey()))
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
            }
            throw new ConsentHandlingFailedException("Error while getting essential claims for the session data key " +
                    ": " + oauth2Params.getSessionDataKey(), e);
        }

    }

    private ConsentClaimsData getConsentRequiredClaims(AuthenticatedUser user, ServiceProvider serviceProvider,
                                                       OAuth2Parameters oAuth2Parameters)
            throws SSOConsentServiceException {

        if (hasPromptContainsConsent(oAuth2Parameters)) {
            // Ignore all previous consents and get consent required claims
            return getSSOConsentService().getConsentRequiredClaimsWithoutExistingConsents(serviceProvider, user);
        } else {
            return getSSOConsentService().getConsentRequiredClaimsWithExistingConsents(serviceProvider, user);
        }
    }

    private List<Integer> getUserConsentClaimIds(OAuthMessage oAuthMessage) {

        List<Integer> approvedClaims = new ArrayList<>();
        String consentClaimsPrefix = "consent_";

        Enumeration<String> parameterNames = oAuthMessage.getRequest().getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String parameterName = parameterNames.nextElement();
            if (parameterName.startsWith(consentClaimsPrefix)) {
                try {
                    approvedClaims.add(Integer.parseInt(parameterName.substring(consentClaimsPrefix.length())));
                } catch (NumberFormatException ex) {
                    // Ignore and continue.
                }
            }
        }
        return approvedClaims;
    }

    private void addSessionDataKeyToSessionDataCacheEntry(OAuthMessage oAuthMessage) {

        String commonAuthIdCookieValue = getCommonAuthCookieString(oAuthMessage.getRequest());
        if (StringUtils.isNotBlank(commonAuthIdCookieValue)) {
            String sessionContextKey = DigestUtils.sha256Hex(commonAuthIdCookieValue);
            oAuthMessage.getSessionDataCacheEntry().getParamMap().put(FrameworkConstants.SESSION_DATA_KEY, new String[]
                    {sessionContextKey});
        }
    }

    /**
     * Retrieves the value of the commonAuthId cookie either from request cookies if available or
     * from the request attribute when the response header contains commonAuthId value.
     *
     * @param request HttpServletRequest An authorization or authentication request.
     * @return String commonAuthId value. Returns null when cookie value is not found at request
     * cookies or the request attributes.
     */
    private String getCommonAuthCookieString(HttpServletRequest request) {

        Cookie cookie = FrameworkUtils.getAuthCookie(request);
        String commonAuthIdCookieValue = null;

        if (cookie != null) {
            commonAuthIdCookieValue = cookie.getValue();
        } else if (request.getAttribute(COMMONAUTH_COOKIE) != null) {
            commonAuthIdCookieValue = (String) request.getAttribute(COMMONAUTH_COOKIE);
        }
        return commonAuthIdCookieValue;
    }

    private String getConsentFromRequest(OAuthMessage oAuthMessage) {

        return oAuthMessage.getRequest().getParameter(CONSENT);
    }

    private void handleEmptyConsent(AuthorizationResponseDTO authorizationResponseDTO) {

        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request. \'sessionDataKey\' parameter found but \'consent\' " +
                    "parameter could not be found in request");
        }

        authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, "Empty consent provided",
                OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private void manageOIDCSessionState(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                        AuthorizationResponseDTO authorizationResponseDTO) {

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());
        String sessionStateParam = null;
        if (isOIDCRequest) {
            sessionState.setAddSessionState(true);
            sessionStateParam = manageOIDCSessionState(oAuthMessage, sessionState, oauth2Params,
                    getLoggedInUser(oAuthMessage).getAuthenticatedSubjectIdentifier(),
                    oAuthMessage.getSessionDataCacheEntry(), authorizationResponseDTO);
        }
        authorizationResponseDTO.setSessionState(sessionStateParam);
    }

    private void handleFormPostResponseMode(OAuthMessage oAuthMessage,
                                            OIDCSessionState sessionState,
                                            AuthorizationResponseDTO authorizationResponseDTO,
                                            AuthenticatedUser authenticatedUser) {

        String authenticatedIdPs = oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs();
        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());

        String sessionStateValue = null;
        if (isOIDCRequest) {
            sessionState.setAddSessionState(true);
            sessionStateValue = manageOIDCSessionState(oAuthMessage,
                    sessionState, oauth2Params, getLoggedInUser(oAuthMessage).getAuthenticatedSubjectIdentifier(),
                    oAuthMessage.getSessionDataCacheEntry(), authorizationResponseDTO);
            authorizationResponseDTO.setSessionState(sessionStateValue);
        }

        if (OAuthServerConfiguration.getInstance().isOAuthResponseJspPageAvailable()) {
            String params = buildParams(authorizationResponseDTO.getSuccessResponseDTO().getFormPostBody(),
                    authenticatedIdPs, sessionStateValue);
            String redirectURI = oauth2Params.getRedirectURI();
            if (authenticatedUser != null) {
                forwardToOauthResponseJSP(oAuthMessage, params, redirectURI, authorizationResponseDTO,
                        authenticatedUser);
            } else {
                forwardToOauthResponseJSP(oAuthMessage, params, redirectURI);
            }
            authorizationResponseDTO.setIsForwardToOAuthResponseJSP(true);
        } else {
            authorizationResponseDTO.setAuthenticatedIDPs(authenticatedIdPs);
        }
    }

    private Response handleFormPostResponseModeError(OAuthMessage oAuthMessage,
                                                     OAuthProblemException oauthProblemException) {

        OAuth2Parameters oauth2Params = oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
        if (OAuthServerConfiguration.getInstance().isOAuthResponseJspPageAvailable()) {
            String params = buildErrorParams(oauthProblemException);
            String redirectURI = oauth2Params.getRedirectURI();
            return forwardToOauthResponseJSP(oAuthMessage, params, redirectURI);
        } else {
            return Response.ok(createErrorFormPage(oauth2Params.getRedirectURI(), oauthProblemException)).build();
        }
    }

    private void handleDeniedConsent(OAuthMessage oAuthMessage, AuthorizationResponseDTO authorizationResponseDTO,
                                     ResponseModeProvider responseModeProvider) throws OAuthSystemException {

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        OpenIDConnectUserRPStore.getInstance().putUserRPToStore(getLoggedInUser(oAuthMessage),
                getOauth2Params(oAuthMessage).getApplicationName(), false,
                oauth2Params.getClientId());

        OAuthErrorDTO oAuthErrorDTO = EndpointUtil.getOAuth2Service().handleUserConsentDenial(oauth2Params);
        OAuthProblemException consentDenialException = buildConsentDenialException(oAuthErrorDTO);

        if (ResponseModeProvider.AuthResponseType.POST_RESPONSE.equals(responseModeProvider.getAuthResponseType())) {
            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie
                    (oAuthMessage.getRequest());
            String sessionStateParam = OIDCSessionManagementUtil.getSessionStateParam(oauth2Params.getClientId(),
                    oauth2Params.getRedirectURI(), opBrowserStateCookie == null ? null :
                            opBrowserStateCookie.getValue());

            authorizationResponseDTO.setSessionState(sessionStateParam);
        }

        authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, consentDenialException.getMessage(),
                OAuth2ErrorCodes.ACCESS_DENIED);
        authorizationResponseDTO.setRedirectUrl(oauth2Params.getRedirectURI());

    }

    private OAuthProblemException buildConsentDenialException(OAuthErrorDTO oAuthErrorDTO) {

        String errorDescription = DEFAULT_ERROR_DESCRIPTION;

        // Adding custom error description.
        if (oAuthErrorDTO != null && StringUtils.isNotBlank(oAuthErrorDTO.getErrorDescription())) {
            errorDescription = oAuthErrorDTO.getErrorDescription();
        }

        OAuthProblemException consentDeniedException = OAuthProblemException.error(OAuth2ErrorCodes.ACCESS_DENIED,
                errorDescription);

        // Adding Error URI if exist.
        if (oAuthErrorDTO != null && StringUtils.isNotBlank(oAuthErrorDTO.getErrorURI())) {
            consentDeniedException.uri(oAuthErrorDTO.getErrorURI());
        }
        return consentDeniedException;
    }

    private Response handleAuthenticationResponse(OAuthMessage oAuthMessage)
            throws OAuthSystemException, URISyntaxException, ConsentHandlingFailedException, OAuthProblemException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.RECEIVE_AUTHENTICATION_RESPONSE);
            if (oAuthMessage.getRequest() != null && MapUtils.isNotEmpty(oAuthMessage.getRequest().getParameterMap())) {
                oAuthMessage.getRequest().getParameterMap().forEach((key, value) -> {
                    if (ArrayUtils.isNotEmpty(value)) {
                        diagnosticLogBuilder.inputParam(key, Arrays.asList(value));
                    }
                });
            }
            diagnosticLogBuilder.resultMessage("Received authentication response from Framework.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        updateAuthTimeInSessionDataCacheEntry(oAuthMessage);
        addSessionDataKeyToSessionDataCacheEntry(oAuthMessage);

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        String tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oauth2Params.getClientId());
        setSPAttributeToRequest(oAuthMessage.getRequest(), oauth2Params.getApplicationName(), tenantDomain);
        String sessionDataKeyFromLogin = getSessionDataKeyFromLogin(oAuthMessage);
        AuthenticationResult authnResult = getAuthenticationResult(oAuthMessage, sessionDataKeyFromLogin);
        AuthorizationResponseDTO authorizationResponseDTO = getAuthResponseDTO(oauth2Params);
        ResponseModeProvider responseModeProvider = getResponseModeProvider(authorizationResponseDTO);
        authorizationResponseDTO.setFormPostRedirectPage(formPostRedirectPage);

        if (isAuthnResultFound(authnResult)) {
            removeAuthenticationResult(oAuthMessage, sessionDataKeyFromLogin);

            if (authnResult.isAuthenticated()) {
                String userIdentifier = null;
                if (authnResult.getSubject() != null) {
                    try {
                        userIdentifier = authnResult.getSubject().getUserId();
                    } catch (UserIdNotFoundException e) {
                        if (StringUtils.isNotBlank(authnResult.getSubject().getAuthenticatedSubjectIdentifier())) {
                            userIdentifier = LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(authnResult
                                    .getSubject().getAuthenticatedSubjectIdentifier()) : authnResult.getSubject()
                                    .getAuthenticatedSubjectIdentifier();
                        }
                    }
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHENTICATION_RESPONSE);
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.APPLICATION_NAME,
                                    oauth2Params.getApplicationName())
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthMessage.getClientId())
                            .inputParam(LogConstants.InputKeys.TENANT_DOMAIN, tenantDomain)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                    if (userIdentifier != null) {
                        diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, userIdentifier);
                        if (LoggerUtils.isLogMaskingEnable) {
                            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER,
                                    LoggerUtils.getMaskedContent(authnResult.getSubject().getUserName()));
                        }
                    }
                    if (oAuthMessage.getAuthorizationGrantCacheEntry() != null) {
                        diagnosticLogBuilder.inputParam("authentication method reference",
                                oAuthMessage.getAuthorizationGrantCacheEntry().getAmrList());
                    }
                    diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .resultMessage("Authentication is successful.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return handleSuccessfulAuthentication(oAuthMessage, oauth2Params, authnResult,
                        authorizationResponseDTO, responseModeProvider);

            } else {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHENTICATION_RESPONSE)
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthMessage.getClientId())
                            .resultMessage("Authentication failed.")
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
                }
                return handleFailedAuthentication(oAuthMessage, oauth2Params, authnResult, authorizationResponseDTO);
            }
        } else {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHENTICATION_RESPONSE)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthMessage.getClientId())
                        .resultMessage("Authentication status is empty")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
            }
            return handleEmptyAuthenticationResult(oAuthMessage, authorizationResponseDTO);
        }
    }

    private boolean isAuthnResultFound(AuthenticationResult authnResult) {

        return authnResult != null;
    }

    private Response handleSuccessfulAuthentication(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params,
                                                    AuthenticationResult authenticationResult, AuthorizationResponseDTO
                                                            authorizationResponseDTO, ResponseModeProvider
                                                            responseModeProvider)
            throws OAuthSystemException, URISyntaxException, ConsentHandlingFailedException {

        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(oauth2Params.getScopes());
        AuthenticatedUser authenticatedUser = authenticationResult.getSubject();

        if (authenticatedUser.getUserAttributes() != null) {
            authenticatedUser.setUserAttributes(new ConcurrentHashMap<>(authenticatedUser.getUserAttributes()));
        }

        addToAuthenticationResultDetailsToOAuthMessage(oAuthMessage, authenticationResult, authenticatedUser);

        OIDCSessionState sessionState = new OIDCSessionState();
        String redirectURL;
        try {
            redirectURL = doUserAuthorization(oAuthMessage, oAuthMessage.getSessionDataKeyFromLogin(), sessionState,
                    authorizationResponseDTO);
            String serviceProviderId = oAuthMessage.getRequest().getParameter(SERVICE_PROVIDER_ID);
            redirectURL = addServiceProviderIdToRedirectURI(redirectURL, serviceProviderId);
        } catch (OAuthProblemException ex) {
            if (isFormPostOrFormPostJWTResponseMode(oauth2Params.getResponseMode())) {
                return handleFailedState(oAuthMessage, oauth2Params, ex, authorizationResponseDTO);
            } else {
                redirectURL = EndpointUtil.getErrorRedirectURL(ex, oauth2Params);
                authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, ex.getMessage(), ex.getError());
            }
        }

        if (!authorizationResponseDTO.getIsConsentRedirect()) {
            if (isFormPostWithoutErrors(oAuthMessage, authorizationResponseDTO)) {
                handleFormPostResponseMode(oAuthMessage, sessionState, authorizationResponseDTO, authenticatedUser);
                if (authorizationResponseDTO.getIsForwardToOAuthResponseJSP()) {
                    return Response.ok().build();
                }
                return Response.ok(responseModeProvider.getAuthResponseBuilderEntity(authorizationResponseDTO)).build();
            } else {
                if (isFormPostWithErrors(authorizationResponseDTO, responseModeProvider)) {

                    /* Error message is added as query parameters to the redirect URL if response mode is form post
                     * or form post jwt but redirect url is not a json object.
                     */
                    return Response.status(authorizationResponseDTO.getResponseCode())
                            .location(new URI((getQueryResponseModeProvider())
                                    .getAuthResponseRedirectUrl(authorizationResponseDTO))).build();
                }
            }
        }

        if (isOIDCRequest && !Constants.RESPONSE_TYPE_DEVICE.equalsIgnoreCase(oauth2Params.getResponseType())) {
            String sessionStateParam = manageOIDCSessionState(oAuthMessage,
                    sessionState, oauth2Params, authenticatedUser.getAuthenticatedSubjectIdentifier(),
                    oAuthMessage.getSessionDataCacheEntry(), authorizationResponseDTO);
            redirectURL = OIDCSessionManagementUtil.addSessionStateToURL(redirectURL, sessionStateParam,
                    oauth2Params.getResponseType());
            authorizationResponseDTO.setSessionState(sessionStateParam);
        }
        if (authorizationResponseDTO.getIsConsentRedirect()) {
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(redirectURL)).build();
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(
                new URI(responseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO))).build();
    }

    private String getSessionDataKeyFromLogin(OAuthMessage oAuthMessage) {

        return oAuthMessage.getSessionDataKeyFromLogin();
    }

    private Response handleFailedState(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params,
                                       OAuthProblemException oauthException, AuthorizationResponseDTO
                                               authorizationResponseDTO)
            throws URISyntaxException {

        String redirectURL = EndpointUtil.getErrorRedirectURL(oauthException, oauth2Params);
        authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, oauthException.getMessage(),
                oauthException.getError());
        if (isFormPostOrFormPostJWTResponseMode(oauth2Params.getResponseMode())) {
            authorizationResponseDTO.setState(oauth2Params.getState());
            oauthException.state(oauth2Params.getState());
            return handleFormPostResponseModeError(oAuthMessage, oauthException);
        } else {
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(redirectURL)).build();
        }
    }

    private Response handleFailedAuthentication(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params,
                                                AuthenticationResult authnResult,
                                                AuthorizationResponseDTO authorizationResponseDTO)
            throws URISyntaxException {

        OAuthErrorDTO oAuthErrorDTO = EndpointUtil.getOAuth2Service().handleAuthenticationFailure(oauth2Params);
        OAuthProblemException oauthException = buildOAuthProblemException(authnResult, oAuthErrorDTO);
        return handleFailedState(oAuthMessage, oauth2Params, oauthException, authorizationResponseDTO);
    }

    private Response handleEmptyAuthenticationResult(OAuthMessage oAuthMessage, AuthorizationResponseDTO
            authorizationResponseDTO) throws URISyntaxException {

        String appName = getOauth2Params(oAuthMessage).getApplicationName();

        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request. \'sessionDataKey\' attribute found but " +
                    "corresponding AuthenticationResult does not exist in the cache.");
        }

        OAuth2Parameters oAuth2Parameters = getOAuth2ParamsFromOAuthMessage(oAuthMessage);
        authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, "Invalid authorization request",
                OAuth2ErrorCodes.INVALID_REQUEST);
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes
                        .OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST, "Invalid authorization request", appName,
                oAuth2Parameters)
        )).build();
    }

    private void addToAuthenticationResultDetailsToOAuthMessage(OAuthMessage oAuthMessage,
                                                                AuthenticationResult authnResult,
                                                                AuthenticatedUser authenticatedUser) {

        oAuthMessage.getSessionDataCacheEntry().setLoggedInUser(authenticatedUser);
        oAuthMessage.getSessionDataCacheEntry().setAuthenticatedIdPs(authnResult.getAuthenticatedIdPs());
        oAuthMessage.getSessionDataCacheEntry().setSessionContextIdentifier((String)
                authnResult.getProperty(FrameworkConstants.AnalyticsAttributes.SESSION_ID));
        // Adding federated tokens come with the authentication result of the authorization call.
        addFederatedTokensToSessionCache(oAuthMessage, authnResult);
        // Adding mapped remoted claims come with the authentication result to resolve access token claims in
        // federated flow.
        addMappedRemoteClaimsToSessionCache(oAuthMessage, authnResult);
    }

    private void updateAuthTimeInSessionDataCacheEntry(OAuthMessage oAuthMessage) {

        String commonAuthIdCookieValue = getCommonAuthCookieString(oAuthMessage.getRequest());
        long authTime = getAuthenticatedTimeFromCommonAuthCookieValue(commonAuthIdCookieValue,
                oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters().getLoginTenantDomain());

        if (authTime > 0) {
            oAuthMessage.getSessionDataCacheEntry().setAuthTime(authTime);
        }

        associateAuthenticationHistory(oAuthMessage.getSessionDataCacheEntry(), commonAuthIdCookieValue);
    }

    private boolean isFormPostResponseMode(OAuthMessage oAuthMessage, String redirectURL) {

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        return isFormPostResponseMode(oauth2Params, redirectURL);
    }

    private boolean isFormPostResponseMode(OAuth2Parameters oauth2Params, String redirectURL) {

        return (OAuthConstants.ResponseModes.FORM_POST.equals(oauth2Params.getResponseMode()) ||
                OAuthConstants.ResponseModes.FORM_POST_JWT.equals(oauth2Params.getResponseMode()))
                && isJSON(redirectURL);
    }

    private boolean isFormPostOrFormPostJWTResponseMode(String responseMode) {

        return (OAuthConstants.ResponseModes.FORM_POST.equals(responseMode) ||
                OAuthConstants.ResponseModes.FORM_POST_JWT.equals(responseMode));
    }

    private Response handleInitialAuthorizationRequest(OAuthMessage oAuthMessage) throws OAuthSystemException,
            OAuthProblemException, URISyntaxException, InvalidRequestParentException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.RECEIVE_AUTHORIZATION_RESPONSE);
            if (oAuthMessage.getRequest() != null && MapUtils.isNotEmpty(oAuthMessage.getRequest().getParameterMap())) {
                oAuthMessage.getRequest().getParameterMap().forEach((key, value) -> {
                    if (ArrayUtils.isNotEmpty(value)) {
                        if (STATE.equals(key) || LOGIN_HINT.equals(key)) {
                            String[] maskedValue = Arrays.copyOf(value, value.length);
                            Arrays.setAll(maskedValue, i ->
                                    LoggerUtils.isLogMaskingEnable ?
                                            LoggerUtils.getMaskedContent(maskedValue[i]) : maskedValue[i]);
                            diagnosticLogBuilder.inputParam(key, Arrays.asList(maskedValue));
                        } else {
                            diagnosticLogBuilder.inputParam(key, Arrays.asList(value));
                        }
                    }
                });
            }
            String userAgentHeader = oAuthMessage.getRequest().getHeader("User-Agent");
            if (StringUtils.isNotEmpty(userAgentHeader)) {
                UserAgent userAgent = new UserAgent(userAgentHeader);
                diagnosticLogBuilder.inputParam("login browser", userAgent.getBrowser())
                        .inputParam("login device", userAgent.getDevice());
            }
            diagnosticLogBuilder.resultMessage("Successfully received OAuth2 Authorize request.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String redirectURL = handleOAuthAuthorizationRequest(oAuthMessage);
        String type = getRequestProtocolType(oAuthMessage);
        try {
            // Add the service provider id to the redirect URL. This is needed to support application wise branding.
            String clientId = oAuthMessage.getRequest().getParameter(CLIENT_ID);
            if (StringUtils.isNotBlank(clientId)) {
                ServiceProvider serviceProvider = getServiceProvider(clientId);
                if (serviceProvider != null) {
                    redirectURL = addServiceProviderIdToRedirectURI(redirectURL,
                            serviceProvider.getApplicationResourceId());
                }
            }
        } catch (OAuthSystemException e) {
            // The value is set to be used for branding purposes. Therefore, if an error occurs, the process should
            // continue without breaking.
            log.debug("Error while getting the service provider id", e);
        }
        if (AuthenticatorFlowStatus.SUCCESS_COMPLETED == oAuthMessage.getFlowStatus()) {
            return handleAuthFlowThroughFramework(oAuthMessage, type, redirectURL);
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

    private String createBaseFormPage(String params, String redirectURI) {

        if (StringUtils.isNotBlank(formPostRedirectPage)) {
            String newPage = formPostRedirectPage;
            String pageWithRedirectURI = newPage.replace("$redirectURI", redirectURI);
            return pageWithRedirectURI.replace("<!--$params-->", params);
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
        form.append(params);
        form.append(formBottom);
        return form.toString();
    }

    private String createFormPage(String jsonPayLoad, String redirectURI, String authenticatedIdPs,
                                  String sessionStateValue) {

        String params = buildParams(jsonPayLoad, authenticatedIdPs, sessionStateValue);
        return createBaseFormPage(params, redirectURI);
    }

    private String createErrorFormPage(String redirectURI, OAuthProblemException oauthProblemException) {

        String params = buildErrorParams(oauthProblemException);
        return createBaseFormPage(params, redirectURI);
    }

    private String buildParams(String jsonPayLoad, String authenticatedIdPs, String sessionStateValue) {

        JSONObject jsonObject = new JSONObject(jsonPayLoad);
        StringBuilder paramStringBuilder = new StringBuilder();

        for (Object key : jsonObject.keySet()) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"")
                    .append(key)
                    .append("\"" + "value=\"")
                    .append(Encode.forHtml(jsonObject.get(key.toString()).toString()))
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

    private String buildErrorParams(OAuthProblemException oauthProblemException) {

        StringBuilder paramStringBuilder = new StringBuilder();

        if (StringUtils.isNotEmpty(oauthProblemException.getError())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"error\" value=\"")
                    .append(oauthProblemException.getError())
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(oauthProblemException.getDescription())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"error_description\" value=\"")
                    .append(oauthProblemException.getDescription())
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(oauthProblemException.getState())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"state\" value=\"")
                    .append(oauthProblemException.getState())
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

    private String handleUserConsent(OAuthMessage oAuthMessage, String consent, OIDCSessionState sessionState,
                                     OAuth2Parameters oauth2Params, AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException {

        storeUserConsent(oAuthMessage, consent);
        OAuthResponse oauthResponse;
        String responseType = oauth2Params.getResponseType();
        HttpRequestHeaderHandler httpRequestHeaderHandler = new HttpRequestHeaderHandler(oAuthMessage.getRequest());
        OAuth2AuthorizeReqDTO authzReqDTO =
                buildAuthRequest(oauth2Params, oAuthMessage.getSessionDataCacheEntry(), httpRequestHeaderHandler,
                        oAuthMessage.getRequest());
        /* We have persisted the oAuthAuthzReqMessageContext before the consent after scope validation. Here we
        retrieve it from the cache and use it again because it contains  information that was set during the scope
        validation process. */
        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext =
                oAuthMessage.getSessionDataCacheEntry().getAuthzReqMsgCtx();
        oAuthAuthzReqMessageContext.setAuthorizationReqDTO(authzReqDTO);
        oAuthAuthzReqMessageContext.addProperty(OAuthConstants.IS_MTLS_REQUEST, oauth2Params.isMtlsRequest());
        // authorizing the request
        OAuth2AuthorizeRespDTO authzRespDTO = authorize(oAuthAuthzReqMessageContext);
        if (authzRespDTO != null && authzRespDTO.getCallbackURI() != null) {
            authorizationResponseDTO.setRedirectUrl(authzRespDTO.getCallbackURI());
        }

        if (isSuccessfulAuthorization(authzRespDTO)) {
            oauthResponse =
                    handleSuccessAuthorization(oAuthMessage, sessionState, oauth2Params, responseType, authzRespDTO,
                            authorizationResponseDTO);
        } else if (isFailureAuthorizationWithErrorCode(authzRespDTO)) {
            // Authorization failure due to various reasons
            return handleFailureAuthorization(oAuthMessage, sessionState, oauth2Params, authzRespDTO,
                    authorizationResponseDTO);
        } else {
            // Authorization failure due to various reasons
            return handleServerErrorAuthorization(oAuthMessage, sessionState, oauth2Params, authorizationResponseDTO);
        }

        //When response_mode equals to form_post, body parameter is passed back.
        if (isFormPostModeAndResponseBodyExists(oauth2Params, oauthResponse)) {
            authorizationResponseDTO.getSuccessResponseDTO().setFormPostBody(oauthResponse.getBody());
            return oauthResponse.getBody();
        } else {
            // When responseType contains "id_token", the resulting token is passed back as a URI fragment
            // as per the specification: http://openid.net/specs/openid-connect-core-1_0.html#HybridCallback
            if (hasIDTokenOrTokenInResponseType(responseType)) {
                return buildOIDCResponseWithURIFragment(oauthResponse, authzRespDTO);
            } else {
                return appendAuthenticatedIDPs(oAuthMessage.getSessionDataCacheEntry(), oauthResponse.getLocationUri(),
                        authorizationResponseDTO);
            }
        }
    }

    /**
     * Checks if the given response type contains either "id_token" or "token".
     *
     * @param responseType The response type to check.
     * @return {@code true} if "id_token" or "token" is present in the response type, {@code false} otherwise.
     */
    private boolean hasIDTokenOrTokenInResponseType(String responseType) {

        return hasResponseType(responseType, OAuthConstants.ID_TOKEN)
                || hasResponseType(responseType, OAuthConstants.TOKEN);
    }

    /**
     * Checks if the given response type contains the specified OAuth response type.
     *
     * @param responseType      The response type to check.
     * @param oauthResponseType The OAuth response type to look for.
     * @return {@code true} if the specified OAuth response type is present in the response type,
     * {@code false} otherwise.
     */
    private boolean hasResponseType(String responseType, String oauthResponseType) {

        if (StringUtils.isNotBlank(responseType)) {
            String[] responseTypes = responseType.split(SPACE_SEPARATOR);
            return Arrays.asList(responseTypes).contains(oauthResponseType);
        }
        return false;
    }

    private String buildOIDCResponseWithURIFragment(OAuthResponse oauthResponse, OAuth2AuthorizeRespDTO authzRespDTO) {

        if (authzRespDTO.getCallbackURI().contains("?")) {
            return authzRespDTO.getCallbackURI() + "#" + StringUtils.substring(oauthResponse.getLocationUri()
                    , authzRespDTO.getCallbackURI().length() + 1);
        } else {
            return oauthResponse.getLocationUri().replace("?", "#");
        }
    }

    private boolean isFailureAuthorizationWithErrorCode(OAuth2AuthorizeRespDTO authzRespDTO) {

        return authzRespDTO != null && authzRespDTO.getErrorCode() != null;
    }

    private boolean isSuccessfulAuthorization(OAuth2AuthorizeRespDTO authzRespDTO) {

        return authzRespDTO != null && authzRespDTO.getErrorCode() == null;
    }

    private void storeUserConsent(OAuthMessage oAuthMessage, String consent) throws OAuthSystemException {

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        String applicationName = oauth2Params.getApplicationName();
        AuthenticatedUser loggedInUser = getLoggedInUser(oAuthMessage);
        String clientId = oauth2Params.getClientId();

        if (!isConsentSkipped(oauth2Params)) {
            boolean approvedAlways = OAuthConstants.Consent.APPROVE_ALWAYS.equals(consent);
            if (approvedAlways) {
                OpenIDConnectUserRPStore.getInstance().putUserRPToStore(loggedInUser, applicationName,
                        true, clientId);
                if (hasPromptContainsConsent(oauth2Params)) {
                    EndpointUtil.storeOAuthScopeConsent(loggedInUser, oauth2Params, true);
                } else {
                    EndpointUtil.storeOAuthScopeConsent(loggedInUser, oauth2Params, false);
                }
            }
        }
    }

    private boolean isFormPostModeAndResponseBodyExists(OAuth2Parameters oauth2Params, OAuthResponse oauthResponse) {

        return (OAuthConstants.ResponseModes.FORM_POST.equals(oauth2Params.getResponseMode()) ||
                OAuthConstants.ResponseModes.FORM_POST_JWT.equals(oauth2Params.getResponseMode()))
                && StringUtils.isNotEmpty(oauthResponse.getBody());
    }

    private String handleServerErrorAuthorization(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                                  OAuth2Parameters oauth2Params,
                                                  AuthorizationResponseDTO authorizationResponseDTO) {

        sessionState.setAuthenticated(false);
        String errorCode = OAuth2ErrorCodes.SERVER_ERROR;
        String errorMsg = "Error occurred while processing the request";
        OAuthProblemException oauthProblemException = OAuthProblemException.error(
                errorCode, errorMsg);
        authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, errorMsg, errorCode);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HANDLE_AUTHORIZATION);
            if (oauth2Params != null) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .inputParam(LogConstants.InputKeys.APPLICATION_NAME, oauth2Params.getApplicationName())
                        .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI, oauth2Params.getRedirectURI())
                        .inputParam(LogConstants.InputKeys.SCOPE, oauth2Params.getScopes())
                        .inputParam(RESPONSE_TYPE, oauth2Params.getResponseType());
            }
            diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultMessage(errorMsg);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return EndpointUtil.getErrorRedirectURL(oAuthMessage.getRequest(),
                oauthProblemException, oauth2Params);
    }

    private String handleFailureAuthorization(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                              OAuth2Parameters oauth2Params,
                                              OAuth2AuthorizeRespDTO authzRespDTO,
        AuthorizationResponseDTO authorizationResponseDTO) {

        sessionState.setAuthenticated(false);
        String errorMsg;
        if (authzRespDTO.getErrorMsg() != null) {
            errorMsg = authzRespDTO.getErrorMsg();
        } else {
            errorMsg = "Error occurred while processing the request";
        }
        OAuthProblemException oauthProblemException = OAuthProblemException.error(
                authzRespDTO.getErrorCode(), errorMsg);
        authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, errorMsg,
                authzRespDTO.getErrorCode());
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HANDLE_AUTHORIZATION);
            if (oauth2Params != null) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .inputParam(LogConstants.InputKeys.APPLICATION_NAME, oauth2Params.getApplicationName())
                        .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI, oauth2Params.getRedirectURI())
                        .inputParam(LogConstants.InputKeys.SCOPE, oauth2Params.getScopes())
                        .inputParam(RESPONSE_TYPE, oauth2Params.getResponseType());
            }
            diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .resultMessage("Error occurred while processing the authorization: " + errorMsg)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return EndpointUtil.getErrorRedirectURL(oAuthMessage.getRequest(), oauthProblemException, oauth2Params);
    }

    private String handleAuthorizationFailureBeforeConsent(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params,
                                              OAuth2AuthorizeRespDTO authzRespDTO) {

        String errorMsg = authzRespDTO.getErrorMsg() != null ? authzRespDTO.getErrorMsg()
                : "Error occurred while processing authorization request.";
        OAuthProblemException oauthProblemException = OAuthProblemException.error(
                authzRespDTO.getErrorCode(), errorMsg);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_SCOPES_BEFORE_CONSENT);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                    .inputParam(LogConstants.InputKeys.APPLICATION_NAME, oauth2Params.getApplicationName())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI, authzRespDTO.getCallbackURI())
                    .resultMessage("Error occurred when processing the authorization request before consent. " +
                            authzRespDTO.getErrorMsg())
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return EndpointUtil.getErrorRedirectURL(oAuthMessage.getRequest(), oauthProblemException, oauth2Params);
    }

    private OAuthResponse handleSuccessAuthorization(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                                     OAuth2Parameters oauth2Params, String responseType,
                                                     OAuth2AuthorizeRespDTO authzRespDTO,
                                                     AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException {

        OAuthASResponse.OAuthAuthorizationResponseBuilder builder = OAuthASResponse.authorizationResponse(
                oAuthMessage.getRequest(), HttpServletResponse.SC_FOUND);
        // all went okay
        if (isAuthorizationCodeExists(authzRespDTO)) {
            // Get token binder if it is enabled for the client.
            Optional<TokenBinder> tokenBinderOptional = getTokenBinder(oauth2Params.getClientId());
            String tokenBindingValue = null;
            if (tokenBinderOptional.isPresent()) {
                TokenBinder tokenBinder = tokenBinderOptional.get();
                if (!tokenBinder.getBindingType().equals(CLIENT_REQUEST)) {
                    tokenBindingValue = tokenBinder.getOrGenerateTokenBindingValue(oAuthMessage.getRequest());
                    tokenBinder.setTokenBindingValueForResponse(oAuthMessage.getResponse(), tokenBindingValue);
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                                OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, "generate-token-binding-value")
                                .inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                                .inputParam("token binding value", tokenBindingValue)
                                .configParam("token binder type", tokenBinder.getBindingType())
                                .resultMessage("Successfully generated token binding value.")
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
                    }
                }
            }
            setAuthorizationCode(oAuthMessage, authzRespDTO, builder, tokenBindingValue, oauth2Params,
                    authorizationResponseDTO);
        }
        if (Constants.RESPONSE_TYPE_DEVICE.equalsIgnoreCase(responseType)) {
            cacheUserAttributesByDeviceCode(oAuthMessage.getSessionDataCacheEntry());
        }
        if (isResponseTypeNotIdTokenOrNone(responseType, authzRespDTO)) {
            setAccessToken(authzRespDTO, builder, authorizationResponseDTO);
            setScopes(authzRespDTO, builder, authorizationResponseDTO);
        }
        if (isSubjectTokenFlow(responseType, authzRespDTO)) {
            setSubjectToken(authzRespDTO, builder, authorizationResponseDTO);
        }
        if (isIdTokenExists(authzRespDTO)) {
            setIdToken(authzRespDTO, builder, authorizationResponseDTO);
            oAuthMessage.setProperty(OIDC_SESSION_ID, authzRespDTO.getOidcSessionId());
        }
        if (StringUtils.isNotBlank(oauth2Params.getState())) {
            builder.setParam(OAuth.OAUTH_STATE, oauth2Params.getState());
            authorizationResponseDTO.setState(oauth2Params.getState());
        }
        String redirectURL = authzRespDTO.getCallbackURI();

        OAuthResponse oauthResponse;

        if (isFormPostOrFormPostJWTResponseMode(oauth2Params.getResponseMode())) {
            oauthResponse = handleFormPostMode(oAuthMessage, builder, redirectURL, authorizationResponseDTO);
        } else {
            oauthResponse = builder.location(redirectURL).buildQueryMessage();
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HANDLE_AUTHORIZATION);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                    .inputParam(LogConstants.InputKeys.APPLICATION_NAME, oauth2Params.getApplicationName())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI, redirectURL)
                    .inputParam(RESPONSE_TYPE, oauth2Params.getResponseMode())
                    .inputParam("authorized scopes", authzRespDTO.getScope())
                    .resultMessage("Successfully generated oauth response.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        sessionState.setAuthenticated(true);
        return oauthResponse;
    }

    private boolean isSubjectTokenFlow(String responseType, OAuth2AuthorizeRespDTO authzRespDTO) {

        return StringUtils.isNotBlank(authzRespDTO.getSubjectToken()) &&
                hasResponseType(responseType, OAuthConstants.SUBJECT_TOKEN);
    }

    private Optional<TokenBinder> getTokenBinder(String clientId) throws OAuthSystemException {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new OAuthSystemException("Failed to retrieve OAuth application with client id: " + clientId, e);
        }

        if (oAuthAppDO == null || StringUtils.isBlank(oAuthAppDO.getTokenBindingType())) {
            return Optional.empty();
        }

        OAuth2Service oAuth2Service = getOAuth2Service();
        List<TokenBinder> supportedTokenBinders = oAuth2Service.getSupportedTokenBinders();
        if (supportedTokenBinders == null || supportedTokenBinders.isEmpty()) {
            return Optional.empty();
        }

        return supportedTokenBinders.stream().filter(t -> t.getBindingType().equals(oAuthAppDO.getTokenBindingType()))
                .findAny();
    }

    private OAuthResponse handleFormPostMode(OAuthMessage oAuthMessage,
                                             OAuthASResponse.OAuthAuthorizationResponseBuilder builder,
                                             String redirectURL, AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException {

        OAuthResponse oauthResponse;
        String authenticatedIdPs = oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs();
        if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
            builder.setParam(AUTHENTICATED_ID_PS, oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs());
            authorizationResponseDTO.setAuthenticatedIDPs
                    (oAuthMessage.getSessionDataCacheEntry().getAuthenticatedIdPs());
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

    private void setIdToken(OAuth2AuthorizeRespDTO authzRespDTO,
                            OAuthASResponse.OAuthAuthorizationResponseBuilder builder,
                            AuthorizationResponseDTO authorizationResponseDTO) {

        builder.setParam(OAuthConstants.ID_TOKEN, authzRespDTO.getIdToken());
        authorizationResponseDTO.getSuccessResponseDTO().setIdToken(authzRespDTO.getIdToken());
    }

    private void setAuthorizationCode(OAuthMessage oAuthMessage, OAuth2AuthorizeRespDTO authzRespDTO,
                                      OAuthASResponse.OAuthAuthorizationResponseBuilder builder,
                                      String tokenBindingValue, OAuth2Parameters oauth2Params, AuthorizationResponseDTO
                                              authorizationResponseDTO)
            throws OAuthSystemException {

        String authorizationCode = authzRespDTO.getAuthorizationCode();
        builder.setCode(authorizationCode);
        authorizationResponseDTO.getSuccessResponseDTO().setAuthorizationCode(authorizationCode);

        AccessTokenExtendedAttributes tokenExtendedAttributes = null;
        if (isConsentResponseFromUser(oAuthMessage)) {
            tokenExtendedAttributes = getExtendedTokenAttributes(oAuthMessage, oauth2Params);
        }
        addUserAttributesToOAuthMessage(oAuthMessage, authorizationCode, authzRespDTO.getCodeId(),
                tokenBindingValue, tokenExtendedAttributes);
    }

    private AccessTokenExtendedAttributes getExtendedTokenAttributes(OAuthMessage oAuthMessage,
                                                                     OAuth2Parameters oauth2Params) {

        try {
            ServiceProvider serviceProvider = getServiceProvider(oauth2Params.getClientId());
            // TODO: Improve to read the script separately instead of reading from adaptive script.
            if (!EndpointUtil.isExternalConsentPageEnabledForSP(serviceProvider) ||
                    serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationScriptConfig() == null) {
                return null;
            }
            Gson gson = new Gson();
            JSEngine jsEngine = EngineUtils.getEngineFromConfig();
            JsLogger jsLogger = new JsLogger();
            Map<String, Object> bindings = new HashMap<>();
            bindings.put(FrameworkConstants.JSAttributes.JS_LOG, jsLogger);
            List<String> accessTokenJSObject = new ArrayList<>();
            Map<String, Object> parameterMap = gson.fromJson(gson.toJson(oAuthMessage.getRequest().getParameterMap()),
                    new TypeToken<Map<String, Object>>() {
                    }.getType());
            accessTokenJSObject.add(ACCESS_TOKEN_JS_OBJECT);
            Map<String, Object> result = jsEngine
                    .createEngine()
                    .addBindings(bindings)
                    .evalScript(
                            serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationScriptConfig()
                                    .getContent())
                    .invokeFunction(DYNAMIC_TOKEN_DATA_FUNCTION, parameterMap)
                    .getJSObjects(accessTokenJSObject);
            AccessTokenExtendedAttributes accessTokenExtendedAttributes =
                    gson.fromJson(gson.toJson(result.get(ACCESS_TOKEN_JS_OBJECT)), AccessTokenExtendedAttributes.class);
            if (accessTokenExtendedAttributes != null) {
                accessTokenExtendedAttributes.setExtendedToken(true);
            }
            return accessTokenExtendedAttributes;
        } catch (Exception e) {
            String msg = "Error occurred when processing consent response request from tenant: " +
                    oauth2Params.getTenantDomain() + "after consent.";
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,  "authorize-client")
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage(msg)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            log.warn(msg, e);
        }
        return null;
    }

    private void setAccessToken(OAuth2AuthorizeRespDTO authzRespDTO,
                                OAuthASResponse.OAuthAuthorizationResponseBuilder builder,
                                AuthorizationResponseDTO authorizationResponseDTO) {

        builder.setAccessToken(authzRespDTO.getAccessToken());
        builder.setExpiresIn(authzRespDTO.getValidityPeriod());
        builder.setParam(OAuth.OAUTH_TOKEN_TYPE, BEARER);
        authorizationResponseDTO.getSuccessResponseDTO().setAccessToken(authzRespDTO.getAccessToken());
        authorizationResponseDTO.getSuccessResponseDTO().setTokenType(BEARER);
        authorizationResponseDTO.getSuccessResponseDTO().setValidityPeriod(authzRespDTO.getValidityPeriod());
    }

    private void setSubjectToken(OAuth2AuthorizeRespDTO authzRespDTO,
                                 OAuthASResponse.OAuthAuthorizationResponseBuilder builder,
                                 AuthorizationResponseDTO authorizationResponseDTO) {

        builder.setParam(OAuthConstants.SUBJECT_TOKEN, authzRespDTO.getSubjectToken());
        authorizationResponseDTO.getSuccessResponseDTO().setSubjectToken(authzRespDTO.getSubjectToken());
    }

    private void setScopes(OAuth2AuthorizeRespDTO authzRespDTO,
                           OAuthASResponse.OAuthAuthorizationResponseBuilder builder, AuthorizationResponseDTO
                                   authorizationResponseDTO) {

        String[] scopes = authzRespDTO.getScope();
        if (scopes != null && scopes.length > 0) {
            String scopeString =  StringUtils.join(scopes, " ");
            builder.setScope(scopeString.trim());
            Set<String> scopesSet = new HashSet<>(Arrays.asList(scopes));
            authorizationResponseDTO.getSuccessResponseDTO().setScope(scopesSet);
        }
    }

    private void addUserAttributesToOAuthMessage(OAuthMessage oAuthMessage, String code, String codeId,
                                                 String tokenBindingValue,
                                                 AccessTokenExtendedAttributes tokenExtendedAttributes)
            throws OAuthSystemException {

        SessionDataCacheEntry sessionDataCacheEntry = oAuthMessage.getSessionDataCacheEntry();
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
        authorizationGrantCacheEntry.setMaxAge(sessionDataCacheEntry.getoAuth2Parameters().getMaxAge());
        authorizationGrantCacheEntry.setTokenBindingValue(tokenBindingValue);
        authorizationGrantCacheEntry.setSessionContextIdentifier(sessionDataCacheEntry.getSessionContextIdentifier());
        authorizationGrantCacheEntry.setAccessTokenExtensionDO(tokenExtendedAttributes);
        if (isApiBasedAuthenticationFlow(oAuthMessage)) {
            authorizationGrantCacheEntry.setApiBasedAuthRequest(true);
        }

        String[] sessionIds = sessionDataCacheEntry.getParamMap().get(FrameworkConstants.SESSION_DATA_KEY);
        if (ArrayUtils.isNotEmpty(sessionIds)) {
            String commonAuthSessionId = sessionIds[0];
            SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(commonAuthSessionId,
                    sessionDataCacheEntry.getoAuth2Parameters().getLoginTenantDomain());
            if (sessionContext != null) {
                String selectedAcr = sessionContext.getSessionAuthHistory().getSelectedAcrValue();
                authorizationGrantCacheEntry.setSelectedAcrValue(selectedAcr);
            }
        }

        String[] amrEntries = sessionDataCacheEntry.getParamMap().get(OAuthConstants.AMR);
        if (amrEntries != null) {
            for (String amrEntry : amrEntries) {
                authorizationGrantCacheEntry.addAmr(amrEntry);
            }
        }
        authorizationGrantCacheEntry.setAuthorizationCode(code);
        boolean isRequestObjectFlow = sessionDataCacheEntry.getoAuth2Parameters().isRequestObjectFlow();
        authorizationGrantCacheEntry.setRequestObjectFlow(isRequestObjectFlow);
        authorizationGrantCacheEntry.setFederatedTokens(sessionDataCacheEntry.getFederatedTokens());
        sessionDataCacheEntry.setFederatedTokens(null);
        Map<ClaimMapping, String> mappedRemoteClaims =  sessionDataCacheEntry.getMappedRemoteClaims();
        if (mappedRemoteClaims != null) {
            authorizationGrantCacheEntry.setMappedRemoteClaims(mappedRemoteClaims);
        }
        oAuthMessage.setAuthorizationGrantCacheEntry(authorizationGrantCacheEntry);
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
     * @throws OAuthSystemException  OAuthSystemException
     * @throws OAuthProblemException OAuthProblemException
     */
    private String handleOAuthAuthorizationRequest(OAuthMessage oAuthMessage)
            throws OAuthSystemException, OAuthProblemException, InvalidRequestException {

        OAuth2ClientValidationResponseDTO validationResponse = validateClient(oAuthMessage);

        if (!validationResponse.isValidClient()) {
            EndpointUtil.triggerOnRequestValidationFailure(oAuthMessage, validationResponse);
            return getErrorPageURL(oAuthMessage.getRequest(), validationResponse.getErrorCode(), OAuth2ErrorCodes
                    .OAuth2SubErrorCodes.INVALID_CLIENT, validationResponse.getErrorMsg(), null);
        } else {
            populateValidationResponseWithAppDetail(oAuthMessage, validationResponse);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthMessage.getClientId())
                        .resultMessage("OAuth client validation is successful.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
            }
            String tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
            setSPAttributeToRequest(oAuthMessage.getRequest(), validationResponse.getApplicationName(), tenantDomain);
        }

        OAuthAuthzRequest oauthRequest = getOAuthAuthzRequest(oAuthMessage.getRequest());

        OAuth2Parameters params = new OAuth2Parameters();
        String sessionDataKey = UUID.randomUUID().toString();
        params.setSessionDataKey(sessionDataKey);
        String redirectURI = populateOauthParameters(params, oAuthMessage, validationResponse, oauthRequest);
        if (redirectURI != null) {
            return redirectURI;
        }
        // Check whether PAR should be mandated in  the request.
        checkPARMandatory(params, oAuthMessage);
        String prompt = oauthRequest.getParam(OAuthConstants.OAuth20Params.PROMPT);
        params.setPrompt(prompt);

        redirectURI = analyzePromptParameter(oAuthMessage, params, prompt);
        if (redirectURI != null) {
            return redirectURI;
        }

        if (isNonceMandatory(params.getResponseType())) {
            validateNonceParameter(params.getNonce());
        }

        if (isFapiConformant(params.getClientId())) {
            EndpointUtil.validateFAPIAllowedResponseTypeAndMode(params.getResponseType(), params.getResponseMode());
        }

        addDataToSessionCache(oAuthMessage, params, sessionDataKey);

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                    .inputParam(LogConstants.InputKeys.CLIENT_ID, params.getClientId())
                    .resultMessage("OIDC request input parameter validation is successful.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
        }

        try {
            oAuthMessage.getRequest().setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus
                    .SUCCESS_COMPLETED);
            oAuthMessage.getRequest().setAttribute(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
            return getLoginPageURL(oAuthMessage.getClientId(), sessionDataKey, oAuthMessage.isForceAuthenticate(),
                    oAuthMessage.isPassiveAuthentication(), oauthRequest.getScopes(),
                    oAuthMessage.getRequest().getParameterMap(), oAuthMessage.getRequest());
        } catch (IdentityOAuth2Exception e) {
            return handleException(e);
        }
    }

    private void populateValidationResponseWithAppDetail(OAuthMessage oAuthMessage,
                                                         OAuth2ClientValidationResponseDTO validationResponse)
            throws OAuthSystemException {

        String clientId = oAuthMessage.getRequest().getParameter(CLIENT_ID);
        try {
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            if (Boolean.TRUE.equals(oAuthMessage.getRequest().getAttribute(OAuthConstants.PKCE_UNSUPPORTED_FLOW))) {
                validationResponse.setPkceMandatory(false);
            } else {
                validationResponse.setPkceMandatory(appDO.isPkceMandatory());
            }
            validationResponse.setApplicationName(appDO.getApplicationName());
            validationResponse.setPkceSupportPlain(appDO.isPkceSupportPlain());
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw new OAuthSystemException("Error while retrieving app information for client_id : " + clientId, e);
        }
    }

    /**
     * Checks whether the given authentication flow requires {@code nonce} as a mandatory parameter.
     *
     * @param responseType Response type from the authentication request.
     * @return {@true} {@code true} if parameter is mandatory, {@code false} if not.
     */
    private boolean isNonceMandatory(String responseType) {

        /*
        nonce parameter is required for the OIDC hybrid flow and implicit flow grant types requesting ID_TOKEN.
         */
        return Arrays.stream(responseType.split("\\s+")).anyMatch(OAuthConstants.ID_TOKEN::equals);
    }

    /**
     * Validates the nonce parameter as mandatory.
     *
     * @param nonce {@code nonce} parameter. Presence of nonce in the request object is honoured over
     *              oauth2 request parameters.
     * @throws OAuthProblemException Nonce parameter is not found.
     */
    private void validateNonceParameter(String nonce) throws OAuthProblemException {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS);
            diagnosticLogBuilder.inputParam("nonce", nonce)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        if (StringUtils.isBlank(nonce)) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                diagnosticLogBuilder.resultMessage("'response_type' contains 'id_token' but 'nonce' param not found.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST)
                    .description("\'response_type\' contains \'id_token\'; but \'nonce\' parameter not found");
        }
        if (log.isDebugEnabled()) {
            log.debug("Mandatory " + NONCE + " parameter is successfully validated");
        }
        if (diagnosticLogBuilder != null) {
            // diagnosticLogBuilder will be null if diagnostic logs are disabled.
            diagnosticLogBuilder.resultMessage("'nonce' parameter validation is successful.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private void persistRequestObject(OAuth2Parameters params, RequestObject requestObject)
            throws RequestObjectException {

        String sessionDataKey = params.getSessionDataKey();
        if (EndpointUtil.getRequestObjectService() != null) {
            if (requestObject != null && MapUtils.isNotEmpty(requestObject.getRequestedClaims())) {
                EndpointUtil.getRequestObjectService().addRequestObject(params.getClientId(), sessionDataKey,
                        new ArrayList(requestObject.getRequestedClaims().values()));
                params.setRequestObjectFlow(true);
            }
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
        sessionDataCacheEntryNew.setValidityPeriod(TimeUnit.MINUTES.toNanos(IdentityUtil.getTempDataCleanUpTimeout()));
        SessionDataCache.getInstance().addToCache(cacheKey, sessionDataCacheEntryNew);
        oAuthMessage.setSessionDataCacheEntry(sessionDataCacheEntryNew);
    }

    private String analyzePromptParameter(OAuthMessage oAuthMessage, OAuth2Parameters params, String prompt) {

        List promptsList = getSupportedPromtsValues();
        boolean containsNone = (OAuthConstants.Prompt.NONE).equals(prompt);

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, params.getClientId())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.PROMPT, prompt)
                    .configParam("serverSupportedPrompts", promptsList)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        if (StringUtils.isNotBlank(prompt)) {
            List requestedPrompts = getRequestedPromptList(prompt);
            if (!CollectionUtils.containsAny(requestedPrompts, promptsList)) {
                String message = "Invalid prompt variables passed with the authorization request";
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    diagnosticLogBuilder.resultMessage(message);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return handleInvalidPromptValues(oAuthMessage, params, prompt, message);
            }

            if (requestedPrompts.size() > 1) {
                if (requestedPrompts.contains(OAuthConstants.Prompt.NONE)) {

                    String message =
                            "Invalid prompt variable combination. The value 'none' cannot be used with others " +
                                    "prompts. Prompt: ";
                    if (diagnosticLogBuilder != null) {
                        // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                        diagnosticLogBuilder.resultMessage(message);
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    return handleInvalidPromptValues(oAuthMessage, params, prompt, message);

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

    private String handleInvalidPromptValues(OAuthMessage oAuthMessage, OAuth2Parameters params, String prompt, String
            message) {

        if (log.isDebugEnabled()) {
            log.debug(message + " " + prompt);
        }
        OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.INVALID_REQUEST, message);
        return EndpointUtil.getErrorRedirectURL(oAuthMessage.getRequest(), ex, params);
    }

    private List getRequestedPromptList(String prompt) {

        String[] prompts = prompt.trim().split("\\s");
        return Arrays.asList(prompts);
    }

    private List<String> getSupportedPromtsValues() {

        return Arrays.asList(OAuthConstants.Prompt.NONE, OAuthConstants.Prompt.LOGIN,
                OAuthConstants.Prompt.CONSENT, OAuthConstants.Prompt.SELECT_ACCOUNT);
    }

    private String validatePKCEParameters(OAuthMessage oAuthMessage, OAuth2ClientValidationResponseDTO
            validationResponse, String pkceChallengeCode, String pkceChallengeMethod) {

        OAuth2Parameters oAuth2Parameters = getOAuth2ParamsFromOAuthMessage(oAuthMessage);

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            String clientID = oAuth2Parameters.getClientId();
            if (clientID == null) {
                clientID = oAuthMessage.getClientId();
            }
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_PKCE)
                    .inputParam(LogConstants.InputKeys.CLIENT_ID, clientID)
                    .inputParam("PKCE challenge", pkceChallengeCode)
                    .inputParam("PKCE method", pkceChallengeMethod)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        // Check if PKCE is mandatory for the application
        if (validationResponse.isPkceMandatory()) {
            if (pkceChallengeCode == null || !OAuth2Util.validatePKCECodeChallenge(pkceChallengeCode,
                    pkceChallengeMethod)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    diagnosticLogBuilder.configParam("is PKCE mandatory", "true")
                            .resultMessage("PKCE Challenge is not provided or is not upto RFC 7636 specification.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes
                        .OAuth2SubErrorCodes.INVALID_PKCE_CHALLENGE_CODE, "PKCE is mandatory for this application. " +
                        "PKCE Challenge is not provided or is not upto RFC 7636 " +
                        "specification.", null, oAuth2Parameters);
            }
        }
        //Check if the code challenge method value is neither "plain" or "s256", if so return error
        if (pkceChallengeCode != null && pkceChallengeMethod != null) {
            if (!OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(pkceChallengeMethod) &&
                    !OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(pkceChallengeMethod)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    diagnosticLogBuilder.configParam("is PKCE mandatory",
                                    Boolean.toString(validationResponse.isPkceMandatory()))
                            .resultMessage("Unsupported PKCE Challenge Method.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes
                                .OAuth2SubErrorCodes.INVALID_PKCE_CHALLENGE_CODE,
                        "Unsupported PKCE Challenge Method", null, oAuth2Parameters);
            }
        }

        // Check if "plain" transformation algorithm is disabled for the application
        if (pkceChallengeCode != null && !validationResponse.isPkceSupportPlain()) {
            if (pkceChallengeMethod == null || OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(pkceChallengeMethod)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    diagnosticLogBuilder.configParam("is PKCE mandatory",
                                    Boolean.toString(validationResponse.isPkceMandatory()))
                            .configParam("is PKCE support plain", "false")
                            .resultMessage("OAuth client does not support 'plain' transformation algorithm.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes
                        .OAuth2SubErrorCodes.INVALID_PKCE_CHALLENGE_CODE, "This application does not support " +
                        "\"plain\" transformation algorithm.", null, oAuth2Parameters);
            }
        }

        // If PKCE challenge code was sent, check if the code challenge is upto specifications
        if (pkceChallengeCode != null && !OAuth2Util.validatePKCECodeChallenge(pkceChallengeCode,
                pkceChallengeMethod)) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                diagnosticLogBuilder.configParam("is PKCE mandatory",
                                Boolean.toString(validationResponse.isPkceMandatory()))
                        .resultMessage("Code challenge used is not up to RFC 7636 specifications.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes
                    .OAuth2SubErrorCodes.INVALID_PKCE_CHALLENGE_CODE, "Code challenge used is not up to RFC 7636 " +
                    "specifications.", null, oAuth2Parameters);
        }
        if (diagnosticLogBuilder != null) {
            diagnosticLogBuilder.resultMessage("PKCE validation is successful.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return null;
    }

    private boolean isPkceSupportEnabled() {

        return getOAuth2Service().isPKCESupportEnabled();
    }

    private String getSpDisplayName(String clientId) throws OAuthSystemException {

        if (getOAuthServerConfiguration().isShowDisplayNameInConsentPage()) {
            ServiceProvider serviceProvider = getServiceProvider(clientId);
            ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
            for (ServiceProviderProperty serviceProviderProperty : serviceProviderProperties) {
                if (DISPLAY_NAME.equals(serviceProviderProperty.getName())) {
                    return serviceProviderProperty.getValue();
                }
            }
        }
        return StringUtils.EMPTY;
    }

    private String populateOauthParameters(OAuth2Parameters params, OAuthMessage oAuthMessage,
                                           OAuth2ClientValidationResponseDTO validationResponse,
                                           OAuthAuthzRequest oauthRequest)
            throws OAuthSystemException, InvalidRequestException {

        String clientId = oAuthMessage.getClientId();
        params.setClientId(clientId);
        params.setRedirectURI(validationResponse.getCallbackURL());
        params.setResponseType(oauthRequest.getResponseType());
        params.setResponseMode(oauthRequest.getParam(RESPONSE_MODE));
        params.setScopes(oauthRequest.getScopes());
        if (params.getScopes() == null) { // to avoid null pointers
            Set<String> scopeSet = new HashSet<String>();
            scopeSet.add("");
            params.setScopes(scopeSet);
        }
        params.setState(oauthRequest.getState());
        params.setApplicationName(validationResponse.getApplicationName());

        String spDisplayName = getSpDisplayName(clientId);
        if (StringUtils.isNotBlank(spDisplayName)) {
            params.setDisplayName(spDisplayName);
        }

        // OpenID Connect specific request parameters
        params.setNonce(oauthRequest.getParam(OAuthConstants.OAuth20Params.NONCE));
        params.setDisplay(oauthRequest.getParam(OAuthConstants.OAuth20Params.DISPLAY));
        params.setIDTokenHint(oauthRequest.getParam(OAuthConstants.OAuth20Params.ID_TOKEN_HINT));
        params.setLoginHint(oauthRequest.getParam(OAuthConstants.OAuth20Params.LOGIN_HINT));

        // Set the service provider tenant domain.
        params.setTenantDomain(getSpTenantDomain(clientId));

        // Set the login tenant domain.
        String loginTenantDomain = getLoginTenantDomain(oAuthMessage, clientId);
        params.setLoginTenantDomain(loginTenantDomain);

        if (StringUtils.isNotBlank(oauthRequest.getParam(ACR_VALUES)) && !"null".equals(oauthRequest.getParam
                (ACR_VALUES))) {
            List acrValuesList = Arrays.asList(oauthRequest.getParam(ACR_VALUES).split(" "));
            LinkedHashSet acrValuesHashSet = new LinkedHashSet<>(acrValuesList);
            params.setACRValues(acrValuesHashSet);
            oAuthMessage.getRequest().setAttribute(ACR_VALUES, acrValuesList);
        }
        if (StringUtils.isNotBlank(oauthRequest.getParam(CLAIMS))) {
            params.setEssentialClaims(oauthRequest.getParam(CLAIMS));
        }

        handleMaxAgeParameter(oauthRequest, params);

        Object isMtls = oAuthMessage.getRequest().getAttribute(OAuthConstants.IS_MTLS_REQUEST);
        params.setIsMtlsRequest(isMtls != null && Boolean.parseBoolean(isMtls.toString()));

        /*
            OIDC Request object will supersede parameters sent in the OAuth Authorization request. So handling the
            OIDC Request object needs to done after processing all request parameters.
         */
        if (OAuth2Util.isOIDCAuthzRequest(oauthRequest.getScopes())) {
            try {
                handleOIDCRequestObject(oAuthMessage, oauthRequest, params);
            } catch (RequestObjectException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Request Object Handling failed due to : " + e.getErrorCode() + " for client_id: "
                            + clientId + " of tenantDomain: " + params.getTenantDomain(), e);
                }
                if (StringUtils.isNotBlank(oAuthMessage.getRequest().getParameter(REQUEST_URI))) {
                    return EndpointUtil.getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes
                                    .OAuth2SubErrorCodes.INVALID_REQUEST_URI,
                            e.getErrorCode(), e.getErrorMessage(), null, params);
                } else {
                    return EndpointUtil.getErrorPageURL(oAuthMessage.getRequest(), OAuth2ErrorCodes
                                    .OAuth2SubErrorCodes.INVALID_REQUEST_OBJECT, e.getErrorCode(), e.getErrorMessage(),
                            null, params);
                }
            }
        }

        if (isPkceSupportEnabled()) {
            String pkceChallengeCode = getPkceCodeChallenge(oAuthMessage, params);
            String pkceChallengeMethod = getPkceCodeChallengeMethod(oAuthMessage, params);

            String redirectURI = validatePKCEParameters(oAuthMessage, validationResponse, pkceChallengeCode,
                    pkceChallengeMethod);
            if (redirectURI != null) {
                return redirectURI;
            }
            params.setPkceCodeChallenge(pkceChallengeCode);
            params.setPkceCodeChallengeMethod(pkceChallengeMethod);
        }
        params.setRequestedSubjectId(oAuthMessage.getRequestedSubjectId());

        return null;
    }

    private String getSpTenantDomain(String clientId) throws InvalidRequestException {

        try {
            // At this point we have verified that a valid app exists for the client_id. So we directly get the SP
            // tenantDomain.
            return OAuth2Util.getTenantDomainOfOauthApp(clientId);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw new InvalidRequestException("Error retrieving Service Provider tenantDomain for client_id: "
                    + clientId, OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes
                    .UNEXPECTED_SERVER_ERROR);
        }
    }

    private String getLoginTenantDomain(OAuthMessage oAuthMessage, String clientId) throws InvalidRequestException {

        if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
            return EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
        }

        String loginTenantDomain =
                oAuthMessage.getRequest().getParameter(FrameworkConstants.RequestParams.LOGIN_TENANT_DOMAIN);
        if (StringUtils.isBlank(loginTenantDomain)) {
            return EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
        }
        return loginTenantDomain;
    }

    private void handleMaxAgeParameter(OAuthAuthzRequest oauthRequest,
                                       OAuth2Parameters params) throws InvalidRequestException {
        // Set max_age parameter sent in the authorization request.
        String maxAgeParam = oauthRequest.getParam(OAuthConstants.OIDCClaims.MAX_AGE);
        if (StringUtils.isNotBlank(maxAgeParam)) {
            try {
                params.setMaxAge(Long.parseLong(maxAgeParam));
            } catch (NumberFormatException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid max_age parameter: '" + maxAgeParam + "' sent in the authorization request.");
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, params.getClientId())
                            .inputParam("max age", maxAgeParam)
                            .resultMessage("Invalid max_age parameter value.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                throw new InvalidRequestException("Invalid max_age parameter value sent in the authorization request" +
                        ".", OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_PARAMETERS);
            }
        }
    }

    private void handleOIDCRequestObject(OAuthMessage oAuthMessage, OAuthAuthzRequest oauthRequest,
                                         OAuth2Parameters parameters)
            throws RequestObjectException, InvalidRequestException {

        validateRequestObjectParams(oauthRequest);
        String requestObjValue = null;
        if (isRequestUri(oauthRequest)) {
            requestObjValue = oauthRequest.getParam(REQUEST_URI);
        } else if (isRequestParameter(oauthRequest)) {
            requestObjValue = oauthRequest.getParam(REQUEST);
        }
        /* Mandate request object for FAPI requests.
           https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server (5.2.2-1)  */
        if (isFapiConformant(oAuthMessage.getClientId())) {
            if (requestObjValue == null) {
                throw new InvalidRequestException("Request Object is mandatory for FAPI Conformant Applications.",
                        OAuth2ErrorCodes.INVALID_REQUEST, "Request object is missing.");
            }
        }

        if (StringUtils.isNotEmpty(requestObjValue)) {
            handleRequestObject(oAuthMessage, oauthRequest, parameters);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Authorization Request does not contain a Request Object or Request Object reference.");
            }
        }
    }

    private void validateRequestObjectParams(OAuthAuthzRequest oauthRequest) throws RequestObjectException {

        if (StringUtils.isNotEmpty(oauthRequest.getParam(REQUEST)) && StringUtils.isNotEmpty(oauthRequest.getParam
                (REQUEST_URI))) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT)
                        .inputParam("request", oauthRequest.getParam(REQUEST))
                        .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI,
                                oauthRequest.getParam(REQUEST_URI))
                        .resultMessage("'request' and 'request_uri' parameters associated with the same " +
                                "authorization request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED
                ));
            }
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Both request and " +
                    "request_uri parameters can not be associated with the same authorization request.");
        }
    }

    private void handleRequestObject(OAuthMessage oAuthMessage, OAuthAuthzRequest oauthRequest,
                                     OAuth2Parameters parameters)
            throws RequestObjectException, InvalidRequestException {

        RequestObject requestObject = OIDCRequestObjectUtil.buildRequestObject(oauthRequest, parameters);
        if (requestObject == null) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Unable to build a valid Request " +
                    "Object from the authorization request.");
        }
            /*
              When the request parameter is used, the OpenID Connect request parameter values contained in the JWT
              supersede those passed using the OAuth 2.0 request syntax
             */
        boolean isFapiConformant = isFapiConformant(oAuthMessage.getClientId());
        // If FAPI conformant, claims outside request object should be ignored.
        overrideAuthzParameters(oAuthMessage, parameters, oauthRequest.getParam(REQUEST),
                oauthRequest.getParam(REQUEST_URI), requestObject, isFapiConformant);

        // If the redirect uri was not given in auth request the registered redirect uri will be available here,
        // so validating if the registered redirect uri is a single uri that can be properly redirected.
        if (StringUtils.isBlank(parameters.getRedirectURI()) ||
                StringUtils.startsWith(parameters.getRedirectURI(), REGEX_PATTERN)) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                        .resultMessage("Redirect URI is not present in the authorization request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            throw new InvalidRequestException(
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.INVALID_REDIRECT_URI,
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REDIRECT_URI);
        }
        persistRequestObject(parameters, requestObject);
    }

    private void overrideAuthzParameters(OAuthMessage oAuthMessage, OAuth2Parameters params,
                                         String requestParameterValue,
                                         String requestURIParameterValue, RequestObject requestObject,
                                         boolean ignoreClaimsOutsideRequestObject) {

        if (StringUtils.isNotBlank(requestParameterValue) || StringUtils.isNotBlank(requestURIParameterValue)) {
            replaceIfPresent(requestObject, REDIRECT_URI, params::setRedirectURI, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, NONCE, params::setNonce, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, STATE, params::setState, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, DISPLAY, params::setDisplay, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, RESPONSE_MODE, params::setResponseMode, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, LOGIN_HINT, params::setLoginHint, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, ID_TOKEN_HINT, params::setIDTokenHint, ignoreClaimsOutsideRequestObject);
            replaceIfPresent(requestObject, PROMPT, params::setPrompt, ignoreClaimsOutsideRequestObject);

            if (requestObject.getClaim(CLAIMS) instanceof net.minidev.json.JSONObject) {
                // Claims in the request object is in the type of net.minidev.json.JSONObject,
                // hence retrieving claims as a JSONObject
                net.minidev.json.JSONObject claims = (net.minidev.json.JSONObject) requestObject.getClaim(CLAIMS);
                params.setEssentialClaims(claims.toJSONString());
            }

            if (isPkceSupportEnabled()) {
                // If code_challenge and code_challenge_method is sent inside the request object then add them to
                // Oauth2 parameters.
                replaceIfPresent(requestObject, CODE_CHALLENGE, params::setPkceCodeChallenge, false);
                replaceIfPresent(requestObject, CODE_CHALLENGE_METHOD, params::setPkceCodeChallengeMethod, false);
            }

            if (StringUtils.isNotEmpty(requestObject.getClaimValue(SCOPE))) {
                String scopeString = requestObject.getClaimValue(SCOPE);
                params.setScopes(new HashSet<>(Arrays.asList(scopeString.split(SPACE_SEPARATOR))));
            }
            if (StringUtils.isNotEmpty(requestObject.getClaimValue(MAX_AGE))) {
                params.setMaxAge(Integer.parseInt(requestObject.getClaimValue(MAX_AGE)));
            }
            if (StringUtils.isNotEmpty(requestObject.getClaimValue(AUTH_TIME))) {
                params.setAuthTime(Long.parseLong(requestObject.getClaimValue(AUTH_TIME)));
            }
            if (StringUtils.isNotEmpty(requestObject.getClaimValue(ACR_VALUES))) {
                String acrString = requestObject.getClaimValue(ACR_VALUES);
                params.setACRValues(new LinkedHashSet<>(Arrays.asList(acrString.split(COMMA_SEPARATOR))));
                oAuthMessage.getRequest().setAttribute(ACR_VALUES,
                        new ArrayList<>(Arrays.asList(acrString.split(COMMA_SEPARATOR))));
            } else {
                List<String> acrRequestedValues = getAcrValues(requestObject);
                if (CollectionUtils.isNotEmpty(acrRequestedValues)) {
                    oAuthMessage.getRequest().setAttribute(ACR_VALUES, acrRequestedValues);
                }
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.OVERRIDE_AUTHZ_PARAMS)
                        .resultMessage("Successfully overridden the parameters in authorization request with the " +
                                "parameters available in request object.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
            }
        }
    }

    /**
     * To get the value(s) for "acr" from request object.
     *
     * @param requestObject {@link RequestObject}
     * @return list of acr value(s)
     */
    private List<String> getAcrValues(RequestObject requestObject) {

        List<String> acrRequestedValues = null;
        if (requestObject != null) {
            Map<String, List<RequestedClaim>> requestedClaims = requestObject.getRequestedClaims();
            List<RequestedClaim> requestedClaimsForIdToken = requestedClaims.get(OIDCConstants.ID_TOKEN);
            if (CollectionUtils.isNotEmpty(requestedClaimsForIdToken)) {
                for (RequestedClaim requestedClaim : requestedClaimsForIdToken) {
                    if (OAuthConstants.ACR.equalsIgnoreCase(requestedClaim.getName()) && requestedClaim.isEssential()) {
                        acrRequestedValues = requestedClaim.getValues();
                        if (CollectionUtils.isEmpty(acrRequestedValues) && StringUtils
                                .isNotEmpty(requestedClaim.getValue())) {
                            acrRequestedValues = Collections.singletonList(requestedClaim.getValue());
                        }
                        break;
                    }
                }
            }
        }
        return acrRequestedValues;
    }

    private void replaceIfPresent(RequestObject requestObject, String claim, Consumer<String> consumer,
                                  boolean ignoreClaimsOutsideRequestObject) {

        String claimValue = requestObject.getClaimValue(claim);
        if (StringUtils.isNotEmpty(claimValue)) {
            consumer.accept(claimValue);
        } else if (ignoreClaimsOutsideRequestObject) {
            consumer.accept(null);
        }
    }

    private static boolean isRequestUri(OAuthAuthzRequest oAuthAuthzRequest) {

        String param = oAuthAuthzRequest.getParam(REQUEST_URI);
        return StringUtils.isNotBlank(param);
    }

    private static boolean isRequestParameter(OAuthAuthzRequest oAuthAuthzRequest) {

        String param = oAuthAuthzRequest.getParam(REQUEST);
        return StringUtils.isNotBlank(param);
    }

    private OAuth2ClientValidationResponseDTO validateClient(OAuthMessage oAuthMessage) {

        return getOAuth2Service().validateClientInfo(oAuthMessage.getRequest());
    }

    /**
     * Return ServiceProvider for the given clientId
     *
     * @param clientId clientId
     * @return ServiceProvider ServiceProvider
     * @throws OAuthSystemException if couldn't retrieve ServiceProvider Information
     */
    private ServiceProvider getServiceProvider(String clientId) throws OAuthSystemException {

        try {
            return OAuth2Util.getServiceProvider(clientId);
        } catch (IdentityOAuth2ClientException e) {
            String msg = "Couldn't retrieve Service Provider for clientId: " + clientId;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new OAuthSystemException(msg, e);
        } catch (IdentityOAuth2Exception e) {
            String msg = "Couldn't retrieve Service Provider for clientId: " + clientId;
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
    private String doUserAuthorization(OAuthMessage oAuthMessage, String sessionDataKeyFromLogin,
                                       OIDCSessionState sessionState, AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException, ConsentHandlingFailedException, OAuthProblemException {

        OAuth2Parameters oauth2Params = getOauth2Params(oAuthMessage);
        AuthenticatedUser authenticatedUser = getLoggedInUser(oAuthMessage);

        /* Here we validate all scopes before user consent to prevent invalidate scopes prompt for consent in the
        consent page. */
        HttpRequestHeaderHandler httpRequestHeaderHandler = new HttpRequestHeaderHandler(oAuthMessage.getRequest());
        OAuth2AuthorizeReqDTO authzReqDTO =
                buildAuthRequest(oauth2Params, oAuthMessage.getSessionDataCacheEntry(), httpRequestHeaderHandler,
                        oAuthMessage.getRequest());
        try {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_SCOPES_BEFORE_CONSENT);
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .inputParam(LogConstants.InputKeys.APPLICATION_NAME, oauth2Params.getApplicationName())
                        .inputParam("scopes to be validate", oauth2Params.getScopes())
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .resultMessage("Scope validation started.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            validateScopesBeforeConsent(oAuthMessage, oauth2Params, authzReqDTO);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_SCOPES_BEFORE_CONSENT);
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .inputParam(LogConstants.InputKeys.APPLICATION_NAME, oauth2Params.getApplicationName())
                        .inputParam("scopes after validation", oauth2Params.getScopes())
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .resultMessage("Scope validation completed.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IdentityOAuth2UnauthorizedScopeException e) {
            OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
            authorizeRespDTO.setErrorCode(e.getErrorCode());
            authorizeRespDTO.setErrorMsg(e.getMessage());
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            authorizationResponseDTO.setError(HttpServletResponse.SC_FOUND, e.getMessage(), e.getErrorCode());
            return handleAuthorizationFailureBeforeConsent(oAuthMessage, oauth2Params, authorizeRespDTO);
        }

        boolean hasUserApproved = isUserAlreadyApproved(oauth2Params, authenticatedUser);

        if (hasPromptContainsConsent(oauth2Params)) {
            // Remove any existing consents.
            String clientId = oauth2Params.getClientId();
            OpenIDConnectUserRPStore.getInstance().removeConsentForUser(authenticatedUser, clientId);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.REMOVE_USER_CONSENT);
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .inputParam(OAuthConstants.LogConstants.InputKeys.PROMPT, oauth2Params.getPrompt())
                        .resultMessage("'prompt' contains consent. Hence existing user consent is revoked.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                try {
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, authenticatedUser.getUserId());
                } catch (UserIdNotFoundException e) {
                    if (StringUtils.isNotBlank(authenticatedUser.getAuthenticatedSubjectIdentifier())) {
                        diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                LoggerUtils.getMaskedContent(authenticatedUser.getAuthenticatedSubjectIdentifier())
                                : authenticatedUser.getAuthenticatedSubjectIdentifier());
                    }
                }
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            if (log.isDebugEnabled()) {
                log.debug("Prompt parameter contains 'consent'. Existing consents for user: "
                        + authenticatedUser.toFullQualifiedUsername() + " for oauth app with clientId: " + clientId
                        + " are revoked and user will be prompted to give consent again.");
            }
            // Need to prompt for consent and get user consent for claims as well.
            return promptUserForConsent(sessionDataKeyFromLogin, oauth2Params, authenticatedUser, true,
                    oAuthMessage, authorizationResponseDTO);
        } else if (isPromptNone(oauth2Params)) {
            return handlePromptNone(oAuthMessage, sessionState, oauth2Params, authenticatedUser, hasUserApproved,
                    authorizationResponseDTO);
        } else if (isPromptLogin(oauth2Params) || isPromptParamsNotPresent(oauth2Params)
                || isPromptSelectAccount(oauth2Params)) {
            /*
             * IS does not currently support multiple logged-in sessions.
             * Therefore, gracefully handling prompt=select_account by mimicking the behaviour of a request that does
             * not have a prompt param.
             */
            return handleConsent(oAuthMessage, sessionDataKeyFromLogin, sessionState, oauth2Params, authenticatedUser,
                    hasUserApproved, authorizationResponseDTO);
        } else {
            return StringUtils.EMPTY;
        }
    }

    /**
     * Validate scopes before consent page.
     *
     * @param  oAuthMessage oAuthMessage
     * @param oauth2Params oauth2Params
     */
    private void validateScopesBeforeConsent(OAuthMessage oAuthMessage, OAuth2Parameters oauth2Params,
                                             OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2UnauthorizedScopeException, OAuthSystemException {

        try {
            OAuthAuthzReqMessageContext authzReqMsgCtx = getOAuth2Service().validateScopesBeforeConsent(authzReqDTO);
            // Here we need to preserve the OAuthAuthzReqMessageContext to preserve backward compatibility as
            // extensions might add information to context that needs to be available when authorizing
            // (issue code, token) the request later.
            oAuthMessage.getSessionDataCacheEntry().setAuthzReqMsgCtx(authzReqMsgCtx);
            if (ArrayUtils.isEmpty(authzReqMsgCtx.getApprovedScope())) {
                oauth2Params.setScopes(new HashSet<>(Collections.emptyList()));
            } else {
                oauth2Params.setScopes(new HashSet<>(Arrays.asList(authzReqMsgCtx.getApprovedScope())));
            }
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error occurred while validating requested scopes.", e);
            throw new OAuthSystemException("Error occurred while validating requested scopes", e);
        }
    }

    private OAuth2Parameters getOauth2Params(OAuthMessage oAuthMessage) {

        if (oAuthMessage.getSessionDataCacheEntry() == null) {
            return null;
        }
        return oAuthMessage.getSessionDataCacheEntry().getoAuth2Parameters();
    }

    private AuthenticatedUser getLoggedInUser(OAuthMessage oAuthMessage) {

        return oAuthMessage.getSessionDataCacheEntry().getLoggedInUser();
    }

    private String handleConsent(OAuthMessage oAuthMessage, String sessionDataKey,
                                 OIDCSessionState sessionState, OAuth2Parameters oauth2Params,
                                 AuthenticatedUser authenticatedUser, boolean hasUserApproved, AuthorizationResponseDTO
                                         authorizationResponseDTO)
            throws OAuthSystemException, ConsentHandlingFailedException {

        if (isConsentSkipped(oauth2Params)) {
            sessionState.setAddSessionState(true);
            return handleUserConsent(oAuthMessage, APPROVE, sessionState, oauth2Params, authorizationResponseDTO);
        } else if (hasUserApproved) {
            return handleApproveAlwaysWithPromptForNewConsent(oAuthMessage, sessionState, oauth2Params,
                    authorizationResponseDTO);
        } else {
            return promptUserForConsent(sessionDataKey, oauth2Params, authenticatedUser, false,
                    oAuthMessage, authorizationResponseDTO);
        }
    }

    private boolean isPromptParamsNotPresent(OAuth2Parameters oauth2Params) {

        return StringUtils.isBlank(oauth2Params.getPrompt());
    }

    private boolean isPromptLogin(OAuth2Parameters oauth2Params) {

        return (OAuthConstants.Prompt.LOGIN).equals(oauth2Params.getPrompt());
    }

    private String promptUserForConsent(String sessionDataKey, OAuth2Parameters oauth2Params,
                                        AuthenticatedUser user, boolean ignoreExistingConsents,
                                        OAuthMessage oAuthMessage, AuthorizationResponseDTO authorizationResponseDTO)
            throws ConsentHandlingFailedException, OAuthSystemException {

        authorizationResponseDTO.setIsConsentRedirect(true);
        String clientId = oauth2Params.getClientId();
        String tenantDomain = oauth2Params.getTenantDomain();

        String preConsent;
        if (ignoreExistingConsents) {
            // Ignore existing consents and prompt for all SP mandatory and requested claims.
            if (log.isDebugEnabled()) {
                log.debug("Initiating consent handling for user: " + user.toFullQualifiedUsername() + " for client_id: "
                        + clientId + "  of tenantDomain: " + tenantDomain + " excluding existing consents.");
            }
            preConsent = handlePreConsentExcludingExistingConsents(oauth2Params, user);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Initiating consent handling for user: " + user.toFullQualifiedUsername() + " for client_id: "
                        + clientId + "  of tenantDomain: " + tenantDomain + " including existing consents.");
            }
            preConsent = handlePreConsentIncludingExistingConsents(oauth2Params, user);
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.PROMPT_CONSENT_PAGE)
                    .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                    .resultMessage("Redirecting to Consent Page URL.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
        }
        return getUserConsentURL(sessionDataKey, oauth2Params, user, preConsent, oAuthMessage);
    }

    private String handlePromptNone(OAuthMessage oAuthMessage,
                                    OIDCSessionState sessionState,
                                    OAuth2Parameters oauth2Params,
                                    AuthenticatedUser authenticatedUser,
                                    boolean hasUserApproved, AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException,
            ConsentHandlingFailedException, OAuthProblemException {

        if (isUserSessionNotExists(authenticatedUser)) {
            // prompt=none but user is not logged in. Therefore throw error according to
            // http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            sessionState.setAddSessionState(true);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_USER_SESSION)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                        .resultMessage("Request with 'prompt=none' but user session does not exist.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            throw OAuthProblemException.error(OAuth2ErrorCodes.LOGIN_REQUIRED,
                    "Request with \'prompt=none\' but user session does not exist");
        }

        if (isIdTokenHintExists(oauth2Params)) {
            // prompt=none with id_token_hint parameter with an id_token indicating a previously authenticated session.
            return handleIdTokenHint(oAuthMessage, sessionState, oauth2Params, authenticatedUser, hasUserApproved,
                    authorizationResponseDTO);
        } else {
            // Handle previously approved consent for prompt=none scenario
            return handlePreviouslyApprovedConsent(oAuthMessage, sessionState, oauth2Params, hasUserApproved,
                    authorizationResponseDTO);
        }
    }

    /**
     * Consent page can be skipped by setting OpenIDConnect configuration or by setting SP property.
     *
     * @param oauth2Params oauth2 params related to this request.
     * @return A boolean stating whether consent page is skipped or not.
     */
    private boolean isConsentSkipped(OAuth2Parameters oauth2Params) throws OAuthSystemException {

        ServiceProvider serviceProvider = getServiceProvider(oauth2Params.getClientId());
        boolean isApiBasedAuthenticationFlow = isApiBasedAuthenticationFlow(oauth2Params);

        // Consent handling is skipped for API based authentication flow.
        return getOAuthServerConfiguration().getOpenIDConnectSkipeUserConsentConfig()
                || FrameworkUtils.isConsentPageSkippedForSP(serviceProvider) || isApiBasedAuthenticationFlow;
    }

    private boolean isConsentFromUserRequired(String preConsentQueryParams) {

        return StringUtils.isNotBlank(preConsentQueryParams);
    }

    private String handlePreConsentExcludingExistingConsents(OAuth2Parameters oauth2Params, AuthenticatedUser user)
            throws ConsentHandlingFailedException, OAuthSystemException {

        return handlePreConsent(oauth2Params, user, false);
    }

    private String handlePreConsentIncludingExistingConsents(OAuth2Parameters oauth2Params, AuthenticatedUser user)
            throws ConsentHandlingFailedException, OAuthSystemException {

        return handlePreConsent(oauth2Params, user, true);
    }

    /**
     * Handle user consent from claims that will be shared in OIDC responses. Claims that require consent will be
     * sent to the consent page as query params. Consent page will interpret the query params and prompt the user
     * for consent.
     *
     * @param oauth2Params
     * @param user                Authenticated User
     * @param useExistingConsents Whether to consider existing user consents
     * @return
     * @throws ConsentHandlingFailedException
     * @throws OAuthSystemException
     */
    private String handlePreConsent(OAuth2Parameters oauth2Params, AuthenticatedUser user, boolean useExistingConsents)
            throws ConsentHandlingFailedException, OAuthSystemException {

        String additionalQueryParam = StringUtils.EMPTY;
        String clientId = oauth2Params.getClientId();
        String spTenantDomain = oauth2Params.getTenantDomain();
        ServiceProvider serviceProvider = getServiceProvider(clientId);

        Map<String, Object> params = new HashMap<>();
        params.put(LogConstants.InputKeys.CLIENT_ID, clientId);
        try {
            params.put(LogConstants.InputKeys.USER_ID, user.getUserId());
        } catch (UserIdNotFoundException e) {
            if (StringUtils.isNotBlank(user.getAuthenticatedSubjectIdentifier())) {
                params.put(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(
                        user.getAuthenticatedSubjectIdentifier()) : user.getAuthenticatedSubjectIdentifier());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Initiating consent handling for user: " + user.toFullQualifiedUsername() + " for client_id: "
                    + clientId + " of tenantDomain: " + spTenantDomain);
        }

        if (isConsentHandlingFromFrameworkSkipped(oauth2Params)) {
            if (log.isDebugEnabled()) {
                log.debug("Consent handling from framework skipped for client_id: " + clientId + " of tenantDomain: "
                        + spTenantDomain + " for user: " + user.toFullQualifiedUsername());
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                params.put("skip consent", "true");
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.GENERATE_CONSENT_CLAIMS);
                diagnosticLogBuilder.inputParams(params)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultMessage("'skipConsent' is enabled for the OAuth client. Hence consent claims not " +
                                "generated.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return StringUtils.EMPTY;
        }

        DiagnosticLog.DiagnosticLogBuilder errorDiagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            errorDiagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.GENERATE_CONSENT_CLAIMS)
                    .inputParams(params)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        try {
            ConsentClaimsData claimsForApproval = getConsentRequiredClaims(user, serviceProvider, useExistingConsents);
            if (claimsForApproval != null) {
                String requestClaimsQueryParam = null;
                // Get the mandatory claims and append as query param.
                String mandatoryClaimsQueryParam = null;
                // Remove the claims which dont have values given by the user.
                claimsForApproval.setRequestedClaims(
                        removeConsentRequestedNullUserAttributes(claimsForApproval.getRequestedClaims(),
                                user.getUserAttributes(), spTenantDomain));
                List<ClaimMetaData> requestedOidcClaimsList =
                        getRequestedOidcClaimsList(claimsForApproval, oauth2Params, spTenantDomain);
                if (CollectionUtils.isNotEmpty(requestedOidcClaimsList)) {
                    requestClaimsQueryParam = REQUESTED_CLAIMS + "=" +
                            buildConsentClaimString(requestedOidcClaimsList);
                }

                if (CollectionUtils.isNotEmpty(claimsForApproval.getMandatoryClaims())) {
                    mandatoryClaimsQueryParam = MANDATORY_CLAIMS + "=" +
                            buildConsentClaimString(claimsForApproval.getMandatoryClaims());
                }
                additionalQueryParam = buildQueryParamString(requestClaimsQueryParam, mandatoryClaimsQueryParam);
            }
        } catch (UnsupportedEncodingException | SSOConsentServiceException e) {
            String username = LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(
                    user.toFullQualifiedUsername()) : user.toFullQualifiedUsername();
            String msg = "Error while handling user consent for claim for user: " + username + " for client_id: " +
                    clientId + " of tenantDomain: " + spTenantDomain;
            if (errorDiagnosticLogBuilder != null) {
                // errorDiagnosticLogBuilder is not null only if diagnostic logs are enabled.
                errorDiagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage(msg);
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
            throw new ConsentHandlingFailedException(msg, e);
        } catch (ClaimMetadataException e) {
            if (errorDiagnosticLogBuilder != null) {
                // errorDiagnosticLogBuilder is not null only if diagnostic logs are enabled.
                errorDiagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("System error occurred.");
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
            throw new ConsentHandlingFailedException("Error while getting claim mappings for " + OIDC_DIALECT, e);
        } catch (RequestObjectException e) {
            if (errorDiagnosticLogBuilder != null) {
                // errorDiagnosticLogBuilder is not null only if diagnostic logs are enabled.
                errorDiagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("System error occurred.");
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
            throw new ConsentHandlingFailedException("Error while getting essential claims for the session data key " +
                    ": " + oauth2Params.getSessionDataKey(), e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Additional Query param to be sent to consent page for user: " + user.toFullQualifiedUsername() +
                    " for client_id: " + clientId + " is '" + additionalQueryParam + "'");
        }

        return additionalQueryParam;
    }

    /**
     * Filter out the requested claims with the user attributes.
     *
     * @param requestedClaims List of requested claims metadata.
     * @param userAttributes  Authenticated users' attributes.
     * @param spTenantDomain  Tenant domain.
     * @return Filtered claims with user attributes.
     * @throws ClaimMetadataException If an error occurred while getting claim mappings.
     */
    private List<ClaimMetaData> removeConsentRequestedNullUserAttributes(List<ClaimMetaData> requestedClaims,
                                                                         Map<ClaimMapping, String> userAttributes,
                                                                         String spTenantDomain)
            throws ClaimMetadataException {

        List<String> localClaims = new ArrayList<>();
        List<ClaimMetaData> filteredRequestedClaims = new ArrayList<>();
        List<String> localClaimUris = new ArrayList<>();

        if (requestedClaims != null && userAttributes != null) {
            for (Map.Entry<ClaimMapping, String> attribute : userAttributes.entrySet()) {
                localClaims.add(attribute.getKey().getLocalClaim().getClaimUri());
            }
            if (CollectionUtils.isNotEmpty(localClaims)) {
                Set<ExternalClaim> externalClaimSetOfOidcClaims = ClaimMetadataHandler.getInstance()
                        .getMappingsFromOtherDialectToCarbon(OIDC_DIALECT, new HashSet<String>(localClaims),
                                spTenantDomain);
                for (ExternalClaim externalClaim : externalClaimSetOfOidcClaims) {
                    localClaimUris.add(externalClaim.getMappedLocalClaim());
                }
            }
            for (ClaimMetaData claimMetaData : requestedClaims) {
                if (localClaimUris.contains(claimMetaData.getClaimUri())) {
                    filteredRequestedClaims.add(claimMetaData);
                }
            }
        }
        return filteredRequestedClaims;
    }

    /**
     * Filter requested claims based on OIDC claims and return the claims which includes in OIDC.
     *
     * @param claimsForApproval         Consent required claims.
     * @param oauth2Params              OAuth parameters.
     * @param spTenantDomain            Tenant domain.
     * @return                          Requested OIDC claim list.
     * @throws RequestObjectException   If an error occurred while getting essential claims for the session data key.
     * @throws ClaimMetadataException   If an error occurred while getting claim mappings.
     */
    private List<ClaimMetaData> getRequestedOidcClaimsList(ConsentClaimsData claimsForApproval,
                                                           OAuth2Parameters oauth2Params, String spTenantDomain)
            throws RequestObjectException, ClaimMetadataException {

        List<ClaimMetaData> requestedOidcClaimsList = new ArrayList<>();
        List<String> localClaimsOfOidcClaims = new ArrayList<>();
        List<String> localClaimsOfEssentialClaims = new ArrayList<>();

        // Get the claims uri list of all the requested scopes. Eg:- country, email.
        List<String> claimListOfScopes =
                openIDConnectClaimFilter.getClaimsFilteredByOIDCScopes(oauth2Params.getScopes(), spTenantDomain);

        List<String> essentialRequestedClaims = new ArrayList<>();

        if (oauth2Params.isRequestObjectFlow()) {
            // Get the requested claims came through request object.
            List<RequestedClaim> requestedClaimsOfIdToken = EndpointUtil.getRequestObjectService()
                    .getRequestedClaimsForSessionDataKey(oauth2Params.getSessionDataKey(), false);

            List<RequestedClaim> requestedClaimsOfUserInfo = EndpointUtil.getRequestObjectService()
                    .getRequestedClaimsForSessionDataKey(oauth2Params.getSessionDataKey(), true);


            // Get the list of id token's essential claims.
            for (RequestedClaim requestedClaim : requestedClaimsOfIdToken) {
                if (requestedClaim.isEssential()) {
                    essentialRequestedClaims.add(requestedClaim.getName());
                }
            }

            // Get the list of user info's essential claims.
            for (RequestedClaim requestedClaim : requestedClaimsOfUserInfo) {
                if (requestedClaim.isEssential()) {
                    essentialRequestedClaims.add(requestedClaim.getName());
                }
            }
        }

        // Add user info's essential claims requested using claims parameter. Claims for id_token are skipped
        // since claims parameter does not support id_token yet.
        if (oauth2Params.getEssentialClaims() != null) {
            essentialRequestedClaims.addAll(OAuth2Util.getEssentialClaims(oauth2Params.getEssentialClaims(),
                    USERINFO));
        }

        if (CollectionUtils.isNotEmpty(claimListOfScopes)) {
            // Get the external claims relevant to all oidc scope claims and essential claims.
            Set<ExternalClaim> externalClaimSetOfOidcClaims = ClaimMetadataHandler.getInstance()
                    .getMappingsFromOtherDialectToCarbon(OIDC_DIALECT, new HashSet<String>(claimListOfScopes),
                            spTenantDomain);

            /* Get the locally mapped claims for all the external claims of requested scope and essential claims.
            Eg:- http://wso2.org/claims/country, http://wso2.org/claims/emailaddress
             */
            for (ExternalClaim externalClaim : externalClaimSetOfOidcClaims) {
                localClaimsOfOidcClaims.add(externalClaim.getMappedLocalClaim());
            }
        }

        if (CollectionUtils.isNotEmpty(essentialRequestedClaims)) {
            // Get the external claims relevant to all essential requested claims.
            Set<ExternalClaim> externalClaimSetOfEssentialClaims = ClaimMetadataHandler.getInstance()
                    .getMappingsFromOtherDialectToCarbon(OIDC_DIALECT, new HashSet<String>(essentialRequestedClaims),
                            spTenantDomain);

            /* Get the locally mapped claims for all the external claims of essential claims.
            Eg:- http://wso2.org/claims/country, http://wso2.org/claims/emailaddress
             */
            for (ExternalClaim externalClaim : externalClaimSetOfEssentialClaims) {
                localClaimsOfEssentialClaims.add(externalClaim.getMappedLocalClaim());
            }
        }

        /* Check whether the local claim of oidc claims contains the requested claims or essential claims of
         request object contains the requested claims, If it contains add it as requested claim.
         */
        for (ClaimMetaData claimMetaData : claimsForApproval.getRequestedClaims()) {
            if (localClaimsOfOidcClaims.contains(claimMetaData.getClaimUri()) ||
                    localClaimsOfEssentialClaims.contains(claimMetaData.getClaimUri())) {
                requestedOidcClaimsList.add(claimMetaData);
            }
        }

        return requestedOidcClaimsList;
    }

    private ConsentClaimsData getConsentRequiredClaims(AuthenticatedUser user,
                                                       ServiceProvider serviceProvider,
                                                       boolean useExistingConsents) throws SSOConsentServiceException {

        if (useExistingConsents) {
            return getSSOConsentService().getConsentRequiredClaimsWithExistingConsents(serviceProvider, user);
        } else {
            return getSSOConsentService().getConsentRequiredClaimsWithoutExistingConsents(serviceProvider, user);
        }
    }

    private String buildQueryParamString(String firstQueryParam, String secondQueryParam) {

        StringJoiner joiner = new StringJoiner("&");
        if (StringUtils.isNotBlank(firstQueryParam)) {
            joiner.add(firstQueryParam);
        }

        if (StringUtils.isNotBlank(secondQueryParam)) {
            joiner.add(secondQueryParam);
        }

        return joiner.toString();
    }

    private String buildConsentClaimString(List<ClaimMetaData> consentClaimsData) throws UnsupportedEncodingException {

        StringJoiner joiner = new StringJoiner(",");
        for (ClaimMetaData claimMetaData : consentClaimsData) {
            joiner.add(claimMetaData.getId() + "_" + claimMetaData.getDisplayName());
        }
        return URLEncoder.encode(joiner.toString(), StandardCharsets.UTF_8.toString());
    }

    private String handleIdTokenHint(OAuthMessage oAuthMessage,
                                     OIDCSessionState sessionState,
                                     OAuth2Parameters oauth2Params,
                                     AuthenticatedUser loggedInUser,
                                     boolean hasUserApproved, AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException,
            ConsentHandlingFailedException, OAuthProblemException {

        sessionState.setAddSessionState(true);
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_ID_TOKEN_HINT);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.PROMPT, oauth2Params.getPrompt())
                    .inputParam("id token hint", oauth2Params.getIDTokenHint())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        try {
            String idTokenHint = oauth2Params.getIDTokenHint();
            if (isIdTokenValidationFailed(idTokenHint)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                    diagnosticLogBuilder.resultMessage("ID token signature validation failed.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw OAuthProblemException.error(OAuth2ErrorCodes.ACCESS_DENIED,
                        "Request with \'id_token_hint=" + idTokenHint +
                                "\' but ID Token validation failed");
            }

            String loggedInUserSubjectId = loggedInUser.getAuthenticatedSubjectIdentifier();
            if (isIdTokenSubjectEqualsToLoggedInUser(loggedInUserSubjectId, idTokenHint)) {
                return handlePreviouslyApprovedConsent(oAuthMessage, sessionState, oauth2Params, hasUserApproved,
                        authorizationResponseDTO);
            } else {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                    diagnosticLogBuilder.resultMessage("ID token 'sub' does not match with the authenticated user " +
                            "subject identifier.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw OAuthProblemException.error(OAuth2ErrorCodes.LOGIN_REQUIRED,
                        "Request with \'id_token_hint=" + idTokenHint +
                                "\' but user has denied the consent");
            }
        } catch (ParseException e) {
            String msg = "Error while getting clientId from the IdTokenHint.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("System error occurred.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw OAuthProblemException.error(OAuth2ErrorCodes.ACCESS_DENIED, msg);
        }
    }

    private String handlePreviouslyApprovedConsent(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                                   OAuth2Parameters oauth2Params, boolean hasUserApproved,
                                                   AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException, ConsentHandlingFailedException, OAuthProblemException {

        sessionState.setAddSessionState(true);
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_EXISTING_CONSENT);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.PROMPT, oauth2Params.getPrompt())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        if (isConsentSkipped(oauth2Params)) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null only if diagnostic logs are disabled.
                diagnosticLogBuilder.configParam("skip consent", "true")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .resultMessage("'prompt' is set to none, and consent is disabled for the OAuth client.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return handleUserConsent(oAuthMessage, APPROVE, sessionState, oauth2Params, authorizationResponseDTO);
        } else if (hasUserApproved) {
            return handleApprovedAlwaysWithoutPromptingForNewConsent(oAuthMessage, sessionState, oauth2Params,
                    authorizationResponseDTO);
        } else {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null only if diagnostic logs are disabled.
                diagnosticLogBuilder.configParam("skip consent", "false")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .resultMessage("'prompt' is set to none, but required consent not found.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw OAuthProblemException.error(OAuth2ErrorCodes.CONSENT_REQUIRED,
                    "Required consent not found");
        }
    }

    private String handleApprovedAlwaysWithoutPromptingForNewConsent(OAuthMessage oAuthMessage,
                                                                     OIDCSessionState sessionState,
                                                                     OAuth2Parameters oauth2Params,
                                                                     AuthorizationResponseDTO authorizationResponseDTO)
            throws ConsentHandlingFailedException, OAuthSystemException, OAuthProblemException {

        AuthenticatedUser authenticatedUser = getLoggedInUser(oAuthMessage);
        String preConsent = handlePreConsentIncludingExistingConsents(oauth2Params, authenticatedUser);

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_EXISTING_CONSENT);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oauth2Params.getClientId())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.PROMPT, oauth2Params.getPrompt())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        if (isConsentFromUserRequired(preConsent)) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null only if diagnostic logs are disabled.
                diagnosticLogBuilder.configParam("consent required claims", preConsent)
                        .resultMessage("'prompt' is set to none, and existing user consent is incomplete for " +
                                "the OAuth client.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw OAuthProblemException.error(OAuth2ErrorCodes.CONSENT_REQUIRED,
                    "Consent approved always without prompting for new consent");
        } else {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null only if diagnostic logs are disabled.
                diagnosticLogBuilder.resultMessage("'prompt' is set to none, and existing user consent found for " +
                        "the OAuth client.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return handleUserConsent(oAuthMessage, APPROVE, sessionState, oauth2Params, authorizationResponseDTO);
        }
    }

    private String handleApproveAlwaysWithPromptForNewConsent(OAuthMessage oAuthMessage, OIDCSessionState sessionState,
                                                              OAuth2Parameters oauth2Params, AuthorizationResponseDTO
                                                                      authorizationResponseDTO)
            throws ConsentHandlingFailedException, OAuthSystemException {

        AuthenticatedUser authenticatedUser = getLoggedInUser(oAuthMessage);
        String preConsent = handlePreConsentIncludingExistingConsents(oauth2Params, authenticatedUser);

        if (isConsentFromUserRequired(preConsent)) {
            String sessionDataKeyFromLogin = getSessionDataKeyFromLogin(oAuthMessage);
            preConsent = buildQueryParamString(preConsent, USER_CLAIMS_CONSENT_ONLY + "=true");
            authorizationResponseDTO.setIsConsentRedirect(true);
            return getUserConsentURL(sessionDataKeyFromLogin, oauth2Params,
                    authenticatedUser, preConsent, oAuthMessage);
        } else {
            sessionState.setAddSessionState(true);
            return handleUserConsent(oAuthMessage, APPROVE, sessionState, oauth2Params, authorizationResponseDTO);
        }
    }

    private boolean isIdTokenHintExists(OAuth2Parameters oauth2Params) {

        return StringUtils.isNotEmpty(oauth2Params.getIDTokenHint());
    }

    private boolean isUserAlreadyApproved(OAuth2Parameters oauth2Params, AuthenticatedUser user)
            throws OAuthSystemException {

        try {
            return EndpointUtil.isUserAlreadyConsentedForOAuthScopes(user, oauth2Params);
        } catch (IdentityOAuth2ScopeException | IdentityOAuthAdminException e) {
            throw new OAuthSystemException("Error occurred while checking user has already approved the consent " +
                    "required OAuth scopes.", e);
        }
    }

    private boolean isIdTokenSubjectEqualsToLoggedInUser(String loggedInUser, String idTokenHint)
            throws ParseException {

        String subjectValue = getSubjectFromIdToken(idTokenHint);
        return StringUtils.isNotEmpty(loggedInUser) && loggedInUser.equals(subjectValue);
    }

    private String getSubjectFromIdToken(String idTokenHint) throws ParseException {

        return SignedJWT.parse(idTokenHint).getJWTClaimsSet().getSubject();
    }

    private boolean isIdTokenValidationFailed(String idTokenHint) {

        if (!OAuth2Util.validateIdToken(idTokenHint)) {
            if (log.isDebugEnabled()) {
                log.debug("ID token signature validation failed for the IDTokenHint: " + idTokenHint);
            }
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

    private boolean hasPromptContainsConsent(OAuth2Parameters oauth2Params) {

        String[] prompts = null;
        if (StringUtils.isNotBlank(oauth2Params.getPrompt())) {
            prompts = oauth2Params.getPrompt().trim().split("\\s");
        }
        return prompts != null && Arrays.asList(prompts).contains(OAuthConstants.Prompt.CONSENT);
    }

    private String getUserConsentURL(String sessionDataKey,
                                     OAuth2Parameters oauth2Params,
                                     AuthenticatedUser authenticatedUser,
                                     String additionalQueryParams, OAuthMessage oAuthMessage)
            throws OAuthSystemException {

        String loggedInUser = authenticatedUser.getAuthenticatedSubjectIdentifier();
        return EndpointUtil.getUserConsentURL(oauth2Params, loggedInUser, sessionDataKey, oAuthMessage,
                additionalQueryParams);

    }

    /**
     * Here we set the authenticated user to the session data
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return
     */
    private OAuth2AuthorizeRespDTO authorize(OAuthAuthzReqMessageContext authzReqMsgCtx) {

        return getOAuth2Service().authorize(authzReqMsgCtx);
    }

    private OAuth2AuthorizeReqDTO buildAuthRequest(OAuth2Parameters oauth2Params, SessionDataCacheEntry
            sessionDataCacheEntry, HttpRequestHeaderHandler httpRequestHeaderHandler, HttpServletRequest request) {

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
        authzReqDTO.setAuthTime(sessionDataCacheEntry.getAuthTime());
        authzReqDTO.setMaxAge(oauth2Params.getMaxAge());
        authzReqDTO.setEssentialClaims(oauth2Params.getEssentialClaims());
        authzReqDTO.setSessionDataKey(oauth2Params.getSessionDataKey());
        authzReqDTO.setRequestObjectFlow(oauth2Params.isRequestObjectFlow());
        authzReqDTO.setIdpSessionIdentifier(sessionDataCacheEntry.getSessionContextIdentifier());
        authzReqDTO.setLoggedInTenantDomain(oauth2Params.getLoginTenantDomain());
        authzReqDTO.setState(oauth2Params.getState());
        authzReqDTO.setHttpServletRequestWrapper(new HttpServletRequestWrapper(request));
        authzReqDTO.setRequestedSubjectId(oauth2Params.getRequestedSubjectId());
        authzReqDTO.setMappedRemoteClaims(sessionDataCacheEntry.getMappedRemoteClaims());

        if (sessionDataCacheEntry.getParamMap() != null && sessionDataCacheEntry.getParamMap().get(OAuthConstants
                .AMR) != null) {
            authzReqDTO.addProperty(OAuthConstants.AMR, sessionDataCacheEntry.getParamMap().get(OAuthConstants.AMR));
        }
        // Set Selected acr value.
        String[] sessionIds = sessionDataCacheEntry.getParamMap().get(FrameworkConstants.SESSION_DATA_KEY);
        if (ArrayUtils.isNotEmpty(sessionIds)) {
            String commonAuthSessionId = sessionIds[0];
            SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(commonAuthSessionId,
                    oauth2Params.getLoginTenantDomain());
            if (sessionContext != null && sessionContext.getSessionAuthHistory() != null) {
                authzReqDTO.setSelectedAcr(sessionContext.getSessionAuthHistory().getSelectedAcrValue());
            }
        }
        // Adding Httprequest headers and cookies in AuthzDTO.
        authzReqDTO.setHttpRequestHeaders(httpRequestHeaderHandler.getHttpRequestHeaders());
        authzReqDTO.setCookie(httpRequestHeaderHandler.getCookies());
        return authzReqDTO;
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
     * @return AuthenticationResult
     */
    private AuthenticationResult getAuthenticationResultFromRequest(HttpServletRequest request) {

        return (AuthenticationResult) request.getAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT);
    }

    private Response handleAuthFlowThroughFramework(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        try {
            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(oAuthMessage.getResponse());
            invokeCommonauthFlow(oAuthMessage, responseWrapper);
            return processAuthResponseFromFramework(oAuthMessage, responseWrapper);
        } catch (ServletException | IOException | URLBuilderException e) {
            log.error("Error occurred while sending request to authentication framework.");
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private Response processAuthResponseFromFramework(OAuthMessage oAuthMessage,
                                                      CommonAuthResponseWrapper responseWrapper)
            throws IOException, InvalidRequestParentException, URISyntaxException, URLBuilderException {

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

    private Response handleUnknownFlowState(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        oAuthMessage.getRequest().setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus
                .UNKNOWN);
        return authorize(oAuthMessage.getRequest(), oAuthMessage.getResponse());
    }

    private Response handleSuccessfullyCompletedFlow(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        return authorize(oAuthMessage.getRequest(), oAuthMessage.getResponse());
    }

    private boolean isFlowStateIncomplete(OAuthMessage oAuthMessage) {

        return AuthenticatorFlowStatus.INCOMPLETE.equals(oAuthMessage.getFlowStatus());
    }

    private Response handleIncompleteFlow(OAuthMessage oAuthMessage, CommonAuthResponseWrapper responseWrapper)
            throws IOException, URISyntaxException, URLBuilderException {

        if (responseWrapper.isRedirect()) {
            return Response.status(HttpServletResponse.SC_FOUND)
                    .location(buildURI(responseWrapper.getRedirectURL())).build();
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
    private Response handleAuthFlowThroughFramework(OAuthMessage oAuthMessage, String type, String redirectUrl)
            throws URISyntaxException, InvalidRequestParentException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HAND_OVER_TO_FRAMEWORK)
                    .resultMessage("Forward authorization request to framework for user authentication.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthMessage.getClientId())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        try {
            String sessionDataKey =
                    (String) oAuthMessage.getRequest().getAttribute(FrameworkConstants.SESSION_DATA_KEY);


            CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(oAuthMessage.getRequest());
            requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
            requestWrapper.setParameter(FrameworkConstants.RequestParams.TYPE, type);

            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(oAuthMessage.getResponse());

            if (isApiBasedAuthenticationFlow(oAuthMessage)) {
                // Marking the initial request as additional validation will be done from the auth service.
                requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_IS_INITIAL_API_BASED_AUTH_REQUEST, true);
                requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_RELYING_PARTY, oAuthMessage.getClientId());

                AuthenticationService authenticationService = new AuthenticationService();
                AuthServiceResponse authServiceResponse = authenticationService.
                        handleAuthentication(new AuthServiceRequest(requestWrapper, responseWrapper));
                // This is done to provide a way to propagate the auth service response to needed places.
                attachAuthServiceResponseToRequest(requestWrapper, authServiceResponse);
            } else {
                CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();
                commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);
            }

            Object attribute = oAuthMessage.getRequest().getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
            if (attribute != null) {
                if (attribute == AuthenticatorFlowStatus.INCOMPLETE) {

                    if (responseWrapper.isRedirect()) {
                        return Response.status(HttpServletResponse.SC_FOUND)
                                .location(buildURI(responseWrapper.getRedirectURL())).build();
                    } else {
                        return Response.status(HttpServletResponse.SC_OK).entity(responseWrapper.getContent()).build();
                    }
                } else {
                    try {
                        String serviceProviderId =
                                getServiceProvider(oAuthMessage.getRequest().getParameter(CLIENT_ID))
                                .getApplicationResourceId();
                        requestWrapper.setParameter(SERVICE_PROVIDER_ID, serviceProviderId);
                    } catch (Exception e) {
                        // The value is set to be used for branding purposes. Therefore, if an error occurs,
                        // the process should continue without breaking.
                        log.error("Error occurred while getting service provider id.");
                    }
                    return authorize(requestWrapper, oAuthMessage.getResponse());
                }
            } else {
                requestWrapper
                        .setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
                return authorize(requestWrapper, oAuthMessage.getResponse());
            }
        } catch (AuthServiceException e) {
            return handleApiBasedAuthErrorResponse(oAuthMessage.getRequest(), e);
        } catch (ServletException | IOException | URLBuilderException e) {
            log.error("Error occurred while sending request to authentication framework.");
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.HAND_OVER_TO_FRAMEWORK)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthMessage.getClientId())
                        .resultMessage("Server error occurred.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private URI buildURI(String redirectUrl) throws URISyntaxException, URLBuilderException {

        URI uri = new URI(redirectUrl);
        if (uri.isAbsolute()) {
            return uri;
        } else {
            return new URI(ServiceURLBuilder.create().addPath(redirectUrl).build().getAbsolutePublicURL());
        }
    }

    private String manageOIDCSessionState(OAuthMessage oAuthMessage,
                                          OIDCSessionState sessionStateObj, OAuth2Parameters oAuth2Parameters,
                                          String authenticatedUser, SessionDataCacheEntry sessionDataCacheEntry,
                                          AuthorizationResponseDTO authorizationResponseDTO) {

        HttpServletRequest request = oAuthMessage.getRequest();
        HttpServletResponse response = oAuthMessage.getResponse();
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (sessionStateObj.isAuthenticated()) { // successful user authentication
            if (opBrowserStateCookie == null) { // new browser session
                if (log.isDebugEnabled()) {
                    log.debug("User authenticated. Initiate OIDC browser session.");
                }
                opBrowserStateCookie = OIDCSessionManagementUtil.
                        addOPBrowserStateCookie(response, request, oAuth2Parameters.getLoginTenantDomain(),
                                sessionDataCacheEntry.getSessionContextIdentifier());
                // Adding sid claim in the IDtoken to OIDCSessionState class.
                storeSidClaim(authorizationResponseDTO, oAuthMessage, sessionStateObj);
                sessionStateObj.setAuthenticatedUser(authenticatedUser);
                sessionStateObj.addSessionParticipant(oAuth2Parameters.getClientId());
                OIDCSessionManagementUtil.getSessionManager().storeOIDCSessionState(opBrowserStateCookie.getValue(),
                        sessionStateObj, oAuth2Parameters.getLoginTenantDomain());
            } else { // browser session exists
                OIDCSessionState previousSessionState =
                        OIDCSessionManagementUtil.getSessionManager().getOIDCSessionState
                                (opBrowserStateCookie.getValue(), oAuth2Parameters.getLoginTenantDomain());
                if (previousSessionState != null) {
                    if (!previousSessionState.getSessionParticipants().contains(oAuth2Parameters.getClientId())) {
                        // User is authenticated to a new client. Restore browser session state
                        if (log.isDebugEnabled()) {
                            log.debug("User is authenticated to a new client. Restore browser session state.");
                        }
                        String oldOPBrowserStateCookieId = opBrowserStateCookie.getValue();
                        opBrowserStateCookie = OIDCSessionManagementUtil
                                .addOPBrowserStateCookie(response, request, oAuth2Parameters.getLoginTenantDomain(),
                                        sessionDataCacheEntry.getSessionContextIdentifier());
                        String newOPBrowserStateCookieId = opBrowserStateCookie.getValue();
                        previousSessionState.addSessionParticipant(oAuth2Parameters.getClientId());
                        OIDCSessionManagementUtil.getSessionManager().restoreOIDCSessionState
                                (oldOPBrowserStateCookieId, newOPBrowserStateCookieId, previousSessionState,
                                        oAuth2Parameters.getLoginTenantDomain());
                    }
                    // Storing the oidc session id.
                    storeSidClaim(authorizationResponseDTO, oAuthMessage, previousSessionState);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format(
                                "No session state found for the received Session ID : %s. Restore browser session " +
                                        "state.", opBrowserStateCookie.getValue()
                        ));
                    }
                    opBrowserStateCookie = OIDCSessionManagementUtil
                            .addOPBrowserStateCookie(response, request, oAuth2Parameters.getLoginTenantDomain(),
                                    sessionDataCacheEntry.getSessionContextIdentifier());
                    sessionStateObj.setAuthenticatedUser(authenticatedUser);
                    sessionStateObj.addSessionParticipant(oAuth2Parameters.getClientId());
                    storeSidClaim(authorizationResponseDTO, oAuthMessage, sessionStateObj);
                    OIDCSessionManagementUtil.getSessionManager().storeOIDCSessionState(opBrowserStateCookie.getValue(),
                            sessionStateObj, oAuth2Parameters.getLoginTenantDomain());
                }
            }
        }

        String sessionStateParam = null;
        if (sessionStateObj.isAddSessionState() && StringUtils.isNotEmpty(oAuth2Parameters.getRedirectURI())) {
            sessionStateParam = OIDCSessionManagementUtil.getSessionStateParam(oAuth2Parameters.getClientId(),
                    oAuth2Parameters.getRedirectURI(),
                    opBrowserStateCookie == null ? null : opBrowserStateCookie.getValue());
        }
        return sessionStateParam;
    }

    private String appendAuthenticatedIDPs(SessionDataCacheEntry sessionDataCacheEntry, String redirectURL,
                                           AuthorizationResponseDTO authorizationResponseDTO) {

        if (sessionDataCacheEntry != null) {
            String authenticatedIdPs = sessionDataCacheEntry.getAuthenticatedIdPs();

            if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
                try {
                    authorizationResponseDTO.setAuthenticatedIDPs(authenticatedIdPs);
                    String idpAppendedRedirectURL = redirectURL + "&AuthenticatedIdPs=" + URLEncoder.encode
                            (authenticatedIdPs, "UTF-8");
                    return idpAppendedRedirectURL;
                } catch (UnsupportedEncodingException e) {
                    //this exception should not occur
                    log.error("Error while encoding the url", e);
                }
            }
        }
        return redirectURL;
    }

    /**
     *  Associates the authentication method references done while logged into the session (if any) to the OAuth cache.
     *  The SessionDataCacheEntry then will be used when getting "AuthenticationMethodReferences". Please see
     *  <a href="https://tools.ietf.org/html/draft-ietf-oauth-amr-values-02" >draft-ietf-oauth-amr-values-02</a>.
     *
     * @param resultFromLogin The session context.
     * @param cookieValue The cookie string which contains the commonAuthId value.
     */
    private void associateAuthenticationHistory(SessionDataCacheEntry resultFromLogin, String cookieValue) {

        SessionContext sessionContext = getSessionContext(cookieValue,
                resultFromLogin.getoAuth2Parameters().getLoginTenantDomain());
        if (sessionContext != null && sessionContext.getSessionAuthHistory() != null
                && sessionContext.getSessionAuthHistory().getHistory() != null) {
            List<String> authMethods = new ArrayList<>();
            for (AuthHistory authHistory : sessionContext.getSessionAuthHistory().getHistory()) {
                authMethods.add(authHistory.toTranslatableString());
            }
            authMethods = getAMRValues(authMethods, sessionContext.getAuthenticatedIdPs());
            resultFromLogin.getParamMap().put(OAuthConstants.AMR, authMethods.toArray(new String[authMethods.size()]));
        }
    }

    /**
     * Replaces the authenticator names with the AMR values sent by the IDP.
     *
     * @param authMethods       The list of authentication methods set by resident IDP.
     * @param authenticatedIdPs The authenticated IDPs.
     */
    private List<String> getAMRValues(List<String> authMethods, Map<String, AuthenticatedIdPData> authenticatedIdPs) {

        boolean readAMRValueFromIdp = Boolean.parseBoolean(IdentityUtil.getProperty(
                OAuthConstants.READ_AMR_VALUE_FROM_IDP));
        if (readAMRValueFromIdp) {
            List<String> resultantAuthMethods = new ArrayList<>();
            Object[] idpKeySet = authenticatedIdPs.keySet().toArray();
            for (int i = 0; i < authMethods.size(); i++) {
                boolean amrFieldExists = false;
                if (idpKeySet[i] != null) {
                    String idpKey = (String) idpKeySet[i];
                    if (authenticatedIdPs.get(idpKey) != null && authenticatedIdPs.get(idpKey).getUser() != null
                            && authenticatedIdPs.get(idpKey).getUser().getUserAttributes() != null) {
                        for (Map.Entry<ClaimMapping, String> entry : authenticatedIdPs.get(idpKey).getUser()
                                .getUserAttributes().entrySet()) {
                            if (entry.getKey().getLocalClaim().getClaimUri().equals(OAuthConstants.AMR)) {
                                amrFieldExists = true;
                                addToAuthMethods(entry.getValue(), resultantAuthMethods);
                                break;
                            }
                        }
                    }
                }
                if (!amrFieldExists) {
                    resultantAuthMethods.add(authMethods.get(i));
                }
            }
            return resultantAuthMethods;
        }
        return authMethods;
    }

    /**
     * Adds the authentication methods to the list.
     *
     * @param amrValue             Comma separated authentication method value or values.
     * @param resultantAuthMethods The resultant list of authentication methods.
     */
    private void addToAuthMethods(String amrValue, List<String> resultantAuthMethods) {

        if (amrValue.contains(",")) {
            String[] amrValues = amrValue.split(",");
            resultantAuthMethods.addAll(Arrays.asList(amrValues));
        } else {
            resultantAuthMethods.add(amrValue);
        }
    }

    /**
     * Returns the SessionContext associated with the cookie value, if there is a one.
     * @param cookieValue String value of the cookie of commonAuthId.
     * @param loginTenantDomain Login tenant domain.
     * @return The associate SessionContext or null.
     */
    private SessionContext getSessionContext(String cookieValue, String loginTenantDomain) {

        if (StringUtils.isNotBlank(cookieValue)) {
            String sessionContextKey = DigestUtils.sha256Hex(cookieValue);
            return FrameworkUtils.getSessionContextFromCache(sessionContextKey, loginTenantDomain);
        }
        return null;
    }

    /**
     * Gets the last authenticated value from the commonAuthId cookie value.
     *
     * @param cookieValue       String CommonAuthId cookie values.
     * @param loginTenantDomain String Login tenant domain.
     * @return long The last authenticated timestamp.
     */
    private long getAuthenticatedTimeFromCommonAuthCookieValue(String cookieValue, String loginTenantDomain) {

        long authTime = 0;
        SessionContext sessionContext = getSessionContext(cookieValue, loginTenantDomain);
        if (sessionContext == null) {
            return authTime;
        }
            if (sessionContext.getProperty(FrameworkConstants.UPDATED_TIMESTAMP) != null) {
                authTime = Long.parseLong(
                        sessionContext.getProperty(FrameworkConstants.UPDATED_TIMESTAMP).toString());
            } else {
                authTime = Long.parseLong(
                        sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP).toString());
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
    OAuthProblemException buildOAuthProblemException(AuthenticationResult authenticationResult,
                                                     OAuthErrorDTO oAuthErrorDTO) {

        String errorCode = String.valueOf(authenticationResult.getProperty(FrameworkConstants.AUTH_ERROR_CODE));
        if (IdentityUtil.isBlank(errorCode)) {
            // If there is no custom error code sent from framework we set our default error code.
            errorCode = OAuth2ErrorCodes.LOGIN_REQUIRED;
        }

        String errorMessage = String.valueOf(authenticationResult.getProperty(FrameworkConstants.AUTH_ERROR_MSG));
        if (IdentityUtil.isBlank(errorMessage)) {
            if (oAuthErrorDTO != null && StringUtils.isNotBlank(oAuthErrorDTO.getErrorDescription())) {
                // If there is a custom message from responseTypeHandler we set that as error message.
                errorMessage = oAuthErrorDTO.getErrorDescription();
            } else {
                // If there is no custom error message sent from framework we set our default error message.
                errorMessage = DEFAULT_ERROR_MSG_FOR_FAILURE;
            }
        }

        String errorUri = String.valueOf(authenticationResult.getProperty(FrameworkConstants.AUTH_ERROR_URI));
        if (IdentityUtil.isBlank(errorUri)) {
            if (oAuthErrorDTO != null && StringUtils.isNotBlank(oAuthErrorDTO.getErrorURI())) {
                // If there is a custom message from responseTypeHandler we set that as error message.
                return OAuthProblemException.error(errorCode, errorMessage).uri(oAuthErrorDTO.getErrorURI());
            } else {
                // If there is no custom error URI we set just error code and message.
                return OAuthProblemException.error(errorCode, errorMessage);
            }
        } else {
            // If there is a error uri sent in the authentication result we add that to the exception.
            return OAuthProblemException.error(errorCode, errorMessage).uri(errorUri);
        }
    }

    /**
     * Store sessionID using the redirect URl.
     * @param oAuthMessage
     * @param sessionState
     * @param authorizationResponseDTO
     */
    private void storeSidClaim(AuthorizationResponseDTO authorizationResponseDTO, OAuthMessage oAuthMessage,
                               OIDCSessionState sessionState) {

        if (authorizationResponseDTO.getSuccessResponseDTO().getIdToken() != null) {
            String oidcSessionState = (String) oAuthMessage.getProperty(OIDC_SESSION_ID);
            sessionState.setSidClaim(oidcSessionState);
        } else if (authorizationResponseDTO.getSuccessResponseDTO().getAuthorizationCode() != null) {
            setSidToSessionState(sessionState);
            addToBCLogoutSessionToOAuthMessage(oAuthMessage, sessionState.getSidClaim());
        }
    }

    /**
     * Generate sessionID if there is no sessionID otherwise get sessionId from Session State
     *
     * @param sessionState
     */
    private void setSidToSessionState(OIDCSessionState sessionState) {

        String sessionId = sessionState.getSidClaim();
        if (sessionId == null) {
            // Generating sid claim for authorization code flow.
            sessionId = UUID.randomUUID().toString();
            sessionState.setSidClaim(sessionId);
        }
    }

    /**
     * Return true if the id token is encrypted.
     *
     * @param idToken String JWT ID token.
     * @return Boolean state of encryption.
     */
    private boolean isIDTokenEncrypted(String idToken) {
        // Encrypted ID token contains 5 base64 encoded components separated by periods.
        return StringUtils.countMatches(idToken, ".") == 4;
    }

    /**
     * Get id token from redirect Url fragment.
     *
     * @param redirectURL
     * @return
     * @throws URISyntaxException
     */
    private String getIdTokenFromRedirectURL(String redirectURL) throws URISyntaxException {

        String fragment = new URI(redirectURL).getFragment();
        Map<String, String> output = new HashMap<>();
        String[] keys = fragment.split("&");
        for (String key : keys) {
            String[] values = key.split("=");
            output.put(values[0], (values.length > 1 ? values[1] : ""));
            if (ID_TOKEN.equals(values[0])) {
                break;
            }
        }
        String idToken = output.get(ID_TOKEN);
        return idToken;
    }

    /**
     * Get AuthorizationCode from redirect Url query parameters.
     *
     * @param redirectURL
     * @return
     * @throws URISyntaxException
     */
    private String getAuthCodeFromRedirectURL(String redirectURL) throws URISyntaxException {

        String authCode = null;
        List<NameValuePair> queryParameters = new URIBuilder(redirectURL).getQueryParams();
        for (NameValuePair param : queryParameters) {
            if ((ACCESS_CODE).equals(param.getName())) {
                authCode = param.getValue();
            }
        }
        return authCode;
    }

    /**
     * Store Authorization Code and SessionID for back-channel logout in the cache.
     *
     * @param oAuthMessage
     * @param sessionId
     */
    private void addToBCLogoutSessionToOAuthMessage(OAuthMessage oAuthMessage, String sessionId) {

        AuthorizationGrantCacheEntry entry = oAuthMessage.getAuthorizationGrantCacheEntry();
        if (entry == null) {
            log.debug("Authorization code is not found in the redirect URL");
            return;
        }
        entry.setOidcSessionId(sessionId);
    }

    private void setSPAttributeToRequest(HttpServletRequest req, String spName, String tenantDomain) {

        req.setAttribute(REQUEST_PARAM_SP, spName);
        req.setAttribute(TENANT_DOMAIN, tenantDomain);
    }

    /**
     * Return OAuth2Parameters retrieved from OAuthMessage.
     * @param oAuthMessage
     * @return OAuth2Parameters
     */
    private OAuth2Parameters getOAuth2ParamsFromOAuthMessage(OAuthMessage oAuthMessage) {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        if (oAuthMessage.getSessionDataCacheEntry() != null) {
            oAuth2Parameters = getOauth2Params(oAuthMessage);
        }
        return oAuth2Parameters;
    }

    /**
     * Method to retrieve PkceCodeChallenge.
     * First check whether PkceCodeChallenge available in OAuth2Parameters and retrieve. If not retrieve from
     * request query parameters.
     *
     * @param oAuthMessage oAuthMessage
     * @param params       OAuth2 Parameters
     * @return PKCE code challenge. Priority will be given to the value inside the OAuth2Parameters.
     */
    private String getPkceCodeChallenge(OAuthMessage oAuthMessage, OAuth2Parameters params) {

        String pkceChallengeCode;
        // If the code_challenge is in the request object, then it is added to Oauth2 params before this point.
        if (params.getPkceCodeChallenge() != null) {
            // If Oauth2 params contains code_challenge get value from Oauth2 params.
            pkceChallengeCode = params.getPkceCodeChallenge();
        } else {
            // Else retrieve from request query params.
            pkceChallengeCode = oAuthMessage.getOauthPKCECodeChallenge();
        }

        return pkceChallengeCode;
    }

    /**
     * Method to retrieve PkceCodeChallengeMethod.
     * First check whether PkceCodeChallengeMethod available in OAuth2Parameters and retrieve. If not retrieve from
     * request query parameters.
     *
     * @param oAuthMessage oAuthMessage
     * @param params       OAuth2 Parameters
     * @return PKCE code challenge method. Priority will be given to the value inside the OAuth2Parameters.
     */
    private String getPkceCodeChallengeMethod(OAuthMessage oAuthMessage, OAuth2Parameters params) {

        String pkceChallengeMethod;
        // If the code_challenge_method is in the request object, then it is added to Oauth2 params before this point.
        if (params.getPkceCodeChallengeMethod() != null) {
            // If Oauth2 params contains code_challenge_method get value from Oauth2 params.
            pkceChallengeMethod = params.getPkceCodeChallengeMethod();
        } else {
            // Else retrieve from request query params.
            pkceChallengeMethod = oAuthMessage.getOauthPKCECodeChallengeMethod();
        }

        return pkceChallengeMethod;
    }

    private Response forwardToOauthResponseJSP(OAuthMessage oAuthMessage, String params, String redirectURI) {

        try {
            HttpServletRequest request = oAuthMessage.getRequest();
            HttpServletResponse response = oAuthMessage.getResponse();
            request.setAttribute(PARAMETERS, params);
            request.setAttribute(FORM_POST_REDIRECT_URI, redirectURI);
            ServletContext authEndpoint = request.getServletContext().getContext(AUTHENTICATION_ENDPOINT);
            RequestDispatcher requestDispatcher = authEndpoint.getRequestDispatcher(OAUTH_RESPONSE_JSP_PAGE);
            requestDispatcher.forward(request, response);
            return Response.ok().build();
        } catch (ServletException | IOException exception) {
            log.error("Error occurred while forwarding the request to oauth_response.jsp page.", exception);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private Response forwardToOauthResponseJSP(OAuthMessage oAuthMessage, String params, String redirectURI,
                                               AuthorizationResponseDTO authorizationResponseDTO,
                                               AuthenticatedUser authenticatedUser) {
        try {
            HttpServletRequest request = oAuthMessage.getRequest();
            request.setAttribute(USER_TENANT_DOMAIN, authenticatedUser.getTenantDomain());
            request.setAttribute(TENANT_DOMAIN, authorizationResponseDTO.getSigningTenantDomain());
            ServiceProvider serviceProvider = getServiceProvider(authorizationResponseDTO.getClientId());
            if (serviceProvider != null && serviceProvider.getApplicationName() != null) {
                request.setAttribute(SERVICE_PROVIDER, serviceProvider.getApplicationName());
            }
            forwardToOauthResponseJSP(oAuthMessage, params, redirectURI);
            return Response.ok().build();
        } catch (OAuthSystemException exception) {
            log.error("Error occurred while setting service provider in the request to oauth_response.jsp page.",
                    exception);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                       .entity("Internal Server Error: " + exception.getMessage())
                       .build();
        }
    }

    private boolean isPromptSelectAccount(OAuth2Parameters oauth2Params) {

        return OAuthConstants.Prompt.SELECT_ACCOUNT.equals(oauth2Params.getPrompt());
    }

    /**
     * Set the device authentication service.
     *
     * @param deviceAuthService Device authentication service.
     */
    public static void setDeviceAuthService(DeviceAuthService deviceAuthService) {

        OAuth2AuthzEndpoint.deviceAuthService = deviceAuthService;
    }

    private void cacheUserAttributesByDeviceCode(SessionDataCacheEntry sessionDataCacheEntry)
            throws OAuthSystemException {

        String userCode = null;
        Optional<String> deviceCodeOptional = Optional.empty();
        String[] userCodeArray = sessionDataCacheEntry.getParamMap().get(Constants.USER_CODE);
        if (ArrayUtils.isNotEmpty(userCodeArray)) {
            userCode = userCodeArray[0];
        }
        if (StringUtils.isNotBlank(userCode)) {
            deviceCodeOptional = getDeviceCodeByUserCode(userCode);
        }
        if (deviceCodeOptional.isPresent()) {
            addUserAttributesToCache(sessionDataCacheEntry, deviceCodeOptional.get());
        }
    }

    private Optional<String> getDeviceCodeByUserCode(String userCode) throws OAuthSystemException {

        try {
            return deviceAuthService.getDeviceCode(userCode);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException("Error occurred while retrieving device code for user code: " + userCode, e);
        }
    }

    private void addUserAttributesToCache(SessionDataCacheEntry sessionDataCacheEntry, String deviceCode) {

        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                new DeviceAuthorizationGrantCacheEntry(sessionDataCacheEntry.getLoggedInUser().getUserAttributes());
        if (sessionDataCacheEntry.getMappedRemoteClaims() != null) {
            cacheEntry.setMappedRemoteClaims(sessionDataCacheEntry
                    .getMappedRemoteClaims());
        }
        DeviceAuthorizationGrantCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private boolean isFapiConformant(String clientId) throws InvalidRequestException {

        try {
            return OAuth2Util.isFapiConformantApp(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new InvalidRequestException(OAuth2ErrorCodes.INVALID_CLIENT, "Could not find an existing app for " +
                    "clientId: " + clientId, e);
        } catch (IdentityOAuth2Exception e) {
            throw new InvalidRequestException(OAuth2ErrorCodes.SERVER_ERROR, "Error while obtaining the service " +
                    "provider for clientId: " + clientId, e);
        }
    }

    private boolean isApiBasedAuthenticationFlow(OAuthMessage oAuthMessage) {

        OAuth2Parameters oAuth2Parameters = getOauth2Params(oAuthMessage);
        if (oAuth2Parameters != null) {
            return isApiBasedAuthenticationFlow(getOauth2Params(oAuthMessage));
        }

        return OAuth2Util.isApiBasedAuthenticationFlow(oAuthMessage.getRequest());
    }

    private boolean isApiBasedAuthenticationFlow(OAuth2Parameters oAuth2Parameters) {

        if (oAuth2Parameters == null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth2Parameters is null. Returning false for isApiBasedAuthenticationFlow check.");
            }
            return false;
        }
        return OAuthConstants.ResponseModes.DIRECT.equals(oAuth2Parameters.getResponseMode());
    }

    private void attachAuthServiceResponseToRequest(HttpServletRequest request,
                                                    AuthServiceResponse authServiceResponse) {

        request.setAttribute(AUTH_SERVICE_RESPONSE, authServiceResponse);
    }

    private Response handleApiBasedAuthenticationResponse(OAuthMessage oAuthMessage, Response oauthResponse) {

        // API based auth response transformation has already been handled no need for further handling.
        if (Boolean.TRUE.equals(oAuthMessage.getRequest().getAttribute(IS_API_BASED_AUTH_HANDLED))) {
            return oauthResponse;
        }
        try {
            Object attribute = oAuthMessage.getRequest().getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
            if (attribute == AuthenticatorFlowStatus.INCOMPLETE) {
                AuthServiceResponse authServiceResponse = (AuthServiceResponse) oAuthMessage.getRequest()
                        .getAttribute(AUTH_SERVICE_RESPONSE);

                if (authServiceResponse.getFlowStatus() == AuthServiceConstants.FlowStatus.FAIL_COMPLETED) {
                    if (authServiceResponse.getErrorInfo().isPresent()) {
                        throw new AuthServiceClientException(authServiceResponse.getErrorInfo().get().getErrorCode(),
                                authServiceResponse.getErrorInfo().get().getErrorDescription());
                    } else {
                        throw new AuthServiceClientException(
                                AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.message());
                    }
                }

                AuthResponse authResponse = API_AUTHN_HANDLER.handleResponse(authServiceResponse);
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
                String jsonString = null;
                try {
                    jsonString = objectMapper.writeValueAsString(authResponse);
                } catch (JsonProcessingException e) {
                    throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
                            "Error while building JSON response.", e);
                }
                oAuthMessage.getRequest().setAttribute(IS_API_BASED_AUTH_HANDLED, true);
                return Response.ok().entity(jsonString).build();
            } else {
                List<Object> locationHeader = oauthResponse.getMetadata().get("Location");
                if (CollectionUtils.isNotEmpty(locationHeader)) {
                    String location = locationHeader.get(0).toString();
                    if (StringUtils.isNotBlank(location)) {
                        Map<String, String> queryParams;
                        try {
                            queryParams = getQueryParamsFromUrl(location);
                        } catch (UnsupportedEncodingException | URISyntaxException e) {
                            throw new AuthServiceException(
                                    AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
                                    "Error while extracting query params from provided url.", e);
                        }
                        if (isRedirectToClient(location)) {
                            SuccessCompleteAuthResponse successCompleteAuthResponse =
                                    new SuccessCompleteAuthResponse(queryParams);
                            String jsonPayload = new Gson().toJson(successCompleteAuthResponse);
                            oAuthMessage.getRequest().setAttribute(IS_API_BASED_AUTH_HANDLED, true);
                            return Response.status(HttpServletResponse.SC_OK).entity(jsonPayload).build();
                        } else {
                            /* At this point if the location header doesn't indicate a redirection to the client
                             we can assume it is an error scenario which redirects to the error page. Therefore,
                             we need to handle the response as an API based error response.*/
                            String errorMsg = getErrorMessageForApiBasedClientError(queryParams);
                            if (StringUtils.isBlank(errorMsg)) {
                                errorMsg = AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.description();
                            }
                            throw new AuthServiceClientException(
                                    AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(), errorMsg);

                        }
                    }
                }
            }
        } catch (AuthServiceException e) {
            return handleApiBasedAuthErrorResponse(oAuthMessage.getRequest(), e);
        }

        // Returning the original response as it hasn't been handled as an API based authentication response.
        return oauthResponse;
    }

    private Response handleApiBasedAuthErrorResponse(HttpServletRequest request, AuthServiceException e) {

        if (e instanceof AuthServiceClientException) {
            request.setAttribute(IS_API_BASED_AUTH_HANDLED, true);
            return ApiAuthnUtils.buildResponseForClientError((AuthServiceClientException) e, log);
        } else {
            request.setAttribute(IS_API_BASED_AUTH_HANDLED, true);
            return ApiAuthnUtils.buildResponseForServerError(e, log);
        }
    }

    private Map<String, String> getQueryParamsFromUrl(String url) throws UnsupportedEncodingException,
            URISyntaxException {

        Map<String, String> queryParams = new HashMap<>();

        if (StringUtils.isBlank(url)) {
            return queryParams;
        }

        URI uri = new URI(url);
        String query = uri.getQuery();
        if (StringUtils.isNotBlank(query)) {
            String[] pairs = query.split(FrameworkUtils.QUERY_SEPARATOR);
            for (String pair : pairs) {
                int idx = pair.indexOf(FrameworkUtils.EQUAL);
                queryParams.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.toString()),
                        URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.toString()));
            }
        }
        return queryParams;
    }

    private void checkPARMandatory(OAuth2Parameters params, OAuthMessage oAuthMessage)
            throws InvalidRequestException {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(params.getClientId(), params.getTenantDomain());
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new InvalidRequestException(e.getMessage(), e.getErrorCode());
        }
        if (oAuthAppDO.isRequirePushedAuthorizationRequests()) {
            if (!Boolean.TRUE.equals(oAuthMessage.getRequest()
                    .getAttribute(OAuthConstants.IS_PUSH_AUTHORIZATION_REQUEST))) {
                throw new InvalidRequestException("PAR request is mandatory for the application.",
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST);
            }
        }
    }

    private boolean isRedirectToClient(String url) {

        if (StringUtils.isBlank(url)) {
            return false;
        }

        if (url.startsWith(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl())) {
            return false;
        }

        return true;
    }

    private String getErrorMessageForApiBasedClientError(Map<String, String> params) {

        String oauthErrorCode = params.get(OAuthConstants.OAUTH_ERROR_CODE);
        String oauthErrorMsg = params.get(OAuthConstants.OAUTH_ERROR_MESSAGE);

        if (StringUtils.isBlank(oauthErrorCode)) {
            return oauthErrorMsg != null ? oauthErrorMsg : StringUtils.EMPTY;
        } else if (StringUtils.isBlank(oauthErrorMsg)) {
            return oauthErrorCode;
        } else {
            return oauthErrorCode + " " + AuthServiceConstants.INTERNAL_ERROR_MSG_SEPARATOR + " " + oauthErrorMsg;
        }
    }

    private OAuthClientAuthnContext getClientAuthnContext(HttpServletRequest request) {

        OAuthClientAuthnContext oAuthClientAuthnContext;
        Object oauthClientAuthnContextObj = request.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT);
        if (oauthClientAuthnContextObj instanceof OAuthClientAuthnContext) {
            oAuthClientAuthnContext = (OAuthClientAuthnContext) oauthClientAuthnContextObj;
        } else {
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }
        return oAuthClientAuthnContext;
    }

    private ClientAttestationContext getClientAttestationContext(HttpServletRequest request) {

        ClientAttestationContext clientAttestationContext;
        Object clientAttestationContextObj = request.getAttribute(CLIENT_ATTESTATION_CONTEXT);
        if (clientAttestationContextObj instanceof ClientAttestationContext) {
            clientAttestationContext = (ClientAttestationContext) clientAttestationContextObj;
        } else {
            clientAttestationContext = new ClientAttestationContext(false);
            clientAttestationContext.setAttested(false);
        }
        return clientAttestationContext;
    }

    /**
     * Handle the authentication failure response for API based authentication.
     *
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @return Auth failure response.
     */
    private Response handleAuthFailureResponse(OAuthClientAuthnContext oAuthClientAuthnContext) {

        if (OAuth2ErrorCodes.SERVER_ERROR.equals(oAuthClientAuthnContext.getErrorCode())) {
            String msg = "Server encountered an error while authorizing the request.";
            return ApiAuthnUtils.buildResponseForServerError(new AuthServiceException(msg), log);
        }
        return ApiAuthnUtils.buildResponseForAuthorizationFailure(oAuthClientAuthnContext.getErrorMessage(), log);
    }

    private Response handleAttestationFailureResponse(ClientAttestationContext clientAttestationContext) {

        return ApiAuthnUtils.buildResponseForAuthorizationFailure(
                clientAttestationContext.getValidationFailureMessage(), log);
    }

    private Response handleUnsupportedGrantForApiBasedAuth() {

        return ApiAuthnUtils.buildResponseForClientError(
                new AuthServiceClientException(AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                        "App native authentication is only supported with code response type."), log);
    }

    private String addServiceProviderIdToRedirectURI(String redirectURI, String serviceProviderId) {

        if (StringUtils.isNotBlank(redirectURI) && StringUtils.isNotBlank(serviceProviderId)) {
            try {
                URI uri = new URI(redirectURI);
                String query = uri.getRawQuery();
                if (StringUtils.isNotBlank(query)) {
                    if (!query.contains(SERVICE_PROVIDER_ID + "=")) {
                        redirectURI = redirectURI + "&" + SERVICE_PROVIDER_ID + "=" + serviceProviderId;
                    }
                } else {
                    redirectURI = redirectURI + "?" + SERVICE_PROVIDER_ID + "=" + serviceProviderId;
                }
            } catch (URISyntaxException e) {
                log.debug("Error occurred while adding service provider id to redirect URI.", e);
            }
        }
        return redirectURI;
    }
}
