/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.client.attestation.filter.ClientAttestationProxy;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnUtils;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthRequest;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.AuthzUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authzChallenge.event.AuthzChallengeInterceptor;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;


/**
 * Class containing the REST API for API based authentication.
 */

@Path("/authorize-challenge")
@InInterceptors(classes = {OAuthClientAuthenticatorProxy.class, ClientAttestationProxy.class})
public class AuthzChallengeEndpoint {

    private static final String AUTH_SESSION = "auth_session";
    private static final String FLOW_ID = "flowId";
    private static final String DPOP = "DPoP";
    private static final String ATTR_AUTHZ_CHALLENGE = "isAuthzChallenge";

    private static final Log log = LogFactory.getLog(AuthzChallengeEndpoint.class);

    private final AuthenticationService authenticationService = new AuthenticationService();
    private static final Log LOG = LogFactory.getLog(AuthzChallengeEndpoint.class);

    public Response handleInitialAuthzChallengeRequest(@Context HttpServletRequest request,
                                                       @Context HttpServletResponse response, boolean isInternalRequest)
            throws URISyntaxException, InvalidRequestParentException, AuthServiceException, IdentityOAuth2Exception {

        OAuthMessage oAuthMessage;

        AuthzUtil.setCommonAuthIdToRequest(request, response);

        try {
            request = RequestUtil.buildRequest(request);
            request.setAttribute(ATTR_AUTHZ_CHALLENGE, true);
            oAuthMessage = AuthzUtil.buildOAuthMessage(request, response);
        } catch (InvalidRequestParentException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            throw e;
        } catch (IdentityException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleIdentityException(request, e);
        }

        // Perform request authentication
        if (!isInternalRequest) {
            if (hasDPoPHeader(request)) {
                processDPoPHeader(request, oAuthMessage);
            }

            OAuthClientAuthnContext oAuthClientAuthnContext = AuthzUtil.getClientAuthnContext(request);
            if (!oAuthClientAuthnContext.isAuthenticated()) {
                return AuthzUtil.handleAuthFailureResponse(oAuthClientAuthnContext, request);
            }

            ClientAttestationContext clientAttestationContext = AuthzUtil.getClientAttestationContext(request);
            if (clientAttestationContext.isAttestationEnabled() && !clientAttestationContext.isAttested()) {
                return AuthzUtil.handleAttestationFailureResponse(clientAttestationContext);
            }

            if (!OAuth2Util.isApiBasedAuthSupportedGrant(request)) {
                return AuthzUtil.handleUnsupportedGrantForApiBasedAuth(request);
            }
        }

        try {
            // Start tenant domain flow if the tenant configuration is not enabled.
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                String tenantDomain = null;
                if (StringUtils.isNotEmpty(oAuthMessage.getClientId())) {
                    tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
                } else if (oAuthMessage.getSessionDataCacheEntry() != null) {
                    OAuth2Parameters oauth2Params = AuthzUtil.getOauth2Params(oAuthMessage);
                    assert oauth2Params != null;
                    tenantDomain = oauth2Params.getTenantDomain();
                }
                FrameworkUtils.startTenantFlow(tenantDomain);
            }

            Response oauthResponse;
            if (AuthzUtil.isPassthroughToFramework(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleAuthFlowThroughFramework(oAuthMessage);
            } else if (AuthzUtil.isInitialRequestFromClient(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleInitialAuthorizationRequest(oAuthMessage);
            } else if (AuthzUtil.isAuthenticationResponseFromFramework(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleAuthenticationResponse(oAuthMessage);
            } else if (AuthzUtil.isConsentResponseFromUser(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleResponseFromConsent(oAuthMessage);
            } else {
                oauthResponse = AuthzUtil.handleInvalidRequest(oAuthMessage);
            }
            oauthResponse = AuthzUtil.handleApiBasedAuthenticationResponse(oAuthMessage, oauthResponse);
            return oauthResponse;
        } catch (OAuthProblemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleOAuthProblemException(oAuthMessage, e);
        } catch (OAuthSystemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleOAuthSystemException(oAuthMessage, e);
        } finally {
            AuthzUtil.handleCachePersistence(oAuthMessage);
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    private Response handleSubsequentAuthzChallengeRequest(@Context HttpServletRequest request,
                                                           @Context HttpServletResponse response, String payload)
            throws AuthServiceException, InvalidRequestParentException, URISyntaxException {

        try {
            payload = renameAuthSessionToFlowId(payload);
            request.setAttribute(ATTR_AUTHZ_CHALLENGE, true);
            AuthRequest authRequest = ApiAuthnUtils.buildAuthRequest(payload);
            AuthServiceRequest authServiceRequest = ApiAuthnUtils.getAuthServiceRequest(request, response, authRequest);
            Optional<String> sessionDataCacheKey = authenticationService.getSessionDataCacheKey(authServiceRequest);
            validateDPoPThumbprint(request, sessionDataCacheKey);
            AuthServiceResponse authServiceResponse = authenticationService.handleAuthentication(authServiceRequest);

            switch (authServiceResponse.getFlowStatus()) {
                case INCOMPLETE:
                    return ApiAuthnUtils.handleIncompleteAuthResponse(request, authServiceResponse);
                case SUCCESS_COMPLETED:
                    return ApiAuthnUtils.handleSuccessCompletedAuthResponse(request, response, authServiceResponse);
                case FAIL_INCOMPLETE:
                    return ApiAuthnUtils.handleFailIncompleteAuthResponse(request, authServiceResponse);
                case FAIL_COMPLETED:
                    return ApiAuthnUtils.handleFailCompletedAuthResponse(request, authServiceResponse);
                default:
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_UNKNOWN_AUTH_FLOW_STATUS.code(),
                            String.format(AuthServiceConstants.ErrorMessage.ERROR_UNKNOWN_AUTH_FLOW_STATUS
                                    .description(), authServiceResponse.getFlowStatus()));
            }

        } catch (AuthServiceClientException e) {
            return AuthzUtil.buildAuthzChallengeResponseForClientError(e, LOG);
        } catch (AuthServiceException e) {
            return ApiAuthnUtils.buildResponseForServerError(e, LOG);
        } catch (IdentityOAuth2Exception e) {
            return AuthzUtil.handleIdentityOAuth2Exception(e);
        } catch (JsonProcessingException e) {
            throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
                    "Error while building JSON response.", e);
        }
    }

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorizeChallengeInitialPost(@Context HttpServletRequest request,
                                           @Context HttpServletResponse response, MultivaluedMap paramMap) {

        try {
            Map<String, String[]> parameterMap = request.getParameterMap();

            if (parameterMap.containsKey(OAuthConstants.OAuth20Params.CLIENT_ID) &&
                    parameterMap.containsKey(OAuthConstants.OAuth20Params.RESPONSE_TYPE) &&
            parameterMap.containsKey(OAuthConstants.OAuth20Params.REDIRECT_URI)) {

                if (!EndpointUtil.validateParams(request, paramMap)) {
                    return Response.status(HttpServletResponse.SC_BAD_REQUEST)
                            .location(new URI(EndpointUtil.getErrorPageURL(request,
                                    OAuth2ErrorCodes.INVALID_REQUEST,
                                    OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST,
                                    "Invalid authorization request with repeated parameters", null)))
                            .build();
                }
                HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
                return handleInitialAuthzChallengeRequest(httpRequest, response, false);
            } else {
                return AuthzUtil.buildAuthzChallengeResponseForClientError(
                        new AuthServiceClientException(AuthServiceConstants.ErrorMessage
                                .ERROR_INVALID_AUTH_REQUEST.code(),
                                "Invalid or missing request parameters."), LOG);
            }

        } catch (AuthServiceClientException e) {
            log.error("Client error while handling authentication request.", e);
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).build();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while handling authorize challenge request.", e);
            return AuthzUtil.handleIdentityOAuth2Exception(e);
        } catch (AuthServiceException | URISyntaxException | InvalidRequestParentException e) {
            log.error("Error occurred while handling authorize challenge request.", e);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    @POST
    @Path("/")
    @Consumes("application/json")
    @Produces("application/json")
    public Response authorizeChallengeSubsequentPost(@Context HttpServletRequest request,
                                                     @Context HttpServletResponse response, String payload) {

        try {
            if (payload != null && payload.contains(AUTH_SESSION)) {
                return handleSubsequentAuthzChallengeRequest(request, response, payload);
            } else {
                return AuthzUtil.buildAuthzChallengeResponseForClientError(
                        new AuthServiceClientException(AuthServiceConstants.ErrorMessage
                                .ERROR_INVALID_AUTH_REQUEST.code(),
                                "Invalid or missing request parameters."), LOG);
            }

        } catch (AuthServiceClientException e) {
            log.error("Client error while handling authentication request.", e);
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).build();
        } catch (AuthServiceException | InvalidRequestParentException | URISyntaxException e) {
            log.error("Error occurred while handling authorize challenge request.", e);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private OAuth2AuthzChallengeReqDTO buildAuthzChallengeReqDTO(HttpServletRequest request) {

        OAuth2AuthzChallengeReqDTO dto = new OAuth2AuthzChallengeReqDTO();

        dto.setClientId(request.getParameter(OAuthConstants.OAuth20Params.CLIENT_ID));
        dto.setResponseType(request.getParameter(OAuthConstants.OAuth20Params.RESPONSE_TYPE));
        dto.setRedirectUri(request.getParameter(OAuthConstants.OAuth20Params.REDIRECT_URI));
        dto.setState(request.getParameter(OAuthConstants.OAuth20Params.STATE));
        dto.setScope(request.getParameter(OAuthConstants.OAuth20Params.SCOPE));
        dto.setAuthSession(request.getParameter(AUTH_SESSION));
        dto.setHttpRequestHeaders(extractHeaders(request));
        dto.setHttpServletRequestWrapper(new HttpServletRequestWrapper(request));

        return dto;
    }

    /**
     * Extracts HTTP headers from the request and converts them into an array of HttpRequestHeader objects.
     *
     * @param request The HTTP servlet request from which to extract headers
     * @return An array of HttpRequestHeader objects containing the header name and values
     */
    private static HttpRequestHeader[] extractHeaders(HttpServletRequest request) {

        Enumeration<String> headerNames = request.getHeaderNames();

        if (headerNames == null || !headerNames.hasMoreElements()) {
            return null;
        }

        List<HttpRequestHeader> httpHeaderList = new ArrayList<>();

        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            Enumeration<String> headerValues = request.getHeaders(headerName);

            List<String> headerValueList = new ArrayList<>();
            while (headerValues != null && headerValues.hasMoreElements()) {
                headerValueList.add(headerValues.nextElement());
            }
            httpHeaderList.add(new HttpRequestHeader(
                    headerName,
                    headerValueList.toArray(new String[0])
            ));
        }
        return httpHeaderList.toArray(new HttpRequestHeader[0]);
    }

    private boolean hasDPoPHeader(HttpServletRequest request) {
        return request.getHeader(DPOP) != null;
    }

    /**
     * Process the DPoP header and extract thumbprint if available. The extracted thumbprint is then stored in the
     * OAuthMessage to be persisted in the session data cache for later validation in subsequent requests.
     *
     * @param request The HTTP servlet request containing the DPoP header
     * @param oAuthMessage The OAuth message to update with the thumbprint
     */
    private void processDPoPHeader(HttpServletRequest request, OAuthMessage oAuthMessage)
            throws IdentityOAuth2Exception {

        AuthzChallengeInterceptor authzChallengeInterceptor = OAuth2ServiceComponentHolder.getInstance()
                .getAuthzChallengeInterceptorHandlerProxy();

        if (authzChallengeInterceptor != null && authzChallengeInterceptor.isEnabled()) {
            OAuth2AuthzChallengeReqDTO requestDTO = buildAuthzChallengeReqDTO(request);
            String thumbprint = authzChallengeInterceptor.handleAuthzChallengeReq(requestDTO);
            if (StringUtils.isNotBlank(thumbprint)) {
                oAuthMessage.setDPoPThumbprint(thumbprint);
                if (log.isDebugEnabled()) {
                    log.debug("DPoP thumbprint successfully processed and set");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("AuthzChallengeInterceptor is not available or not enabled. " +
                        "Skipping DPoP thumbprint processing.");
            }
        }
    }

    /**
     * Validates that the DPoP thumbprint in the current request matches the one stored in the session cache.
     *
     * @param request The HTTP servlet request containing the DPoP header
     * @param sessionDataCacheKey Optional containing the session data cache key
     * @throws AuthServiceException If validation fails or any error occurs during validation
     * @throws IdentityOAuth2Exception If any OAuth2 related error occurs
     */
    private void validateDPoPThumbprint(HttpServletRequest request, Optional<String> sessionDataCacheKey)
            throws AuthServiceException, IdentityOAuth2Exception {

        if (!sessionDataCacheKey.isPresent()) {
            if (log.isDebugEnabled()) {
                log.debug("No session data cache key found in the request. Skipping DPoP thumbprint validation.");
            }
            throw new AuthServiceException(
                    AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Invalid session data cache key."
            );
        }
        SessionDataCacheKey key = new SessionDataCacheKey(sessionDataCacheKey.orElse(""));
        SessionDataCacheEntry entry = SessionDataCache.getInstance().getValueFromCache(key);

        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("No session data cache entry found for the given key.");
            }
            throw new AuthServiceException(
                    AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Session data cache entry not found."
            );
        }

        String cachedThumbprint = entry.getDPoPThumbprint();

        if (!StringUtils.isBlank(cachedThumbprint)) {
            AuthzChallengeInterceptor authzChallengeInterceptor =
                    OAuth2ServiceComponentHolder.getInstance().getAuthzChallengeInterceptorHandlerProxy();

            if (authzChallengeInterceptor != null && authzChallengeInterceptor.isEnabled()) {
                OAuth2AuthzChallengeReqDTO requestDTO = buildAuthzChallengeReqDTO(request);
                String currentThumbprint = authzChallengeInterceptor.handleAuthzChallengeReq(requestDTO);

                if (StringUtils.isBlank(currentThumbprint)) {
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                            "DPoP thumbprint is missing in the current request."
                    );
                }

                if (!cachedThumbprint.equals(currentThumbprint)) {
                    if (log.isDebugEnabled()) {
                        log.debug("DPoP thumbprint validation failed. Cached and current thumbprints do not match.");
                    }
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                            "Invalid DPoP thumbprint value."
                    );
                }
            }
        }
    }

    private String renameAuthSessionToFlowId(String payload) throws JsonProcessingException {

        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode objectNode = (ObjectNode) objectMapper.readTree(payload);

        objectNode.set(FLOW_ID, objectNode.remove(AUTH_SESSION));
        return objectMapper.writeValueAsString(objectNode);
    }
}

