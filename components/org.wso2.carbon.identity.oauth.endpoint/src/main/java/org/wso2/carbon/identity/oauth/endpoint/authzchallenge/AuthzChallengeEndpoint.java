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
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import javax.servlet.ServletException;
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
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.client.attestation.filter.ClientAttestationProxy;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.UserAgent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnUtils;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthRequest;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.AuthzUtil;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.utils.DiagnosticLog;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getErrorPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getLoginPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuthAuthzRequest;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;
import static org.wso2.carbon.identity.openidconnect.model.Constants.LOGIN_HINT;
import static org.wso2.carbon.identity.openidconnect.model.Constants.SERVICE_PROVIDER_ID;
import static org.wso2.carbon.identity.openidconnect.model.Constants.STATE;


/**
 * Class containing the REST API for API based authentication.
 */

@Path("/authorize-challenge")
@InInterceptors(classes = {OAuthClientAuthenticatorProxy.class, ClientAttestationProxy.class})
public class AuthzChallengeEndpoint {

    private static OpenIDConnectClaimFilterImpl openIDConnectClaimFilter;

    private static ScopeMetadataService scopeMetadataService;

    public static OpenIDConnectClaimFilterImpl getOpenIDConnectClaimFilter() {

        return openIDConnectClaimFilter;
    }

    public static void setOpenIDConnectClaimFilter(OpenIDConnectClaimFilterImpl openIDConnectClaimFilter) {

        AuthzChallengeEndpoint.openIDConnectClaimFilter = openIDConnectClaimFilter;
    }

    public static ScopeMetadataService getScopeMetadataService() {

        return scopeMetadataService;
    }

    public static void setScopeMetadataService(ScopeMetadataService scopeMetadataService) {

        AuthzChallengeEndpoint.scopeMetadataService = scopeMetadataService;
    }
    private static DeviceAuthService deviceAuthService;
    private static final Log log = LogFactory.getLog(AuthzChallengeEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response handleAuthorizeChallenge(@Context HttpServletRequest request, @Context HttpServletResponse response, String payload) {
        try {
            Map<String, String[]> parameterMap = request.getParameterMap();

            if (parameterMap.containsKey("client_id") && parameterMap.containsKey("response_type")) {
                // Handle initial authorization challenge request (prev. handled by /authorize)
                return handleInitialAuthzChallengeRequest(request, response);
//            } else if (parameterMap.containsKey("flowId")) {
//                // Handle subsequent authentication flow (prev. handled by /authn)
//                return handleSubsequentAuthzChallengeRequest(request, response, payload);
            } else {
                throw new AuthServiceException(
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                        "Invalid request parameters for /authorize-challenge.");
            }
        } catch (AuthServiceClientException e) {
            log.error("Client error while handling authentication request.", e);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        } catch (AuthServiceException | URISyntaxException | InvalidRequestParentException e) {
            log.error("Error occurred while handling authorize challenge request.", e);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }


    public Response handleInitialAuthzChallengeRequest(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException {

        OAuthMessage oAuthMessage;

        try{
            request = RequestUtil.buildRequest(request);
            oAuthMessage = AuthzUtil.buildOAuthMessage(request, response);
        } catch (InvalidRequestParentException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            throw e;
        } catch (IdentityException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleIdentityException(request, e);
        }

        // Perform request authentication
        OAuthClientAuthnContext oAuthClientAuthnContext = AuthzUtil.getClientAuthnContext(request);
        if (!oAuthClientAuthnContext.isAuthenticated()) {
            return AuthzUtil.handleAuthFailureResponse(oAuthClientAuthnContext);
        }

        ClientAttestationContext clientAttestationContext = AuthzUtil.getClientAttestationContext(request);
        if (clientAttestationContext.isAttestationEnabled() && !clientAttestationContext.isAttested()) {
            return AuthzUtil.handleAttestationFailureResponse(clientAttestationContext);
        }

        if (!OAuth2Util.isApiBasedAuthSupportedGrant(request)) {
            return AuthzUtil.handleUnsupportedGrantForApiBasedAuth();
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
                oauthResponse = handleAuthFlowThroughFramework(oAuthMessage);
            } else if (AuthzUtil.isInitialRequestFromClient(oAuthMessage)) {
                oauthResponse = handleInitialAuthorizationRequest(oAuthMessage);
            } else if (AuthzUtil.isAuthenticationResponseFromFramework(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleAuthenticationResponse(oAuthMessage);
            } else if (AuthzUtil.isConsentResponseFromUser(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleResponseFromConsent(oAuthMessage);
            } else {
                oauthResponse = AuthzUtil.handleInvalidRequest(oAuthMessage);
            }
            // Response for the API based authentication flow.
//            if (AuthzUtil.isApiBasedAuthenticationFlow(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleApiBasedAuthenticationResponse(oAuthMessage, oauthResponse, true);
//            }

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

//    private Response handleSubsequentAuthzChallengeRequest(@Context HttpServletRequest request, @Context HttpServletResponse response, String payload) throws AuthServiceException {
//
//    }



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
        return handleInitialAuthzChallengeRequest(httpRequest, response);
    }

    /**
     * Set the device authentication service.
     *
     * @param deviceAuthService Device authentication service.
     */
    public static void setDeviceAuthService(DeviceAuthService deviceAuthService) {

        AuthzChallengeEndpoint.deviceAuthService = deviceAuthService;
    }

    private Response handleAuthFlowThroughFramework(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        try {
            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(oAuthMessage.getResponse());
            AuthzUtil.invokeCommonauthFlow(oAuthMessage, responseWrapper);
            return processAuthResponseFromFramework(oAuthMessage, responseWrapper);
        } catch (ServletException | IOException | URLBuilderException e) {
            log.error("Error occurred while sending request to authentication framework.");
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private Response processAuthResponseFromFramework(OAuthMessage oAuthMessage,
                                                      CommonAuthResponseWrapper
                                                              responseWrapper)
            throws IOException, InvalidRequestParentException, URISyntaxException, URLBuilderException {

        if (AuthzUtil.isAuthFlowStateExists(oAuthMessage)) {
            if (AuthzUtil.isFlowStateIncomplete(oAuthMessage)) {
                return AuthzUtil.handleIncompleteFlow(oAuthMessage, responseWrapper);
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
        return handleInitialAuthzChallengeRequest(oAuthMessage.getRequest(), oAuthMessage.getResponse());

    }

    private Response handleSuccessfullyCompletedFlow(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        return handleInitialAuthzChallengeRequest(oAuthMessage.getRequest(), oAuthMessage.getResponse());
    }

    public Response handleInitialAuthorizationRequest(OAuthMessage oAuthMessage) throws OAuthSystemException,
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
            diagnosticLogBuilder.resultMessage("Successfully received OAuth2 Authorize Challenge request.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String redirectURL = handleOAuthAuthorizationRequest(oAuthMessage);
        String type = AuthzUtil.getRequestProtocolType(oAuthMessage);
        try {
            // Add the service provider id to the redirect URL. This is needed to support application wise branding.
            String clientId = oAuthMessage.getRequest().getParameter(CLIENT_ID);
            if (StringUtils.isNotBlank(clientId)) {
                ServiceProvider serviceProvider = AuthzUtil.getServiceProvider(clientId);
                if (serviceProvider != null) {
                    redirectURL = AuthzUtil.addServiceProviderIdToRedirectURI(redirectURL,
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

//            if (AuthzUtil.isApiBasedAuthenticationFlow(oAuthMessage)) {
                // Marking the initial request as additional validation will be done from the auth service.
                requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_IS_INITIAL_API_BASED_AUTH_REQUEST, true);
                requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_RELYING_PARTY, oAuthMessage.getClientId());

                AuthenticationService authenticationService = new AuthenticationService();
                AuthServiceResponse authServiceResponse = authenticationService.
                        handleAuthentication(new AuthServiceRequest(requestWrapper, responseWrapper));
                // This is done to provide a way to propagate the auth service response to needed places.
                AuthzUtil.attachAuthServiceResponseToRequest(requestWrapper, authServiceResponse);
//            } else {
//                CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();
//                commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);
//            }

            Object attribute = oAuthMessage.getRequest().getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
            if (attribute != null) {
                if (attribute == AuthenticatorFlowStatus.INCOMPLETE) {

                    if (responseWrapper.isRedirect()) {
                        return Response.status(HttpServletResponse.SC_FOUND)
                                .location(AuthzUtil.buildURI(responseWrapper.getRedirectURL())).build();
                    } else {
                        return Response.status(HttpServletResponse.SC_FORBIDDEN).entity(responseWrapper.getContent()).build();
                    }
                } else {
                    try {
                        String serviceProviderId =
                                AuthzUtil.getServiceProvider(oAuthMessage.getRequest().getParameter(CLIENT_ID))
                                        .getApplicationResourceId();
                        requestWrapper.setParameter(SERVICE_PROVIDER_ID, serviceProviderId);
                    } catch (Exception e) {
                        // The value is set to be used for branding purposes. Therefore, if an error occurs,
                        // the process should continue without breaking.
                        log.error("Error occurred while getting service provider id.");
                    }
                    return handleInitialAuthzChallengeRequest(requestWrapper, oAuthMessage.getResponse());
                }
            } else {
                requestWrapper
                        .setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
                return handleInitialAuthzChallengeRequest(requestWrapper, oAuthMessage.getResponse());
            }
        } catch (AuthServiceException e) {
            return AuthzUtil.handleApiBasedAuthErrorResponse(oAuthMessage.getRequest(), e);
        } catch (IOException | URLBuilderException e) {
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

    public static String handleOAuthAuthorizationRequest(OAuthMessage oAuthMessage)
            throws OAuthSystemException, OAuthProblemException, InvalidRequestException {

        OAuth2ClientValidationResponseDTO validationResponse = AuthzUtil.validateClient(oAuthMessage);

        if (!validationResponse.isValidClient()) {
            EndpointUtil.triggerOnRequestValidationFailure(oAuthMessage, validationResponse);
            return getErrorPageURL(oAuthMessage.getRequest(), validationResponse.getErrorCode(), OAuth2ErrorCodes
                    .OAuth2SubErrorCodes.INVALID_CLIENT, validationResponse.getErrorMsg(), null);
        } else {
            AuthzUtil.populateValidationResponseWithAppDetail(oAuthMessage, validationResponse);
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
            AuthzUtil.setSPAttributeToRequest(oAuthMessage.getRequest(), validationResponse.getApplicationName(), tenantDomain);
        }

        OAuthAuthzRequest oauthRequest = getOAuthAuthzRequest(oAuthMessage.getRequest());

        OAuth2Parameters params = new OAuth2Parameters();
        String sessionDataKey = UUID.randomUUID().toString();
        params.setSessionDataKey(sessionDataKey);
        String redirectURI = AuthzUtil.populateOauthParametersChallenge(params, oAuthMessage, validationResponse, oauthRequest);
        if (redirectURI != null) {
            return redirectURI;
        }
        // Check whether PAR should be mandated in  the request.
        AuthzUtil.checkPARMandatory(params, oAuthMessage);
        String prompt = oauthRequest.getParam(OAuthConstants.OAuth20Params.PROMPT);
        params.setPrompt(prompt);

        redirectURI = AuthzUtil.analyzePromptParameter(oAuthMessage, params, prompt);
        if (redirectURI != null) {
            return redirectURI;
        }

        if (AuthzUtil.isNonceMandatory(params.getResponseType())) {
            AuthzUtil.validateNonceParameter(params.getNonce());
        }

        if (AuthzUtil.isFapiConformant(params.getClientId())) {
            EndpointUtil.validateFAPIAllowedResponseTypeAndMode(params.getResponseType(), params.getResponseMode());
        }

        AuthzUtil.addDataToSessionCache(oAuthMessage, params, sessionDataKey);

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
            return AuthzUtil.handleException(e);
        }
    }

//    private Response initiateChallenge(OAuthMessage oAuthMessage) throws AuthServiceException {
//
//        String authCode = "c8da8db1-6023-4942-a1df-89e1d3d15e23";
//
//        if (AuthzChallengeUtils.isInitialRequest(oAuthMessage)) {
//            AuthzChallengeErrorResponse failureResponse = new AuthzChallengeErrorResponse();
//            failureResponse.setAuthSession(authCode);
//            failureResponse.setError(AuthzChallengeError.INSUFFICIENT_AUTHORIZATION);
//
//            return buildJsonResponse(failureResponse);
//        }
//
//        AuthzChallengeResponse successResponse = new AuthzChallengeResponse();
//        successResponse.setAuthorizationCode(authCode);
//
//        return buildJsonResponse(successResponse);
//    }

}

