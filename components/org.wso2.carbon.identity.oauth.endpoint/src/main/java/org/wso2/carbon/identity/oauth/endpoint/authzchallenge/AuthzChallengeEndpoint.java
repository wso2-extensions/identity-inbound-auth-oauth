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
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnUtils;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthRequest;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.authzChallenge.event.AuthzChallengeInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.AuthzUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getErrorPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;
import static org.wso2.carbon.identity.openidconnect.model.Constants.SERVICE_PROVIDER_ID;


/**
 * Class containing the REST API for API based authentication.
 */

@Path("/authorize-challenge")
@InInterceptors(classes = {OAuthClientAuthenticatorProxy.class, ClientAttestationProxy.class})
public class AuthzChallengeEndpoint {

    private static final Log log = LogFactory.getLog(AuthzChallengeEndpoint.class);

    private final AuthenticationService authenticationService = new AuthenticationService();
    private static final AuthzChallengeEndpoint authzChallengeEndpoint = new AuthzChallengeEndpoint();
    private static final Log LOG = LogFactory.getLog(ApiAuthnEndpoint.class);

    public Response handleInitialAuthzChallengeRequest(@Context HttpServletRequest request, @Context HttpServletResponse response, boolean isInternalRequest)
            throws URISyntaxException, InvalidRequestParentException, AuthServiceException, IdentityOAuth2Exception {

        OAuthMessage oAuthMessage;

        AuthzUtil.setCommonAuthIdToRequest(request, response);

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
        if(!isInternalRequest){
            OAuthClientAuthnContext oAuthClientAuthnContext = AuthzUtil.getClientAuthnContext(request);
            if (!oAuthClientAuthnContext.isAuthenticated()) {
                return AuthzUtil.handleAuthFailureResponse(oAuthClientAuthnContext, true);
            }

            ClientAttestationContext clientAttestationContext = AuthzUtil.getClientAttestationContext(request);
            if (clientAttestationContext.isAttestationEnabled() && !clientAttestationContext.isAttested()) {
                return AuthzUtil.handleAttestationFailureResponse(clientAttestationContext);
            }

            if (!OAuth2Util.isApiBasedAuthSupportedGrant(request)) {
                return AuthzUtil.handleUnsupportedGrantForApiBasedAuth();
            }
        }


        AuthzChallengeInterceptor authzChallengeInterceptor = OAuth2ServiceComponentHolder.getInstance().getAuthzChallengeInterceptorHandlerProxy();
        if (authzChallengeInterceptor != null && authzChallengeInterceptor.isEnabled()) {
            OAuth2AuthzChallengeReqDTO requestDTO = buildAuthzChallengeReqDTO(request);
            authzChallengeInterceptor.handleAuthzChallengeReq(requestDTO);
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
            oauthResponse = AuthzUtil.handleApiBasedAuthenticationResponse(oAuthMessage, oauthResponse, true);
//            String authSession = extractAuthSession(oauthResponse);
//            System.out.println("Auth Session: " + authSession);
//            System.out.println("Thumbprint: " + thumbprint);
            return oauthResponse;
        } catch (OAuthProblemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleOAuthProblemException(oAuthMessage, e);
        } catch (OAuthSystemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleOAuthSystemException(oAuthMessage, e);
//        } catch (JsonProcessingException e) {
//            throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
//                    "Error while extracting auth_session.", e);
        }finally {
            AuthzUtil.handleCachePersistence(oAuthMessage);
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    private Response handleSubsequentAuthzChallengeRequest(@Context HttpServletRequest request, @Context HttpServletResponse response, String payload) throws AuthServiceException {
        try {
            if(isSubsequentAuthzChallengeRequest(payload)) {
                payload = renameAuthSessionToFlowId(payload);
            }
            AuthRequest authRequest = ApiAuthnUtils.buildAuthRequest(payload);
            AuthServiceRequest authServiceRequest = ApiAuthnUtils.getAuthServiceRequest(request, response, authRequest);
            AuthServiceResponse authServiceResponse = authenticationService.handleAuthentication(authServiceRequest);

            switch (authServiceResponse.getFlowStatus()) {
                case INCOMPLETE:
                    return ApiAuthnUtils.handleIncompleteAuthResponse(authServiceResponse, true);
                case SUCCESS_COMPLETED:
                    return handleSuccessCompletedAuthResponse(request, response, authServiceResponse);
                case FAIL_INCOMPLETE:
                    return ApiAuthnUtils.handleFailIncompleteAuthResponse(authServiceResponse, true);
                case FAIL_COMPLETED:
                    return ApiAuthnUtils.handleFailCompletedAuthResponse(authServiceResponse);
                default:
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_UNKNOWN_AUTH_FLOW_STATUS.code(),
                            String.format(AuthServiceConstants.ErrorMessage.ERROR_UNKNOWN_AUTH_FLOW_STATUS
                                    .description(), authServiceResponse.getFlowStatus()));
            }

        } catch (AuthServiceClientException e) {
            return ApiAuthnUtils.buildResponseForClientError(e, LOG);
        } catch (AuthServiceException e) {
            return ApiAuthnUtils.buildResponseForServerError(e, LOG);
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
                                           @Context HttpServletResponse response,
                                           MultivaluedMap paramMap) {
        try {
            Map<String, String[]> parameterMap = request.getParameterMap();

            if (parameterMap.containsKey("client_id") && parameterMap.containsKey("response_type")) {

                if (!validateParams(request, paramMap)) {
                    return Response.status(HttpServletResponse.SC_BAD_REQUEST)
                            .location(new URI(getErrorPageURL(request,
                                    OAuth2ErrorCodes.INVALID_REQUEST,
                                    OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST,
                                    "Invalid authorization request with repeated parameters", null)))
                            .build();
                }
                HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
                return handleInitialAuthzChallengeRequest(httpRequest, response, false);
            }

            throw new AuthServiceException(
                    AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Invalid request parameters for /authorize-challenge."
            );
        } catch (AuthServiceClientException e) {
            log.error("Client error while handling authentication request.", e);
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).build();
        }catch (IdentityOAuth2Exception e){
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
    public Response authorizeChallengeSubsequentPost(@Context HttpServletRequest request, @Context HttpServletResponse response, String payload) {
        try {
            if (payload != null && payload.contains("\"auth_session\"")) {
                return handleSubsequentAuthzChallengeRequest(request, response, payload);
            }

            throw new AuthServiceException(
                    AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Invalid request parameters for /authorize-challenge."
            );

        } catch (AuthServiceClientException e) {
            log.error("Client error while handling authentication request.", e);
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).build();
        } catch (AuthServiceException e) {
            log.error("Error occurred while handling authorize challenge request.", e);
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private String renameAuthSessionToFlowId(String payload) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(payload);

        ObjectNode objectNode = (ObjectNode) jsonNode;
        JsonNode authSessionValue = objectNode.remove("auth_session");
        objectNode.set("flowId", authSessionValue);
        return objectMapper.writeValueAsString(objectNode);
    }

    private String extractAuthSession(Response response) throws JsonProcessingException {

        String responseJson = response.getEntity().toString();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(responseJson);
        return jsonNode.get("auth_session").asText();
    }

    private boolean isSubsequentAuthzChallengeRequest(String payload) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(payload);

        return jsonNode.has("auth_session");
    }

    private Response handleAuthFlowThroughFramework(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        try {
            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(oAuthMessage.getResponse());
            AuthzUtil.invokeCommonauthFlow(oAuthMessage, responseWrapper);
            return processAuthResponseFromFramework(oAuthMessage, responseWrapper);
        } catch (ServletException | IOException | URLBuilderException | AuthServiceException | IdentityOAuth2Exception e) {
            log.error("Error occurred while sending request to authentication framework.");
            return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
        }
    }

    private Response processAuthResponseFromFramework(OAuthMessage oAuthMessage,
                                                      CommonAuthResponseWrapper
                                                              responseWrapper)
            throws IOException, InvalidRequestParentException, URISyntaxException, URLBuilderException,
            AuthServiceException, IdentityOAuth2Exception {

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
            throws URISyntaxException, InvalidRequestParentException, AuthServiceException, IdentityOAuth2Exception {

        oAuthMessage.getRequest().setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus
                .UNKNOWN);
        return handleInitialAuthzChallengeRequest(oAuthMessage.getRequest(), oAuthMessage.getResponse(),true);

    }

    private Response handleSuccessfullyCompletedFlow(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException, AuthServiceException, IdentityOAuth2Exception {

        return handleInitialAuthzChallengeRequest(oAuthMessage.getRequest(), oAuthMessage.getResponse(),true);
    }

    public Response handleInitialAuthorizationRequest(OAuthMessage oAuthMessage) throws OAuthSystemException,
            OAuthProblemException, URISyntaxException, InvalidRequestParentException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            AuthzUtil.logOAuth2InitialRequest(oAuthMessage);
        }
        String redirectURL = AuthzUtil.handleOAuthAuthorizationRequest(oAuthMessage);
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

            // Marking the initial request as additional validation will be done from the auth service.
            requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_IS_INITIAL_API_BASED_AUTH_REQUEST, true);
            requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_RELYING_PARTY, oAuthMessage.getClientId());

            AuthenticationService authenticationService = new AuthenticationService();
            AuthServiceResponse authServiceResponse = authenticationService.
                    handleAuthentication(new AuthServiceRequest(requestWrapper, responseWrapper));
            // This is done to provide a way to propagate the auth service response to needed places.
            AuthzUtil.attachAuthServiceResponseToRequest(requestWrapper, authServiceResponse);

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
                    return handleInitialAuthzChallengeRequest(requestWrapper, oAuthMessage.getResponse(),true);
                }
            } else {
                requestWrapper
                        .setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
                return handleInitialAuthzChallengeRequest(requestWrapper, oAuthMessage.getResponse(),true);
            }
        } catch (AuthServiceException e) {
            return AuthzUtil.handleApiBasedAuthErrorResponse(oAuthMessage.getRequest(), e);
        } catch (IOException | URLBuilderException | IdentityOAuth2Exception e) {
            return AuthzUtil.handleAuthenticationFrameworkError(oAuthMessage, e);
        }
    }

    private Response handleSuccessCompletedAuthResponse(HttpServletRequest request, HttpServletResponse response,
                                                        AuthServiceResponse authServiceResponse)
            throws AuthServiceException {

        String callerSessionDataKey = authServiceResponse.getSessionDataKey();

        OAuthRequestWrapper internalRequest = ApiAuthnUtils.createInternalRequest(request, callerSessionDataKey);

        try {
            return authzChallengeEndpoint.handleInitialAuthzChallengeRequest(internalRequest, response, true);
        } catch (InvalidRequestParentException | URISyntaxException e) {
            throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Error while processing the final oauth authorization request.", e);
        } catch (IdentityOAuth2Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static OAuth2AuthzChallengeReqDTO buildAuthzChallengeReqDTO(HttpServletRequest request) {
        OAuth2AuthzChallengeReqDTO dto = new OAuth2AuthzChallengeReqDTO();

        dto.setClientId(request.getParameter("client_id"));
        dto.setResponseType(request.getParameter("response_type"));
        dto.setRedirectUri(request.getParameter("redirect_uri"));
        dto.setState(request.getParameter("state"));
        dto.setScope(request.getParameter("scope"));

        // Extract HTTP request headers
        dto.setHttpRequestHeaders(extractHeaders(request));

        // Wrap the request
        dto.setHttpServletRequestWrapper(new HttpServletRequestWrapper(request));

        return dto;
    }

    private static HttpRequestHeader[] extractHeaders(HttpServletRequest request) {
        Enumeration<String> headerNames = request.getHeaderNames();

        if (headerNames == null || !headerNames.hasMoreElements()) {
            return null; // No headers found
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

}

