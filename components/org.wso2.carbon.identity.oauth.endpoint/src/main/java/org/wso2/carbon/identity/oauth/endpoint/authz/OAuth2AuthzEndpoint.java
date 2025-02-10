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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
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
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.AuthzUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getErrorPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;
import static org.wso2.carbon.identity.openidconnect.model.Constants.SERVICE_PROVIDER_ID;

/**
 * Rest implementation of OAuth2 authorize endpoint.
 */
@Path("/authorize")
@InInterceptors(classes = {OAuthClientAuthenticatorProxy.class, ClientAttestationProxy.class})
public class OAuth2AuthzEndpoint {

    private static OpenIDConnectClaimFilterImpl openIDConnectClaimFilter;

    private static ScopeMetadataService scopeMetadataService;

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
    private static DeviceAuthService deviceAuthService;

    private static final Log log = LogFactory.getLog(OAuth2AuthzEndpoint.class);

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException {

        OAuthMessage oAuthMessage;

        // TODO: 2021-01-22 Check for the flag in request.
        AuthzUtil.setCommonAuthIdToRequest(request, response);

        // Using a separate try-catch block as this next try block has operations in the final block.
        try {
            request = RequestUtil.buildRequest(request);
            oAuthMessage = AuthzUtil.buildOAuthMessage(request, response);

        } catch (InvalidRequestParentException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            throw e;
        } catch (IdentityException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleIdentityException(request, e);
        }

        // Perform request authentication for API based auth flow.
        if (OAuth2Util.isApiBasedAuthenticationFlow(request)) {
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
        }

        try {
            // Start tenant domain flow if the tenant configuration is not enabled.
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                String tenantDomain = null;
                if (StringUtils.isNotEmpty(oAuthMessage.getClientId())) {
                    tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
                } else if (oAuthMessage.getSessionDataCacheEntry() != null) {
                    OAuth2Parameters oauth2Params = AuthzUtil.getOauth2Params(oAuthMessage);
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

            if (AuthzUtil.isApiBasedAuthenticationFlow(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleApiBasedAuthenticationResponse(oAuthMessage, oauthResponse, false);
            }

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

    /**
     * Set the device authentication service.
     *
     * @param deviceAuthService Device authentication service.
     */
    public static void setDeviceAuthService(DeviceAuthService deviceAuthService) {

        OAuth2AuthzEndpoint.deviceAuthService = deviceAuthService;
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
        return authorize(oAuthMessage.getRequest(), oAuthMessage.getResponse());

    }

    private Response handleSuccessfullyCompletedFlow(OAuthMessage oAuthMessage)
            throws URISyntaxException, InvalidRequestParentException {

        return authorize(oAuthMessage.getRequest(), oAuthMessage.getResponse());
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

            if (AuthzUtil.isApiBasedAuthenticationFlow(oAuthMessage)) {
                // Marking the initial request as additional validation will be done from the auth service.
                requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_IS_INITIAL_API_BASED_AUTH_REQUEST, true);
                requestWrapper.setAttribute(AuthServiceConstants.REQ_ATTR_RELYING_PARTY, oAuthMessage.getClientId());

                AuthenticationService authenticationService = new AuthenticationService();
                AuthServiceResponse authServiceResponse = authenticationService.
                        handleAuthentication(new AuthServiceRequest(requestWrapper, responseWrapper));
                // This is done to provide a way to propagate the auth service response to needed places.
                AuthzUtil.attachAuthServiceResponseToRequest(requestWrapper, authServiceResponse);
            } else {
                CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();
                commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);
            }

            Object attribute = oAuthMessage.getRequest().getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
            if (attribute != null) {
                if (attribute == AuthenticatorFlowStatus.INCOMPLETE) {

                    if (responseWrapper.isRedirect()) {
                        return Response.status(HttpServletResponse.SC_FOUND)
                                .location(AuthzUtil.buildURI(responseWrapper.getRedirectURL())).build();
                    } else {
                        return Response.status(HttpServletResponse.SC_OK).entity(responseWrapper.getContent()).build();
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
                    return authorize(requestWrapper, oAuthMessage.getResponse());
                }
            } else {
                requestWrapper
                        .setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
                return authorize(requestWrapper, oAuthMessage.getResponse());
            }
        } catch (AuthServiceException e) {
            return AuthzUtil.handleApiBasedAuthErrorResponse(oAuthMessage.getRequest(), e);
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

}
