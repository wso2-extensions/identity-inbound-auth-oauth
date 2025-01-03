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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnHandler;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.ApiAuthnUtils;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.SuccessCompleteAuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;
import org.wso2.carbon.identity.oauth.endpoint.authzchallenge.AuthzChallengeUtils;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.CLIENT_ATTESTATION_CONTEXT;


/**
 * Class containing the REST API for API based authentication.
 */

// Server does not recognize new class :/
@Path("/authorize-challenge")
public class AuthzChallengeEndpoint {

    private static final String AUTH_SERVICE_RESPONSE = "authServiceResponse";
    private static final String IS_API_BASED_AUTH_HANDLED = "isApiBasedAuthHandled";
    private static final ApiAuthnHandler API_AUTHN_HANDLER = new ApiAuthnHandler();
    private static final Log log = LogFactory.getLog(AuthzChallengeEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorizeChallenge(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException, AuthServiceException {

        OAuthMessage oAuthMessage;

        try{
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

//        OAuthClientAuthnContext oAuthClientAuthnContext = getClientAuthnContext(request);
//        if (!oAuthClientAuthnContext.isAuthenticated()) {
//            return handleAuthFailureResponse(oAuthClientAuthnContext);
//        }

        if(AuthzChallengeUtils.validateRequest(oAuthMessage)) {
            return initiateChallenge(oAuthMessage);
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    private Response initiateChallenge(OAuthMessage oAuthMessage) throws AuthServiceException {

        String authCode = "c8da8db1-6023-4942-a1df-89e1d3d15e23";

        if (AuthzChallengeUtils.isInitialRequest(oAuthMessage)) {
            AuthzChallengeErrorResponse failureResponse = new AuthzChallengeErrorResponse();
            failureResponse.setAuthSession(authCode);
            failureResponse.setError(AuthzChallengeError.INSUFFICIENT_AUTHORIZATION);

            return buildJsonResponse(failureResponse);
        }

        AuthzChallengeResponse successResponse = new AuthzChallengeResponse();
        successResponse.setAuthorizationCode(authCode);

        return buildJsonResponse(successResponse);
    }

    private Response buildJsonResponse(Object responseObject) throws AuthServiceException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY); // Exclude null/empty fields
        String jsonString;

        try {
            jsonString = objectMapper.writeValueAsString(responseObject);
        } catch (JsonProcessingException e) {
            throw new AuthServiceException(
                    AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
                    "Error while building JSON response.",
                    e
            );
        }

        return Response.ok().entity(jsonString).type("application/json").build();
    }

    private OAuthMessage buildOAuthMessage(HttpServletRequest request, HttpServletResponse response)
            throws InvalidRequestParentException {

        return new OAuthMessage.OAuthMessageBuilder()
                .setRequest(request)
                .setResponse(response)
                .build();
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

    public static Response handleIdentityException(HttpServletRequest request, IdentityException e)
            throws URISyntaxException {

        if (OAuth2ErrorCodes.SERVER_ERROR.equals(e.getErrorCode())) {
            if (log.isDebugEnabled()) {
                log.debug("Server error occurred while performing authorization", e);
            }
            OAuthProblemException ex = OAuthProblemException.error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Server error occurred while performing authorization");
            return Response.status(HttpServletResponse.SC_FOUND).location(new URI(
                    EndpointUtil.getErrorRedirectURL(request, ex, null))).build();
        }
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(EndpointUtil.getErrorPageURL(request,
                e.getErrorCode(), OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST,
                e.getMessage(), null))).build();
    }

    public static OAuthClientAuthnContext getClientAuthnContext(HttpServletRequest request) {

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
                        "API-based authorization is only supported with code response type."), log);
    }
}

