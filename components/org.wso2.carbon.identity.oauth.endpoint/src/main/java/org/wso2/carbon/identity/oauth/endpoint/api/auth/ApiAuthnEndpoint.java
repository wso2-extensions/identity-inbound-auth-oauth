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

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceErrorInfo;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.APIError;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthRequest;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Class containing the REST API for API based authentication.
 */
@Path("/authn")
public class ApiAuthnEndpoint {

    private final AuthenticationService authenticationService = new AuthenticationService();
    private final OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();
    private static final String AUTHENTICATOR = "authenticator";
    private static final String IDP = "idp";
    private static final Log LOG = LogFactory.getLog(ApiAuthnEndpoint.class);
    private static final ApiAuthnHandler API_AUTHN_HANDLER = new ApiAuthnHandler();

    @POST
    @Path("/")
    @Consumes("application/json")
    @Produces("application/json")
    public Response handleAuthentication(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                         String payload) {

        try {
            AuthRequest authRequest = buildAuthRequest(payload);
            AuthServiceRequest authServiceRequest = getAuthServiceRequest(request, response, authRequest);
            AuthServiceResponse authServiceResponse = authenticationService.handleAuthentication(authServiceRequest);

            switch (authServiceResponse.getFlowStatus()) {
                case INCOMPLETE:
                    return handleIncompleteAuthResponse(authServiceResponse);
                case SUCCESS_COMPLETED:
                    return handleSuccessCompletedAuthResponse(request, response, authServiceResponse);
                case FAIL_INCOMPLETE:
                    return handleFailIncompleteAuthResponse(authServiceResponse);
                case FAIL_COMPLETED:
                    return handleFailCompletedAuthResponse(authServiceResponse);
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
        }
    }

    private AuthRequest buildAuthRequest(String payload) throws AuthServiceClientException {

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(payload, AuthRequest.class);
        } catch (JsonProcessingException e) {
            // Throwing a client exception here as the exception can occur due to a malformed request.
            throw new AuthServiceClientException(AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Error occurred while parsing the authentication request.", e);
        }
    }

    private Response buildResponse(AuthResponse response) throws AuthServiceException {

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        String jsonString;
        try {
            jsonString = objectMapper.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
                    "Error while building JSON response.", e);
        }
        return Response.ok().entity(jsonString).build();
    }

    private AuthServiceRequest getAuthServiceRequest(HttpServletRequest request, HttpServletResponse response,
                                                     AuthRequest authRequest) throws AuthServiceClientException {

        Map<String, String[]> params = new HashMap<>();
        params.put(OAuthConstants.SESSION_DATA_KEY, new String[]{authRequest.getFlowId()});

        String authenticatorId = authRequest.getSelectedAuthenticator().getAuthenticatorId();
        if (authenticatorId != null) {
            String decodedAuthenticatorId = base64URLDecode(authenticatorId);
            String[] authenticatorIdSplit = decodedAuthenticatorId.split(OAuthConstants.AUTHENTICATOR_IDP_SPLITTER);

            if (authenticatorIdSplit.length == 2) {
                params.put(AUTHENTICATOR, new String[]{authenticatorIdSplit[0]});
                params.put(IDP, new String[]{authenticatorIdSplit[1]});
            } else {
                throw new AuthServiceClientException(
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTHENTICATOR_ID.code(),
                        String.format(AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTHENTICATOR_ID.description(),
                                authenticatorId));
            }
        } else {
            throw new AuthServiceClientException(
                    AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTHENTICATOR_ID.code(),
                    "Authenticator id is not provided.");
        }

        Map<String, String[]> authParams = authRequest.getSelectedAuthenticator().getParams().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> new String[]{e.getValue()}));
        params.putAll(authParams);

        return new AuthServiceRequest(request, response, params);
    }

    private String base64URLDecode(String value) {

        return new String(
                Base64.getUrlDecoder().decode(value),
                StandardCharsets.UTF_8);
    }

    private Response handleSuccessCompletedAuthResponse(HttpServletRequest request, HttpServletResponse response,
                                                        AuthServiceResponse authServiceResponse)
            throws AuthServiceException {

        String callerSessionDataKey = authServiceResponse.getSessionDataKey();

        Map<String, List<String>> internalParamsList = new HashMap<>();
        internalParamsList.put(OAuthConstants.SESSION_DATA_KEY, Collections.singletonList(callerSessionDataKey));
        OAuthRequestWrapper internalRequest = new OAuthRequestWrapper(request, internalParamsList);
        internalRequest.setInternalRequest(true);

        try {
            return oAuth2AuthzEndpoint.authorize(internalRequest, response);
        } catch (InvalidRequestParentException | URISyntaxException e) {
            throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                    "Error while processing the final oauth authorization request.", e);
        }
    }

    private Response handleIncompleteAuthResponse(AuthServiceResponse authServiceResponse) throws AuthServiceException {

        AuthResponse authResponse = API_AUTHN_HANDLER.handleResponse(authServiceResponse);
        return buildResponse(authResponse);
    }

    private Response handleFailIncompleteAuthResponse(AuthServiceResponse authServiceResponse)
            throws AuthServiceException {

        AuthResponse authResponse = API_AUTHN_HANDLER.handleResponse(authServiceResponse);
        return buildResponse(authResponse);
    }

    private Response handleFailCompletedAuthResponse(AuthServiceResponse authServiceResponse) {

        APIError apiError = new APIError();
        if (authServiceResponse.getErrorInfo().isPresent()) {
            AuthServiceErrorInfo errorInfo = authServiceResponse.getErrorInfo().get();
            apiError.setCode(errorInfo.getErrorCode());
            apiError.setMessage(errorInfo.getErrorMessage());
            apiError.setDescription(errorInfo.getErrorDescription());
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error info is not present in the authentication service response. " +
                        "Setting default error details.");
            }
            apiError.setCode(getDefaultAuthenticationFailureError().code());
            apiError.setMessage(getDefaultAuthenticationFailureError().message());
            apiError.setDescription(getDefaultAuthenticationFailureError().description());
        }
        apiError.setTraceId(ApiAuthnUtils.getCorrelationId());
        String jsonString = new Gson().toJson(apiError);
        /* Authentication FAIL_COMPLETED status could happen due to both client errors and server errors.
         Generally FAIL_COMPLETED status is received when an authenticator throws a AuthenticationFailedException
         and this exception could be thrown for both client and server errors and with the current framework
         implementation it is not possible to distinguish between these two types of errors. Therefore,
         it was decided to set the http status code to 400.*/
        return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity(jsonString).build();
    }

    private AuthServiceConstants.ErrorMessage getDefaultAuthenticationFailureError() {

        return AuthServiceConstants.ErrorMessage.ERROR_AUTHENTICATION_FAILURE;
    }
}
