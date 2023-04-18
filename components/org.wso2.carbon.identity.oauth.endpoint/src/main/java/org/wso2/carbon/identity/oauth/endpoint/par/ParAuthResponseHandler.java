/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.par;


import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.exception.ParErrorDTO;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.model.ParAuthCodeResponse;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

/**
 * Handles creation of authentication and error response.
 */
public class ParAuthResponseHandler {

    private static final Log log = LogFactory.getLog(ParAuthResponseHandler.class);
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPRION = "error_description";

    /**
     * Creates PAR AuthenticationResponse.
     *
     * @param parAuthCodeResponse PAR Authentication Request Data Transfer Object.
     * @return Response for AuthenticationRequest.
     */
    public Response createAuthResponse(@Context HttpServletResponse response, ParAuthCodeResponse parAuthCodeResponse) {

        String requestUri = "urn:ietf:params:wso2is:request_uri:" + UUID.randomUUID();

        if (log.isDebugEnabled()) {
            log.debug("Setting ExpiryTime for the response to the  request made by client with clientID : " +
                    parAuthCodeResponse.getClientId() + ".");
        }

        response.setContentType(MediaType.APPLICATION_JSON);

        JSONObject parAuthResponse = new JSONObject();
        parAuthResponse.put(ParConstants.REQUEST_URI, requestUri);
        parAuthResponse.put(ParConstants.EXPIRES_IN, ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC);

        if (log.isDebugEnabled()) {
            log.debug("Creating PAR Authentication response to the request made by client with clientID : " +
                    parAuthCodeResponse.getClientId() + ".");
        }

        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_CREATED);
        if (log.isDebugEnabled()) {
            log.debug("Returning PAR Authentication Response for the request made by client with clientID : " +
                    parAuthCodeResponse.getClientId() + ".");
        }

        parAuthCodeResponse.setRequestUri(requestUri);
        return responseBuilder.entity(parAuthResponse.toString()).build();
    }

    /**
     * Creates PAR Authentication Error Response.
     *
     * @param oAuth2ClientValidationResponseDTO Ciba Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     */
    public Response createErrorResponse(OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO) {

        // Create PAR Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for PAR Authentication Request.");
        }

        if (oAuth2ClientValidationResponseDTO.getErrorCode().equals(OAuth2ErrorCodes.SERVER_ERROR)) {
            return handleServerException(oAuth2ClientValidationResponseDTO);
        } else {
            return handleClientException(oAuth2ClientValidationResponseDTO);
        }
    }

    /**
     * Creates PAR Authentication Error Response.
     *
     * @param parErrorDTO PAR Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     */
    public Response createErrorResponse(ParErrorDTO parErrorDTO) {

        // Create PAR Authentication Error Response.
        log.debug("Creating Error Response for PAR Authentication Request.");

        if (parErrorDTO.getErrorCode() == parErrorDTO.getErrorCode()) {
            return handleClientException(parErrorDTO);
        } else {
            return null;
        }
    }

    /**
     * Handles server exception.
     *
     * @param oAuth2ClientValidationResponseDTO Authentication Failure Exception.
     * @return Response for AuthenticationRequest.
     */
    public Response handleServerException(OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO) {

        return null;
    }

    /**
     * Handles client exception.
     *
     * @param oAuth2ClientValidationResponseDTO Authentication Failure Exception.
     * @return Response for AuthenticationRequest.
     */
    public Response handleClientException(OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO) {

        String errorCode = oAuth2ClientValidationResponseDTO.getErrorCode();
        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(ERROR, oAuth2ClientValidationResponseDTO.getErrorCode());
        parErrorResponse.put(ERROR_DESCRIPRION, oAuth2ClientValidationResponseDTO.getErrorMsg());

        Response.ResponseBuilder responseBuilder;
        if (errorCode.equals(OAuth2ErrorCodes.INVALID_CLIENT)) {
            responseBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        }
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }

    /**
     * Handles client exception.
     *
     * @param parErrorDTO Authentication Failure Exception.
     * @return Response for AuthenticationRequest.
     */
    public Response handleClientException(ParErrorDTO parErrorDTO) {

        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(ERROR, parErrorDTO.getErrorMsg());
        parErrorResponse.put(ERROR_DESCRIPRION, "request.with.request_uri.not.allowed");

        Response.ResponseBuilder responseBuilder;
        responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }
}
