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

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Handles creation of authentication and error response.
 */
public class CibaAuthResponseHandler {

    private static final Log log = LogFactory.getLog(CibaAuthResponseHandler.class);

    /**
     * Creates CIBA AuthenticationResponse.
     *
     * @param cibaAuthCodeResponse CIBA Authentication Request Data Transfer Object.
     * @return Response for AuthenticationRequest.
     */
    public Response createAuthResponse(@Context HttpServletResponse response,
                                       CibaAuthCodeResponse cibaAuthCodeResponse) {

        // Set the ExpiryTime.
        long expiresIn = cibaAuthCodeResponse.getExpiresIn();
        if (log.isDebugEnabled()) {
            log.info("Setting ExpiryTime for the response to the  request made by client with clientID : " +
                    cibaAuthCodeResponse.getClientId() + ".");
        }
        // Create authentication response.
        response.setContentType(MediaType.APPLICATION_JSON);

        // Creating authentication response for the request.
        JSONObject cibaAuthResponse = new JSONObject();
        cibaAuthResponse.put(CibaConstants.AUTH_REQ_ID, cibaAuthCodeResponse.getAuthReqId());
        cibaAuthResponse.put(CibaConstants.EXPIRES_IN, expiresIn);
        cibaAuthResponse.put(CibaConstants.INTERVAL, CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);

        if (log.isDebugEnabled()) {
            log.info("Creating CIBA Authentication response to the request made by client with clientID : " +
                    cibaAuthCodeResponse.getClientId() + ".");
        }
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_OK);
        if (log.isDebugEnabled()) {
            log.info("Returning CIBA Authentication Response for the request made by client with clientID : " +
                    cibaAuthCodeResponse.getClientId() + ".");
        }
        return respBuilder.entity(cibaAuthResponse.toString()).build();
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaAuthFailureException Ciba Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     */
    public Response createErrorResponse(CibaAuthFailureException cibaAuthFailureException) {

        // Create CIBA Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }

        if (cibaAuthFailureException.getErrorCode().equals(OAuth2ErrorCodes.SERVER_ERROR)) {

            return handleServerError(cibaAuthFailureException);
        } else {
            return handleClientException(cibaAuthFailureException);
        }
    }

    /**
     * Handles client exception.
     *
     * @param cibaAuthFailureException Authentication Failure Exception.
     * @return Response for AuthenticationRequest.
     */
    private Response handleClientException(CibaAuthFailureException cibaAuthFailureException) {

        String errorCode = cibaAuthFailureException.getErrorCode();
        JSONObject cibaErrorResponse = new JSONObject();
        cibaErrorResponse.put("error", cibaAuthFailureException.getErrorCode());
        cibaErrorResponse.put("error_description", cibaAuthFailureException.getMessage());

        if (errorCode.equals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT) || errorCode.equals(ErrorCodes.UNAUTHORIZED_USER)) {

            // Creating error response for the request.
            Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED);
            return respBuilder.entity(cibaErrorResponse.toString()).build();

        } else {
            Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
            return respBuilder.entity(cibaErrorResponse.toString()).build();
        }
    }

    /**
     * Handles server exception.
     *
     * @param cibaAuthFailureException Authentication Failure Exception.
     * @return Response for AuthenticationRequest.
     */
    private Response handleServerError(CibaAuthFailureException cibaAuthFailureException) {

        // Creating error response for the request.
        JSONObject cibaErrorResponse = new JSONObject();
        cibaErrorResponse.put("error", cibaAuthFailureException.getErrorCode());
        cibaErrorResponse.put("error_description", cibaAuthFailureException.getMessage());

        if (cibaAuthFailureException.getCause() != null) {
            log.error(cibaAuthFailureException);
        }
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return respBuilder.entity(cibaErrorResponse.toString()).build();
    }
}
