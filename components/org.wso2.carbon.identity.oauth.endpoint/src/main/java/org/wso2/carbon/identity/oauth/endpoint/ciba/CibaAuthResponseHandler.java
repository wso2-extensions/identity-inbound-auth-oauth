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
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
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

    private CibaAuthResponseHandler() {

    }

    private static CibaAuthResponseHandler cibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();

    public static CibaAuthResponseHandler getInstance() {

        return cibaAuthResponseHandlerInstance;
    }

    /**
     * Creates CIBA AuthenticationResponse.
     *
     * @param cibaAuthResponseDTO CIBA Authentication Request Data Transfer Object.
     * @return Response for AuthenticationRequest.
     */
    public Response createAuthResponse(@Context HttpServletResponse response,
                                       CibaAuthResponseDTO cibaAuthResponseDTO, CibaAuthCodeDO cibaAuthCodeDO) {

        // Set the ExpiryTime.
        long expiresIn = CibaAuthUtil.getExpiresIn(cibaAuthResponseDTO);
        if (log.isDebugEnabled()) {
            log.info("Setting ExpiryTime for the response to the  request made by client with clientID : " +
                    cibaAuthResponseDTO.getAudience() + ".");
        }
        // Create authentication response.
        response.setContentType(MediaType.APPLICATION_JSON);

        // Creating authentication response for the request.
        JSONObject cibaAuthResponse = new JSONObject();
        cibaAuthResponse.put(CibaConstants.AUTH_REQ_ID, cibaAuthCodeDO.getAuthReqID());
        cibaAuthResponse.put(CibaConstants.EXPIRES_IN, expiresIn);
        cibaAuthResponse.put(CibaConstants.INTERVAL, CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);

        if (log.isDebugEnabled()) {
            log.info("Creating CIBA Authentication response to the request made by client with clientID : " +
                    cibaAuthResponseDTO.getAudience() + ".");
        }
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_OK);
        if (log.isDebugEnabled()) {
            log.info("Returning CIBA Authentication Response for the request made by client with clientID : " +
                    cibaAuthResponseDTO.getAudience() + ".");
        }
        return respBuilder.entity(cibaAuthResponse.toString()).build();
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaAuthFailureException CIBA Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     */
    public Response createErrorResponse(CibaAuthFailureException cibaAuthFailureException) {

        // Create CIBA Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }

        // Creating error response for the request.
        JSONObject cibaErrorResponse = new JSONObject();
        cibaErrorResponse.put("error", cibaAuthFailureException.getErrorCode());
        cibaErrorResponse.put("error_description", cibaAuthFailureException.getMessage());

        if (cibaAuthFailureException.getCause() != null) {
            log.error(cibaAuthFailureException.getCause());
        }
        Response.ResponseBuilder respBuilder = Response.status(cibaAuthFailureException.getStatus());
        return respBuilder.entity(cibaErrorResponse.toString()).build();
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaCoreException CIBA Component Core Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     */
    public Response createErrorResponse(CibaCoreException cibaCoreException) {

        // Create CIBA Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }

        // Creating error response for the request.
        JSONObject cibaErrorResponse = new JSONObject();
        cibaErrorResponse.put("error", OAuth2ErrorCodes.SERVER_ERROR);
        cibaErrorResponse.put("error_description", cibaCoreException.getMessage());

        if (cibaCoreException.getCause() != null) {
            log.error(cibaCoreException.getCause());
        }
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return respBuilder.entity(cibaErrorResponse.toString()).build();
    }
}
