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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthResponse;
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
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public Response createAuthResponse(@Context HttpServletResponse response,
                                       CibaAuthResponseDTO cibaAuthResponseDTO, CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaAuthFailureException {

        try {
            // Set the ExpiryTime.
            long expiresIn = CibaAuthUtil.getExpiresIn(cibaAuthResponseDTO);
            if (log.isDebugEnabled()) {
                log.info("Setting ExpiryTime for the response to the  request made by client with clientID : " +
                        cibaAuthResponseDTO.getAudience() + ".");
            }
            // Create authentication response.
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON);

            CibaAuthResponse.CibaAuthResponseBuilder cibaAuthResponsebuilder = CibaAuthResponse
                    .cibaAuthenticationResponse(HttpServletResponse.SC_OK)
                    .setAuthReqID(cibaAuthCodeDO.getAuthReqID())
                    .setExpiresIn(Long.toString(expiresIn))
                    .setInterval(Long.toString(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC));

            if (log.isDebugEnabled()) {
                log.info("Creating CIBA Authentication response to the request made by client with clientID : " +
                        cibaAuthResponseDTO.getAudience() + ".");
            }
            Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
            OAuthResponse cibaAuthenticationresponse = cibaAuthResponsebuilder.buildJSONMessage();

            if (log.isDebugEnabled()) {
                log.info("Returning CIBA Authentication Response for the request made by client with clientID : " +
                        cibaAuthResponseDTO.getAudience() + ".");
            }
            return respBuilder.entity(cibaAuthenticationresponse.getBody()).build();
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in building authenticationResponse for Authentication Request made by client with " +
                        "clientID : " + cibaAuthResponseDTO.getAudience() + ".");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    OAuth2ErrorCodes.SERVER_ERROR, "error in creating authentication response.", e);
        }
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaAuthFailureException Ciba Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     * @throws OAuthSystemException SystemException.
     */
    public Response createErrorResponse(CibaAuthFailureException cibaAuthFailureException) throws OAuthSystemException {

        // Create CIBA Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }
        OAuthResponse errorResponse = OAuthASResponse
                .errorResponse(cibaAuthFailureException.getStatus())
                .setError(cibaAuthFailureException.getErrorCode())
                .setErrorDescription(cibaAuthFailureException.getMessage())
                .buildJSONMessage();

        if (cibaAuthFailureException.getCause() != null) {
            // Log stackTrace.
            log.error(cibaAuthFailureException.getCause());
        }
        Response.ResponseBuilder respBuilder = Response.status(cibaAuthFailureException.getStatus());
        return respBuilder.entity(errorResponse.getBody()).build();
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaCoreException Ciba Component Core Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     * @throws OAuthSystemException SystemException.
     */
    public Response createErrorResponse(CibaCoreException cibaCoreException) throws OAuthSystemException {

        //Create CIBA Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }
        OAuthResponse errorResponse = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .setError(OAuth2ErrorCodes.SERVER_ERROR)
                .setErrorDescription(cibaCoreException.getMessage())
                .buildJSONMessage();

        if (cibaCoreException.getCause() != null) {
            // Log stackTrace.
            log.error(cibaCoreException.getCause());
        }
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return respBuilder.entity(errorResponse.getBody()).build();
    }
}
