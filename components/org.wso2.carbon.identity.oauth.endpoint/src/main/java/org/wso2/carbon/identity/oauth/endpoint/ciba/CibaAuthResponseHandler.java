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

import com.nimbusds.jwt.JWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthResponseDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailedException;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * This class handles authentication response.
 */
public class CibaAuthResponseHandler {

    private static final Log log = LogFactory.getLog(CibaAuthResponseHandler.class);

    private CibaAuthResponseHandler() {

    }

    private static CibaAuthResponseHandler cibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();

    public static CibaAuthResponseHandler getInstance() {

        if (cibaAuthResponseHandlerInstance == null) {

            synchronized (CibaAuthResponseHandler.class) {

                if (cibaAuthResponseHandlerInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();
                }
            }
        }
        return cibaAuthResponseHandlerInstance;

    }

    /**
     * Creates CIBA AuthenticationResponse.
     *
     * @param cibaAuthResponseDTO CIBA Authentication Request Data Transfer Object.
     * @return Response for AuthenticationRequest.
     * @throws CibaAuthFailedException Ciba Authentication Failed Exception.
     */
    public Response createAuthResponse(@Context HttpServletResponse response,
                                       CibaAuthResponseDTO cibaAuthResponseDTO, JWT cibaAuthCodeasJWT)
            throws CibaAuthFailedException {

        try {

            // Set the ExpiryTime.
            long expiresIn = CibaAuthUtil.getExpiresInForResponse(cibaAuthResponseDTO);
            if (log.isDebugEnabled()) {
                log.info("Setting ExpiryTime for the response to the  request made by client with clientID : " +
                        cibaAuthResponseDTO.getAudience() + ".");
            }

            // Serialize so that can be returned in preferable manner.
            String cibaAuthCode = cibaAuthCodeasJWT.serialize();
            if (log.isDebugEnabled()) {
                log.info("Ciba auth_req_id " + cibaAuthCode + " is created for the response to the request made by" +
                        " client with clientID : " + cibaAuthResponseDTO.getAudience() + ".");
            }

            // Create authentication response.
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON);

            CibaAuthResponseDO.CibaAuthResponseBuilder cibaAuthResponsebuilder = CibaAuthResponseDO
                    .cibaAuthenticationResponse(HttpServletResponse.SC_OK)
                    .setAuthReqID(cibaAuthCode)
                    .setExpiresIn(Long.toString(expiresIn))
                    .setInterval(Long.toString(CibaParams.INTERVAL_DEFAULT_VALUE));

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

            // Return respBuilder.entity(cibaAuthResponse.getBody()).build();
            return respBuilder.entity(cibaAuthenticationresponse.getBody()).build();

        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in building authenticationResponse for Authentication Request made by client with " +
                        "clientID : " + cibaAuthResponseDTO.getAudience() + ".");

            }

            throw new CibaAuthFailedException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());

        }

    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaAuthFailedException Ciba Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     * @throws OAuthSystemException SystemException.
     */
    public Response createErrorResponse(CibaAuthFailedException cibaAuthFailedException)
            throws OAuthSystemException {
        // Create CIBA Authentication Error Response.

        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }

        OAuthResponse errorresponse = OAuthASResponse
                .errorResponse(cibaAuthFailedException.getStatus())
                .setError(cibaAuthFailedException.getErrorCode())
                .setErrorDescription(cibaAuthFailedException.getErrorDescription())
                .buildJSONMessage();

        Response.ResponseBuilder respBuilder = Response.status(cibaAuthFailedException.getStatus());
        return respBuilder.entity(errorresponse.getBody()).build();
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaCoreException Ciba Component Core Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     * @throws OAuthSystemException SystemException.
     */
    public Response createErrorResponse(CibaCoreException cibaCoreException)
            throws OAuthSystemException {
        //Create CIBA Authentication Error Response.

        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }

        OAuthResponse errorresponse = OAuthASResponse
                .errorResponse(cibaCoreException.getStatus())
                .setError(cibaCoreException.getErrorCode())
                .setErrorDescription(cibaCoreException.getErrorDescription())
                .buildJSONMessage();

        Response.ResponseBuilder respBuilder = Response.status(cibaCoreException.getStatus());
        return respBuilder.entity(errorresponse.getBody()).build();
    }

}
