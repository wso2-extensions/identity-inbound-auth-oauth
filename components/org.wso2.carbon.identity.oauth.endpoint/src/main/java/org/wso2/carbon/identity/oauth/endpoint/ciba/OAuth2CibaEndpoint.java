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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailedException;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("/ciba")
public class OAuth2CibaEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2CibaEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response ciba(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws OAuthSystemException {

        // Capture all  Authentication Request parameters.
        Map<String, String[]> requestParameterMap = request.getParameterMap();

        if (log.isDebugEnabled()) {
            log.debug("Authentication request has hit Client Initiated Back-channel Authentication EndPoint.");
        }

        // DTO to capture claims in request and to create response.
        CibaAuthRequestDTO cibaAuthRequestDTO = new CibaAuthRequestDTO();

        try {
            if (!requestParameterMap.containsKey(CibaParams.REQUEST)) {
                // Mandatory 'request' parameter does not exist.

                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request that hits Client Initiated Authentication Endpoint has " +
                            "no 'request' parameter.");
                }
                throw new CibaAuthFailedException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                        ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);

            }

            // Capturing authentication request.
            String authRequest = request.getParameter(CibaParams.REQUEST);

            if (log.isDebugEnabled()) {
                log.debug("CIBA Authentication Request with  'request' :" + authRequest + "  has hit Client " +
                        "Initiated Back-Channel Authentication EndPoint.");
            }

            CibaAuthRequestValidator.getInstance().validateRequest(authRequest);

            CibaAuthRequestValidator.getInstance().validateClient(authRequest, cibaAuthRequestDTO);
            // The CIBA Authentication Request is with proper client.
            if (log.isDebugEnabled()) {
                log.debug("CIBA Authentication Request 'request' :" + authRequest +
                        " is having a proper clientID : " + cibaAuthRequestDTO.getAudience() + " as the issuer.");
            }

            CibaAuthRequestValidator.getInstance().validateUser(authRequest, cibaAuthRequestDTO);
            // The CIBA Authentication Request is with proper user hint.
            if (log.isDebugEnabled()) {
                log.debug("CIBA Authentication Request made by Client with clientID," +
                        cibaAuthRequestDTO.getAudience() + " is having a proper user hint  : " +
                        cibaAuthRequestDTO.getUserHint() + ".");
            }

            if (CibaAuthRequestValidator.getInstance().isMatchingUserCode(authRequest, cibaAuthRequestDTO)) {
                // The CIBA Authentication Request is with proper user_code.
                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request made by Client with clientID," +
                            cibaAuthRequestDTO.getAudience() + " is having a proper user_code  : " +
                            cibaAuthRequestDTO.getUserCode() + ".");
                }
            }

            CibaAuthRequestValidator.getInstance().validateAuthRequestParameters(authRequest, cibaAuthRequestDTO);
            // Authentication request is validated.
            if (log.isDebugEnabled()) {
                log.debug("CIBA Authentication Request made by Client with clientID," +
                        cibaAuthRequestDTO.getAudience() + " is properly validated.");
            }

            // Building Authentication response DTO from RequestDTO.
            CibaAuthResponseDTO cibaAuthResponseDTO =
                    CibaAuthUtil.getInstance().buildCibaAuthResponseDTO(cibaAuthRequestDTO);

            // Create JWT as CibaAuthCode.
            JWT cibaAuthCodeasJWT = CibaAuthUtil.getInstance().getCibaAuthReqIDasSignedJWT(cibaAuthResponseDTO);
            if (log.isDebugEnabled()) {
                log.info("Creating CibaAuthCode as a JWT for the request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".");
            }

            // Build authCode from JWT with all the parameters that need to be persisted.
            CibaAuthCodeDO cibaAuthCodeDO =
                    CibaAuthUtil.getInstance()
                            .generateCibaAuthCodeDO(cibaAuthCodeasJWT.serialize(), cibaAuthResponseDTO);

            // Persist CibaAuthCode.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistCibaAuthCode(cibaAuthCodeDO);
            if (log.isDebugEnabled()) {
                log.info("Persisting CibaAuthCodeDO that accumulates parameters to be persisted in regard to the " +
                        "request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            // Build authorize request data transfer object.
            AuthzRequestDTO authzRequestDTO = CibaAuthUtil.getInstance().
                    buildAuthzRequestDO(cibaAuthResponseDTO, cibaAuthCodeDO);
            if (log.isDebugEnabled()) {
                log.info("Build CibaAuthzRequestDTO using  CibaAuthCodeDo in regard to the request made by " +
                        "client with clientID : " + cibaAuthResponseDTO.getAudience() + ".");
            }

            //  Internal authorize java call to /authorize end point.
            CibaAuthzHandler.getInstance().initiateAuthzRequest(authzRequestDTO, request, response);
            if (log.isDebugEnabled()) {
                log.info("Firing a Authorization request in regard to the request made by client with clientID : "
                        + cibaAuthResponseDTO.getAudience() + ".");
            }

            // Create and return Ciba Authentication Response.
            return CibaAuthResponseHandler.getInstance().createAuthResponse(response, cibaAuthResponseDTO
                    , cibaAuthCodeasJWT);

        } catch (CibaAuthFailedException e) {
            //Returning error response.
            return CibaAuthResponseHandler.getInstance().createErrorResponse(e);
        } catch (CibaCoreException e) {
            //Returning error response.
            return CibaAuthResponseHandler.getInstance().createErrorResponse(e);
        }
    }
}

