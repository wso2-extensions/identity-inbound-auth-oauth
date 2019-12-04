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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth.endpoint.factory.CibaServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;

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

        try {
            if (!requestParameterMap.containsKey(CibaConstants.REQUEST)) {
                // Mandatory 'request' parameter does not exist.

                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request that hits Client Initiated Authentication Endpoint has " +
                            "no 'request' parameter.");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "missing the mandated parameter : (request)");
            }

            // Capturing authentication request.
            String authRequest = request.getParameter(CibaConstants.REQUEST);

            if (log.isDebugEnabled()) {
                log.debug("CIBA Authentication Request with  'request' :" + authRequest + "  has hit Client " +
                        "Initiated Back-Channel Authentication EndPoint.");
            }

            CibaAuthRequestValidator.getInstance().validateRequest(authRequest);

            CibaAuthRequestValidator.getInstance().validateClient(authRequest);
            // The CIBA Authentication Request is with proper client.

            CibaAuthRequestValidator.getInstance().validateUserHint(authRequest);
            // The CIBA Authentication Request is with proper user hint.

            // Validate Authentication request.
            CibaAuthRequestValidator.getInstance().validateAuthRequestParams(authRequest);

            // Prepare RequestDTO with validated parameters.
            CibaAuthCodeRequest cibaAuthCodeRequest =
                    CibaAuthRequestValidator.getInstance().prepareRequestDTO(authRequest);

             // Obtain Response DTO from service layer of CIBA.
            CibaAuthCodeResponse cibaAuthCodeResponse = null;
            try {
                cibaAuthCodeResponse = EndpointUtil.getCibaAuthService().generateAuthCodeResponse(cibaAuthCodeRequest);
            } catch (CibaCoreException e) {
                throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error while generating " +
                        "authentication response.", e);
            }

            //  Internal authorize java call to /authorize end point.
            CibaAuthzHandler.getInstance().initiateAuthzRequest(cibaAuthCodeResponse, request, response);
            if (log.isDebugEnabled()) {
                log.info("Firing a Authorization request in regard to the request made by client with clientID: "
                        + cibaAuthCodeResponse.getClientId() + ".");
            }

            // Create and return Ciba Authentication Response.
            return CibaAuthResponseHandler.getInstance().createAuthResponse(response, cibaAuthCodeResponse);

        } catch (CibaAuthFailureException e) {
            //Returning error response.
            return CibaAuthResponseHandler.getInstance().createErrorResponse(e);
        }
    }
}
