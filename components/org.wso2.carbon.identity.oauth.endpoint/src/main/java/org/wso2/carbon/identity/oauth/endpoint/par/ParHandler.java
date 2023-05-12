/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.par;


import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.dao.CacheBackedParDAO;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;

import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;

/**
 * Handles creation of authentication and error response.
 */
public class ParHandler {

    private static final Log log = LogFactory.getLog(ParHandler.class);
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPRION = "error_description";
    private static String uuid;

    private static final ParMgtDAO parMgtDAO = ParDAOFactory.getInstance().getParAuthMgtDAO();

    /**
     * Creates PAR AuthenticationResponse.
     *
     * @return Response for AuthenticationRequest.
     */
    public Response createAuthResponse(HttpServletResponse response) {

        uuid = String.valueOf(UUID.randomUUID());

        if (log.isDebugEnabled()) {
            log.debug("Setting ExpiryTime for the response to the  request.");
        }

        response.setContentType(MediaType.APPLICATION_JSON);

        JSONObject parAuthResponse = new JSONObject();
        parAuthResponse.put(ParConstants.REQUEST_URI, ParConstants.REQUEST_URI_HEAD + uuid);
        parAuthResponse.put(ParConstants.EXPIRES_IN, ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC);

        if (log.isDebugEnabled()) {
            log.debug("Creating PAR Authentication response to the request");
        }

        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_CREATED);
        if (log.isDebugEnabled()) {
            log.debug("Returning PAR Authentication Response for the request");
        }

        //OAuth2ParEndpoint.setRequestUriUUID(uuid);
        return responseBuilder.entity(parAuthResponse.toString()).build();
    }


    private static OAuth2Service getOAuth2Service() {

        return OAuthComponentServiceHolder.getInstance().getOauth2Service();
    }

    private static OAuth2ClientValidationResponseDTO validateClient(HttpServletRequest request) {

        return getOAuth2Service().validateClientInfo(request);
    }

    public static OAuth2ClientValidationResponseDTO getClientValidationResponse (HttpServletRequest request) {

        return validateClient(request);
    }

    public static CacheBackedParDAO getCacheBackedParDAO() {
        return new CacheBackedParDAO();
    }

    public static ParMgtDAO getParMgtDAO() {
        return parMgtDAO;
    }

    /**
     * Sets the UUID for the request_uri.
     */
    public static String getUuid() {
        return uuid;
    }
}
