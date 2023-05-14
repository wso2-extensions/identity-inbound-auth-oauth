/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.par.api;

import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.dao.CacheBackedParDAO;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

/**
 * Provides authentication services.
 */
public class ParAuthServiceImpl implements ParAuthService {

    private static final Log log = LogFactory.getLog(ParAuthServiceImpl.class);
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

        uuid = this.generateParReqUriUUID();

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

    /**
     * Returns a unique AuthCodeKey.
     *
     * @return String Returns random uuid.
     */
    private String generateParReqUriUUID() {

        return UUID.randomUUID().toString();
    }

    /**
     * Gets the generated UUID
     */
    public static String getUuid() {
        return uuid;
    }

//    private static OAuth2Service getOAuth2Service() {
//
//        return OAuthComponentServiceHolder.getInstance().getOauth2Service();
//    }
//
//    private static OAuth2ClientValidationResponseDTO validateClient(HttpServletRequest request) {
//
//        return getOAuth2Service().validateClientInfo(request);
//    }
//
//    public static OAuth2ClientValidationResponseDTO getClientValidationResponse (HttpServletRequest request) {
//
//        return validateClient(request);
//    }

    public static CacheBackedParDAO getCacheBackedParDAO() {
        return new CacheBackedParDAO();
    }

    public static ParMgtDAO getParMgtDAO() {
        return parMgtDAO;
    }
}
