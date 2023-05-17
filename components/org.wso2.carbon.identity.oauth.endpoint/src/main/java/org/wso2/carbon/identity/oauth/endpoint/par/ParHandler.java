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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.cache.CacheBackedParDAO;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequest;
import org.wso2.carbon.identity.oauth.par.model.ParAuthResponseData;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.servlet.http.HttpServletResponse;


import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;

/**
 * Handles creation of authentication and error response.
 */
public class ParHandler {

    private static final Log log = LogFactory.getLog(ParHandler.class);
    private static final ParMgtDAO parMgtDAO = ParDAOFactory.getInstance().getParAuthMgtDAO();

    /**
     * Creates PAR AuthenticationResponse.
     *
     * @return Response for AuthenticationRequest.
     */
    public Response createAuthResponse(HttpServletResponse response, ParAuthResponseData parAuthResponseData) {

        if (log.isDebugEnabled()) {
            log.debug("Setting ExpiryTime for the response to the  request.");
        }

        response.setContentType(MediaType.APPLICATION_JSON);

        JSONObject parAuthResponse = new JSONObject();
        parAuthResponse.put(ParConstants.REQUEST_URI, ParConstants.REQUEST_URI_HEAD + parAuthResponseData.getUuid());
        parAuthResponse.put(ParConstants.EXPIRES_IN, parAuthResponseData.getExpityTime());

        if (log.isDebugEnabled()) {
            log.debug("Creating PAR Authentication response to the request");
        }

        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_CREATED);
        if (log.isDebugEnabled()) {
            log.debug("Returning PAR Authentication Response for the request");
        }

        return responseBuilder.entity(parAuthResponse.toString()).build();
    }

    public static void storeParRecord(String uuid, HashMap<String, String> params, long scheduledExpiryTime)
            throws IdentityOAuth2Exception {

        try {
            // Store values to Database
            ParRequest parRequest;
            int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();


            ParHandler.getParMgtDAO().persistParRequest(uuid,
                    params.get(OAuthConstants.OAuth20Params.CLIENT_ID), scheduledExpiryTime, params);

            // Add data to cache
            parRequest = new ParRequest(uuid, params, scheduledExpiryTime);
            ParHandler.getCacheBackedParDAO().addParRequest(uuid, parRequest, tenantId);

        } catch (ParCoreException e) {
            throw new IdentityOAuth2Exception("Error occurred in persisting PAR request", e);
        }
    }

    private static CacheBackedParDAO getCacheBackedParDAO() {
        return new CacheBackedParDAO();
    }

    private static ParMgtDAO getParMgtDAO() {
        return parMgtDAO;
    }

    public static OAuth2ClientValidationResponseDTO validateClient(HttpServletRequest request) {

        return getOAuth2Service().validateClientInfo(request);
    }
}
