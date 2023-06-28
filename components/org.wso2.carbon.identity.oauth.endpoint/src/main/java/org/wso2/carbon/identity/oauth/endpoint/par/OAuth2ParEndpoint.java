/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthResponseData;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;

/**
 * REST implementation for OAuth2 PAR endpoint.
 * The endpoint accepts POST request with the authorization parameters.
 * Returns a request_uri as a reference for the submitted parameters and the expiry time.
 */
@Path("/par")
@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
public class OAuth2ParEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2ParEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response par(@Context HttpServletRequest request, @Context HttpServletResponse response,
                        MultivaluedMap<String, String> params) {

        try {
            handleValidation(request, params);
            Map<String, String> parameters = transformParams(params);
            ParAuthResponseData parAuthResponseData =
                    EndpointUtil.getParAuthService().handleParAuthRequest(parameters);
            return createAuthResponse(response, parAuthResponseData);
        } catch (ParClientException e) {
            return handleParClientException(e);
        } catch (ParCoreException e) {
            return handleParCoreException(e);
        }
    }

    private Map<String, String> transformParams(MultivaluedMap<String, String> params) {

        Map<String, String> parameters = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : params.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (!values.isEmpty()) {
                String value = values.get(0);
                parameters.put(key, value);
            }
        }

        return parameters;
    }

    private Response createAuthResponse(HttpServletResponse response, ParAuthResponseData parAuthResponseData) {

        response.setContentType(MediaType.APPLICATION_JSON);
        org.json.JSONObject parAuthResponse = new org.json.JSONObject();
        parAuthResponse.put(OAuthConstants.OAuth20Params.REQUEST_URI,
                ParConstants.REQUEST_URI_PREFIX + parAuthResponseData.getReqUriRef());
        parAuthResponse.put(ParConstants.EXPIRES_IN, parAuthResponseData.getExpiryTime());
        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_CREATED);
        return responseBuilder.entity(parAuthResponse.toString()).build();
    }

    private Response handleParClientException(ParClientException exception) {

        String errorCode = exception.getErrorCode();
        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR, errorCode);
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR_DESCRIPTION, exception.getMessage());

        Response.ResponseBuilder responseBuilder;
        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(errorCode)) {
            responseBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        }
        log.error("PAR client Exception: ", exception.fillInStackTrace());
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }

    private Response handleParCoreException(ParCoreException parCoreException) {

        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR, OAuth2ErrorCodes.SERVER_ERROR);
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR_DESCRIPTION, parCoreException.getMessage());

        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        log.error("PAR Server Exception: ", parCoreException.fillInStackTrace());
        return respBuilder.entity(parErrorResponse.toString()).build();
    }

    private void handleValidation(HttpServletRequest request, MultivaluedMap<String, String> params)
            throws ParClientException {

        OAuth2ClientValidationResponseDTO validationResponse = getOAuth2Service().validateClientInfo(request);

        if (!validationResponse.isValidClient()) {
            throw new ParClientException(validationResponse.getErrorCode(), validationResponse.getErrorMsg());
        }
        if (isRequestUriProvided(params)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    ParConstants.REQUEST_URI_IN_REQUEST_BODY_ERROR);
        }
    }

    private boolean isRequestUriProvided(MultivaluedMap<String, String> params) {

        if (params.containsKey(OAuthConstants.OAuth20Params.REQUEST_URI)) {
            return !(params.get(OAuthConstants.OAuth20Params.REQUEST_URI).isEmpty());
        }
        return false;
    }
}
