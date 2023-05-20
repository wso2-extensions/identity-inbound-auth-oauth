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

package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.cxf.interceptor.InInterceptors;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.core.ParAuthServiceImpl;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthResponseData;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

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
 * The endpoint accepts POST request with the authorization parameters
 * Returns a request_uri as a reference for the submitted parameters and the expiry time
 */
@Path("/par")
@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
public class OAuth2ParEndpoint {

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response par(@Context HttpServletRequest request, @Context HttpServletResponse response,
                        MultivaluedMap<String, String> paramMap) {

        try {
            handleValidation(request, paramMap);
            HashMap<String, String> parameters = transformParams(paramMap);
            ParAuthResponseData parAuthResponseData = getParAuthResponseData(response, request);
            persistParRequest(parAuthResponseData.getUuid(), parameters,
                    getExpiry(Calendar.getInstance(TimeZone.getTimeZone(ParConstants.UTC)).getTimeInMillis()));
            return createAuthResponse(response, parAuthResponseData);
        } catch (ParClientException e) {
            return handleParClientException(e);
        } catch (ParCoreException e) {
            return handleParCoreException(e);
        }
    }

    private long getExpiry(long requestedTime) {

        long defaultExpiryInSecs = ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC * ParConstants.SEC_TO_MILLISEC_FACTOR;
        return requestedTime + defaultExpiryInSecs;
    }

    private HashMap<String, String> transformParams(MultivaluedMap<String, String> paramMap) {

        HashMap<String, String> parameters = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : paramMap.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue().get(0);
            parameters.put(key, value);
        }

        return parameters;
    }

    private ParAuthResponseData getParAuthResponseData(HttpServletResponse response, HttpServletRequest request) {

        return getParAuthService().generateParAuthResponse(response, request);
    }

    private Response createAuthResponse(HttpServletResponse response, ParAuthResponseData parAuthResponseData) {

        response.setContentType(MediaType.APPLICATION_JSON);
        net.minidev.json.JSONObject parAuthResponse = new net.minidev.json.JSONObject();
        parAuthResponse.put(OAuthConstants.OAuth20Params.REQUEST_URI,
                ParConstants.REQUEST_URI_HEAD + parAuthResponseData.getUuid());
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
        if (errorCode.equals(OAuth2ErrorCodes.INVALID_CLIENT)) {
            responseBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        }
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }

    private Response handleParCoreException(ParCoreException parCoreException) {

        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR, OAuth2ErrorCodes.SERVER_ERROR);
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR_DESCRIPTION, parCoreException.getMessage());

        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return respBuilder.entity(parErrorResponse.toString()).build();
    }

    private void handleValidation(HttpServletRequest request, MultivaluedMap<String, String> paramMap)
            throws ParClientException {

        OAuth2ClientValidationResponseDTO validationResponse = validateClient(request);

        if (!validationResponse.isValidClient()) {
            throw new ParClientException(validationResponse.getErrorCode(), validationResponse.getErrorMsg());
        }
        if (isRequestUriProvided(paramMap)) {
            String errorMsg = "request.with.request_uri.not.allowed";
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST, errorMsg);
        }
    }

    private boolean isRequestUriProvided(MultivaluedMap<String, String> paramMap) {

        return paramMap.containsKey(OAuthConstants.OAuth20Params.REQUEST_URI);
    }

    private void persistParRequest(String uuid, HashMap<String, String> params, long scheduledExpiryTime)
            throws ParCoreException {

        getParAuthService().persistParRequest(uuid, params, scheduledExpiryTime);
    }

    private OAuth2ClientValidationResponseDTO validateClient(HttpServletRequest request) {

        return getOAuth2Service().validateClientInfo(request);
    }

    private ParAuthServiceImpl getParAuthService() {
        return EndpointUtil.getParAuthService();
    }
}
