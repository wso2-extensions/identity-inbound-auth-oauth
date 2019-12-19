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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.device;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.codegenerator.GenerateKeys;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.errorcodes.DeviceErrorCodes;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Rest implementation for device authorization flow.
 */
@Path("/device_authorize")
public class DeviceEndpoint {

    private static final Log log = LogFactory.getLog(DeviceEndpoint.class);
    private DeviceAuthService deviceAuthService;

    public void setDeviceAuthService(DeviceAuthService deviceAuthService) {

        this.deviceAuthService = deviceAuthService;
    }

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws IdentityOAuth2Exception {

        String clientId = request.getParameter(Constants.CLIENT_ID);
        JSONObject errorResponse = new JSONObject();
        if (StringUtils.isBlank(clientId)) {
            errorResponse.put(Constants.ERROR, DeviceErrorCodes.INVALID_REQUEST)
                    .put(Constants.ERROR_DESCRIPTION, "Request missing required parameters");
            Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
            return respBuilder.entity(errorResponse.toString()).build();
        }
        if (!validateClientId(clientId)) {
            errorResponse.put(Constants.ERROR, DeviceErrorCodes.UNAUTHORIZED_CLIENT)
                    .put(Constants.ERROR_DESCRIPTION, "No registered client with the client id.");
            Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED);
            return respBuilder.entity(errorResponse.toString()).build();
        }
        String userCode = GenerateKeys.getKey(Constants.KEY_LENGTH);
        String deviceCode = UUID.randomUUID().toString();
        String scopes = request.getParameter(Constants.SCOPE);
        String redirectionUri = IdentityUtil.getServerURL("/authenticationendpoint/device.do", false, false);
        String redirectionUriComplete = redirectionUri + "?user_code=" + userCode;
        deviceAuthService.generateDeviceResponse(deviceCode, userCode, clientId, scopes);
        return buildResponseObject(deviceCode, userCode, redirectionUri, redirectionUriComplete);
    }

    /**
     * This method uses to validate the client is exist or not.
     *
     * @param clientId Consumer key of the client.
     * @return Client is exist or not.
     * @throws IdentityOAuth2Exception
     */
    private boolean validateClientId(String clientId) throws IdentityOAuth2Exception {

        return deviceAuthService.validateClientInfo(clientId);
    }

    /**
     * This method converts time in milliseconds to seconds.
     *
     * @param value Time in milliseconds.
     * @return String value of time in seconds.
     */
    private String stringValueInSeconds(long value) {

        return String.valueOf(value / 1000);
    }

    /**
     * This use to build the response.
     *
     * @param deviceCode             Code that is used to identify the device.
     * @param userCode               Code that is used to correlate user and device.
     * @param redirectionUri         Redirection instruction to the user.
     * @param redirectionUriComplete QR instruction to the user.
     * @return
     */
    private Response buildResponseObject(String deviceCode, String userCode, String redirectionUri,
                                         String redirectionUriComplete) {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(Constants.DEVICE_CODE, deviceCode)
                .put(Constants.USER_CODE, userCode)
                .put(Constants.VERIFICATION_URI, redirectionUri)
                .put(Constants.VERIFICATION_URI_COMPLETE, redirectionUriComplete)
                .put(Constants.EXPIRES_IN, stringValueInSeconds(Constants.EXPIRES_IN_VALUE))
                .put(Constants.INTERVAL, stringValueInSeconds(Constants.INTERVAL_VALUE));
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_OK);
        return respBuilder.entity(jsonObject.toString()).build();
    }
}
