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
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.codegenerator.GenerateKeys;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.errorcodes.DeviceErrorCodes;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("/device_authorize")
public class DeviceEndpoint {

    private static final Log log = LogFactory.getLog(DeviceEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws IOException, IdentityOAuth2Exception, InvalidOAuthClientException, OAuthSystemException {

        String clientId = request.getParameter(Constants.CLIENT_ID);
        OAuthResponse errorResponse;
        if (StringUtils.isBlank(clientId)) {
            errorResponse = OAuthASResponse
                    .errorResponse(response.getStatus())
                    .setError(DeviceErrorCodes.INVALID_REQUEST)
                    .setErrorDescription("Request missing required parameters").buildJSONMessage();
            Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
            return respBuilder.entity(errorResponse.getBody()).build();
        } else {
            if (validateClientId(clientId)) {
                int keyLength = 6;
                long expiresIn = 3600000L;
                int interval = 5000;
                String userCode = GenerateKeys.getKey(keyLength);
                String deviceCode = UUID.randomUUID().toString();
                String scope = request.getParameter(Constants.SCOPE);
                String redirectionUri = IdentityUtil.getServerURL("/authenticationendpoint/device.do",
                        false, false);
                String redirectionUriComplete = redirectionUri + "?user_code=" + userCode;
                DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().insertDeviceFlow(deviceCode, userCode,
                        clientId, scope, expiresIn, interval);

                OAuthResponse deviceResponse = OAuthResponse
                        .status(HttpServletResponse.SC_OK)
                        .setParam(Constants.DEVICE_CODE, deviceCode)
                        .setParam(Constants.USER_CODE, userCode)
                        .setParam(Constants.VERIFICATION_URI, redirectionUri)
                        .setParam(Constants.VERIFICATION_URI_COMPLETE, redirectionUriComplete)
                        .setParam(Constants.EXPIRES_IN, stringValueInSeconds(expiresIn))
                        .setParam(Constants.INTERVAL, stringValueInSeconds(interval)).buildJSONMessage();
                Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_ACCEPTED);
                return respBuilder.entity(deviceResponse.getBody()).build();

            } else {
                errorResponse = OAuthASResponse
                        .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setError(DeviceErrorCodes.UNAUTHORIZED_CLIENT)
                        .setErrorDescription("No registered client with the client id.").buildJSONMessage();
                Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                return respBuilder.entity(errorResponse.getBody()).build();
            }
        }
    }

    /**
     * This method uses to validate the client is exist or not.
     *
     * @param clientId Consumer key of the client
     * @return Client is exist or not
     * @throws IdentityOAuth2Exception
     */
    private boolean validateClientId(String clientId) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().checkClientIdExist(clientId);
    }

    /**
     * This method converts time in milliseconds to seconds.
     *
     * @param value Time in milliseconds
     * @return String value of time in seconds
     */
    private String stringValueInSeconds(long value) {

        return String.valueOf((value / 1000));
    }
}
