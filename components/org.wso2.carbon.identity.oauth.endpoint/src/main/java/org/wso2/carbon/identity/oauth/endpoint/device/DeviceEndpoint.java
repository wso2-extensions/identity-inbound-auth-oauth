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
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.json.JSONObject;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointBadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.codegenerator.GenerateKeys;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.util.DeviceFlowUtil;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * Rest implementation for device authorization flow.
 */
@Path("/device_authorize")
@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
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
    public Response authorize(@Context HttpServletRequest request, MultivaluedMap<String, String> paramMap,
                              @Context HttpServletResponse response)
            throws IdentityOAuth2Exception, OAuthSystemException {

        OAuthClientAuthnContext oAuthClientAuthnContext =  getValidationObject(request);

        if (!oAuthClientAuthnContext.isAuthenticated()) {
            return handleErrorResponse(oAuthClientAuthnContext);
        }

        try {
            validateRepeatedParams(request, paramMap);
            String deviceCode = UUID.randomUUID().toString();
            String scopes = request.getParameter(Constants.SCOPE);
            String userCode = getUniqueUserCode(deviceCode, oAuthClientAuthnContext.getClientId(), scopes);
            String redirectionUri = ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH).build()
                    .getAbsolutePublicURL();
            String redirectionUriComplete = ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH)
                    .addParameter("user_code", userCode).build().getAbsolutePublicURL();
            return buildResponseObject(deviceCode, userCode, redirectionUri, redirectionUriComplete);
        } catch (IdentityOAuth2Exception e) {
            return handleIdentityOAuth2Exception(e);
        } catch (TokenEndpointBadRequestException e) {
            return handleTokenEndpointBadRequestException(e);
        } catch (URLBuilderException e) {
            return handleURLBuilderException(e);
        }
    }

    private String getUniqueUserCode(String deviceCode, String clientId, String scopes) throws IdentityOAuth2Exception {

        String temporaryUserCode = GenerateKeys.getKey(OAuthServerConfiguration.getInstance().getDeviceCodeKeyLength());
        long quantifier = GenerateKeys.getCurrentQuantifier();
        return deviceAuthService.generateDeviceResponse(deviceCode, temporaryUserCode, quantifier, clientId, scopes);
    }

    private void validateRepeatedParams(HttpServletRequest request, MultivaluedMap<String, String> paramMap)
            throws TokenEndpointBadRequestException {

        if (!EndpointUtil.validateParams(request, paramMap)) {
            throw new TokenEndpointBadRequestException("Invalid request with repeated parameters.");
        }
    }

    private Response handleErrorResponse(OAuthClientAuthnContext oAuthClientAuthnContext) throws OAuthSystemException {

        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(oAuthClientAuthnContext.getErrorCode())) {
            return handleInvalidClient(oAuthClientAuthnContext);
        } else if (OAuth2ErrorCodes.SERVER_ERROR.equals(oAuthClientAuthnContext.getErrorMessage())) {
            return handleServerError();
        } else {
            // Otherwise send back HTTP 400 Status Code.
            OAuthResponse response = OAuthASResponse
                    .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(oAuthClientAuthnContext.getErrorCode())
                    .setErrorDescription(oAuthClientAuthnContext.getErrorMessage())
                    .buildJSONMessage();
            Response.ResponseBuilder respBuilder = Response.status(response.getResponseStatus());
            return respBuilder.entity(response.getBody()).build();
        }
    }

    private OAuthClientAuthnContext getValidationObject(HttpServletRequest request) throws OAuthSystemException {

        OAuthClientAuthnContext oAuthClientAuthnContext;
        Object oauthClientAuthnContextObj = request.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT);
        if (oauthClientAuthnContextObj instanceof OAuthClientAuthnContext) {
            oAuthClientAuthnContext = (OAuthClientAuthnContext) oauthClientAuthnContextObj;
        } else {
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorMessage("Client Authentication Failed");
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }
        return oAuthClientAuthnContext;
    }

    private Response handleServerError() throws OAuthSystemException {

        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error.")
                .buildJSONMessage();

        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private Response handleIdentityOAuth2Exception(IdentityOAuth2Exception e) throws OAuthSystemException {

        log.error("Error while checking for unique user_code", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error.")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private Response handleTokenEndpointBadRequestException(TokenEndpointBadRequestException e)
            throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Error in the request with repeated parameters", e);
        }
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).
                setError(OAuth2ErrorCodes.INVALID_REQUEST)
                .setErrorDescription("Invalid request with repeated parameters.")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private Response handleURLBuilderException(URLBuilderException e) throws OAuthSystemException {

        log.error("Error occurred while sending request to authentication framework.", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error.")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private Response handleInvalidClient(OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthSystemException {

        OAuthResponse response;
        if (oAuthClientAuthnContext.getClientId() != null) {
            response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                    .setError(OAuth2ErrorCodes.INVALID_CLIENT)
                    .setErrorDescription("Client Authentication failed").buildJSONMessage();
        } else {
            if (StringUtils.isNotBlank(oAuthClientAuthnContext.getErrorMessage())) {
                response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setError(OAuth2ErrorCodes.INVALID_REQUEST)
                        .setErrorDescription(oAuthClientAuthnContext.getErrorMessage()).buildJSONMessage();
            } else {
                response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setError(OAuth2ErrorCodes.INVALID_REQUEST)
                        .setErrorDescription("Missing parameters: client_id").buildJSONMessage();
            }
        }
        return Response.status(response.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                .entity(response.getBody()).build();
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
                .put(Constants.EXPIRES_IN, DeviceFlowUtil.getConfiguredExpiryTime())
                .put(Constants.INTERVAL, DeviceFlowUtil.getIntervalValue());
        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_OK);
        return respBuilder.entity(jsonObject.toString()).build();
    }
}
