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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Rest implementation for device authentication flow.
 */
@Path("/device")
public class UserAuthenticationEndpoint {

    private static final Log log = LogFactory.getLog(UserAuthenticationEndpoint.class);
    public static final String ERROR = "error";
    public static final String INVALID_CODE_ERROR_KEY = "invalid.code";
    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();
    private DeviceFlowDO deviceFlowDO = new DeviceFlowDO();

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response deviceAuthorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws InvalidRequestParentException, OAuthSystemException {

        try {
            String userCode = request.getParameter(Constants.USER_CODE);
            // True when input(user_code) is not REQUIRED.
            if (StringUtils.isBlank(userCode)) {
                if (log.isDebugEnabled()) {
                    log.debug("user_code is missing in the request.");
                }
                String error = ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH)
                        .addParameter(ERROR, INVALID_CODE_ERROR_KEY).build().getAbsolutePublicURL();
                return Response.status(HttpServletResponse.SC_FOUND).location(URI.create(error)).build();
            }
            DeviceFlowDO deviceFlowDODetails =
                    DeviceServiceFactory.getDeviceAuthService().getDetailsByUserCode(userCode);
            if (!isExpiredUserCode(deviceFlowDODetails)) {
                String clientId = deviceFlowDODetails.getConsumerKey();
                DeviceServiceFactory.getDeviceAuthService().setAuthenticationStatus(userCode);
                CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request);
                commonAuthRequestWrapper.setParameter(Constants.CLIENT_ID, clientId);
                commonAuthRequestWrapper.setParameter(Constants.RESPONSE_TYPE, Constants.RESPONSE_TYPE_DEVICE);
                commonAuthRequestWrapper.setParameter(Constants.REDIRECTION_URI, deviceFlowDO.getCallbackUri());
                commonAuthRequestWrapper.setAttribute(OAuthConstants.PKCE_UNSUPPORTED_FLOW, true);
                List<String> scopes = deviceFlowDODetails.getScopes();
                if (CollectionUtils.isNotEmpty(scopes)) {
                    String scope = String.join(Constants.SEPARATED_WITH_SPACE, scopes);
                    commonAuthRequestWrapper.setParameter(Constants.SCOPE, scope);
                }
                commonAuthRequestWrapper.setParameter(Constants.NONCE, userCode);
                return oAuth2AuthzEndpoint.authorize(commonAuthRequestWrapper, response);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Incorrect user_code.");
                }
                String error = ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH)
                        .addParameter(ERROR, INVALID_CODE_ERROR_KEY).build().getAbsolutePublicURL();
                return Response.status(HttpServletResponse.SC_FOUND).location(URI.create(error)).build();
            }
        } catch (IdentityOAuth2Exception e) {
            return handleIdentityOAuth2Exception(e);
        } catch (URLBuilderException e) {
            return handleURLBuilderException(e);
        } catch (URISyntaxException e) {
            return handleURISyntaxException(e);
        }
    }

    private Response handleIdentityOAuth2Exception(IdentityOAuth2Exception e) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug(e.getMessage(), e);
        }
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).
                setError(OAuth2ErrorCodes.INVALID_REQUEST).setErrorDescription("Invalid Request").buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private Response handleURLBuilderException(URLBuilderException e) throws OAuthSystemException {

        log.error("Error occurred while sending request to authentication framework.", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private Response handleURISyntaxException(URISyntaxException e) throws OAuthSystemException {

        log.error("Error while parsing string as an URI reference.", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private boolean isExpiredUserCode(DeviceFlowDO deviceFlowDO) throws IdentityOAuth2Exception {

        if (deviceFlowDO == null) {
            return true;
        }
        // If status changed from PENDING (!PENDING) , then that user_code CANNOT be reused.
        if (!StringUtils.equals(deviceFlowDO.getStatus(), Constants.PENDING)) {
            return true;
        } else if (Instant.now().toEpochMilli() > deviceFlowDO.getExpiryTime().getTime()) {
            DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().
                    setDeviceCodeExpired(deviceFlowDO.getDeviceCode(), Constants.EXPIRED);
            return true;
        }
        return false;
    }
}
