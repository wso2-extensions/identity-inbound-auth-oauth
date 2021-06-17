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
import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;

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

    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();
    private DeviceFlowDO deviceFlowDO = new DeviceFlowDO();
    private DeviceAuthService deviceAuthService;

    public void setDeviceAuthService(DeviceAuthService deviceAuthService) {

        this.deviceAuthService = deviceAuthService;
    }

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response deviceAuthorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException, IdentityOAuth2Exception, IOException {

        try {
            String userCode = request.getParameter(Constants.USER_CODE);
            // True when input(user_code) is not REQUIRED.
            if (StringUtils.isBlank(userCode)) {
                if (log.isDebugEnabled()) {
                    log.debug("user_code is missing in the request.");
                }
                response.sendRedirect(ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH).
                        addParameter("error", "invalidRequest").build().getAbsolutePublicURL());
                return null;
            }
            String clientId = deviceAuthService.getClientId(userCode);
            DeviceFlowDO deviceFlowDODetails =
                    DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getDetailsForUserCode(userCode);
            if (StringUtils.isNotBlank(clientId) && deviceFlowDODetails != null &&
                    !isExpiredUserCode(deviceFlowDODetails)) {
                setCallbackURI(clientId);
                deviceAuthService.setAuthenticationStatus(userCode);
                CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request);
                commonAuthRequestWrapper.setParameter(Constants.CLIENT_ID, clientId);
                commonAuthRequestWrapper.setParameter(Constants.RESPONSE_TYPE, Constants.RESPONSE_TYPE_DEVICE);
                commonAuthRequestWrapper.setParameter(Constants.REDIRECTION_URI, deviceFlowDO.getCallbackUri());
                if (getScope(userCode) != null) {
                    String scope = String.join(Constants.SEPARATED_WITH_SPACE, getScope(userCode));
                    commonAuthRequestWrapper.setParameter(Constants.SCOPE, scope);
                }
                commonAuthRequestWrapper.setParameter(Constants.NONCE, userCode);
                return oAuth2AuthzEndpoint.authorize(commonAuthRequestWrapper, response);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Incorrect user_code: " + userCode);
                }
                response.sendRedirect(ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH).
                        addParameter("error", "invalidUserCode").build().getAbsolutePublicURL());
                return null;
            }
        } catch (URLBuilderException e) {
            return handleURLBuilderException(e);
        }
    }

    private Response handleURLBuilderException(URLBuilderException e) {

        log.error("Error occurred while sending request to authentication framework.", e);
        return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
    }

    /**
     * Get the scopes from the database.
     *
     * @param userCode User code that has delivered to the device.
     * @return Scopes
     * @throws IdentityOAuth2Exception
     */
    private String[] getScope(String userCode) throws IdentityOAuth2Exception {

        return deviceAuthService.getScope(userCode);
    }

    /**
     * This method is used to generate the redirection URI.
     *
     * @param appName Service provider name.
     * @return Redirection URI
     */
    private String getRedirectionURI(String appName) throws URISyntaxException, URLBuilderException {

        try {
            String pageURI = ServiceURLBuilder.create().addPath(Constants.DEVICE_SUCCESS_ENDPOINT_PATH)
                    .build().getAbsolutePublicURL();
            URIBuilder uriBuilder = new URIBuilder(pageURI);
            uriBuilder.addParameter(Constants.APP_NAME, appName);
            return uriBuilder.build().toString();
        } catch (URLBuilderException e) {
            log.error("Error occurred while sending request to authentication framework.", e);
            throw new URLBuilderException("Error occurred while sending request to authentication framework.", e);
        }
    }

    /**
     * This method is used to set the callback uri. If there is no value it will set a default value.
     *
     * @param clientId Consumer key of the application.
     * @throws IdentityOAuth2Exception
     */
    private void setCallbackURI(String clientId) throws IdentityOAuth2Exception, URLBuilderException {

        try {
            OAuthAppDO oAuthAppDO;
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            String redirectURI = oAuthAppDO.getCallbackUrl();
            if (StringUtils.isBlank(redirectURI)) {
                String appName = oAuthAppDO.getApplicationName();
                redirectURI = getRedirectionURI(appName);
                deviceAuthService.setCallbackUri(clientId, redirectURI);
                AppInfoCache.getInstance().clearCacheEntry(clientId);
            }
            deviceFlowDO.setCallbackUri(redirectURI);
        } catch (URLBuilderException e) {
            throw new URLBuilderException(e.getMessage(), e);
        } catch (InvalidOAuthClientException | URISyntaxException | IdentityOAuth2Exception e) {
            String errorMsg = String.format("Error when getting app details for client id : %s", clientId);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    private boolean isExpiredUserCode(DeviceFlowDO deviceFlowDO) throws IdentityOAuth2Exception {

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
