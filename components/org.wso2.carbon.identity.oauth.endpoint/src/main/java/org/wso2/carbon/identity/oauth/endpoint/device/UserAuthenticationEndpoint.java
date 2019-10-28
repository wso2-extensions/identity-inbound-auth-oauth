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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("/device")
public class UserAuthenticationEndpoint {

    private static final Log log = LogFactory.getLog(UserAuthenticationEndpoint.class);

    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();

    public UserAuthenticationEndpoint() {

    }

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response device_authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException, IdentityOAuth2Exception, IOException {

        String userCode = request.getParameter(Constants.USER_CODE);
        String clientId = DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getClientIdByUSerCode(userCode);
        if (clientId != null && !getUserCodeStatus(userCode).equals(Constants.USED)) {
            DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setUserAuthenticated(userCode, Constants.USED);
            CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request);
            commonAuthRequestWrapper.setParameter(Constants.CLIENT_ID, clientId);
            commonAuthRequestWrapper.setParameter(Constants.RESPONSE_TYPE, Constants.DEVICE);
            if (getScope(userCode) != null) {
                commonAuthRequestWrapper.setParameter(Constants.SCOPE, getScope(userCode));
            }
            commonAuthRequestWrapper.setParameter("nonce", userCode);
            return oAuth2AuthzEndpoint.authorize(commonAuthRequestWrapper, response);

        } else response.sendRedirect(IdentityUtil.getServerURL("/authenticationendpoint/device.do",
                false, false));
        return null;
    }

    /**
     *
     * @param userCode user code that has delivered to the device
     * @return scopes
     * @throws IdentityOAuth2Exception
     */
    private String getScope(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getScopeForDevice(userCode);
    }

    /**
     *
     * @param userCode user code that has delivered to the device
     * @return status
     * @throws IdentityOAuth2Exception
     */
    private String getUserCodeStatus(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getStatusForUserCode(userCode);
    }

}
