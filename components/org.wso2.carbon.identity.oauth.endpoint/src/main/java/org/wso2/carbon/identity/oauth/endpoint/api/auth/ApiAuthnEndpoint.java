/*
 * Copyright (c) 2023-2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Class containing the REST API for API based authentication.
 */
@Path("/authn")
public class ApiAuthnEndpoint {

    private final AuthenticationService authenticationService = new AuthenticationService();
    private static final Log LOG = LogFactory.getLog(ApiAuthnEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/json")
    @Produces("application/json")
    public Response handleAuthentication(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                         String payload) {

        try {
            AuthRequest authRequest = ApiAuthnUtils.buildAuthRequest(payload);
            AuthServiceRequest authServiceRequest = ApiAuthnUtils.getAuthServiceRequest(request, response, authRequest);
            AuthServiceResponse authServiceResponse = authenticationService.handleAuthentication(authServiceRequest);

            switch (authServiceResponse.getFlowStatus()) {
                case INCOMPLETE:
                    return ApiAuthnUtils.handleIncompleteAuthResponse(authServiceResponse);
                case SUCCESS_COMPLETED:
                    return ApiAuthnUtils.handleSuccessCompletedAuthResponse(request, response, authServiceResponse);
                case FAIL_INCOMPLETE:
                    return ApiAuthnUtils.handleFailIncompleteAuthResponse(authServiceResponse);
                case FAIL_COMPLETED:
                    return ApiAuthnUtils.handleFailCompletedAuthResponse(authServiceResponse);
                default:
                    throw new AuthServiceException(
                            AuthServiceConstants.ErrorMessage.ERROR_UNKNOWN_AUTH_FLOW_STATUS.code(),
                            String.format(AuthServiceConstants.ErrorMessage.ERROR_UNKNOWN_AUTH_FLOW_STATUS
                                    .description(), authServiceResponse.getFlowStatus()));
            }

        } catch (AuthServiceClientException e) {
            return ApiAuthnUtils.buildResponseForClientError(e, LOG);
        } catch (AuthServiceException e) {
            return ApiAuthnUtils.buildResponseForServerError(e, LOG);
        }
    }

}
