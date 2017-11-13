/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.user;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoEndpointConfig;
import org.wso2.carbon.identity.oauth.user.UserInfoAccessTokenValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoRequestValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_PRAGMA;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE;

@Path("/userinfo")
public class OpenIDConnectUserEndpoint {

    private static final Log log = LogFactory.getLog(OpenIDConnectUserEndpoint.class);

    @GET
    @Path("/")
    @Produces("application/json")
    public Response getUserClaims(@Context HttpServletRequest request) throws OAuthSystemException {
        String userInfoResponse;
        try {
            // validate the request
            UserInfoRequestValidator requestValidator = UserInfoEndpointConfig.getInstance().getUserInfoRequestValidator();
            String accessToken = requestValidator.validateRequest(request);

            // validate the access token
            UserInfoAccessTokenValidator tokenValidator =
                    UserInfoEndpointConfig.getInstance().getUserInfoAccessTokenValidator();
            OAuth2TokenValidationResponseDTO tokenResponse = tokenValidator.validateToken(accessToken);

            // build the claims
            //ToDO - Validate the grant type to be implicit or authorization_code before retrieving claims
            UserInfoResponseBuilder userInfoResponseBuilder =
                    UserInfoEndpointConfig.getInstance().getUserInfoResponseBuilder();
            userInfoResponse = userInfoResponseBuilder.getResponseString(tokenResponse);

        } catch (UserInfoEndpointException e) {
            return handleError(e);
        } catch (OAuthSystemException e) {
            log.error("UserInfoEndpoint Failed", e);
            throw new OAuthSystemException("UserInfoEndpoint Failed");
        }

        ResponseBuilder respBuilder = getResponseBuilderWithCacheControlHeaders();
        if (userInfoResponse != null) {
            return respBuilder.entity(userInfoResponse).build();
        }
        return respBuilder.build();
    }

    @POST
    @Path("/")
    @Produces("application/json")
    public Response getUserClaimsPost(@Context HttpServletRequest request) throws OAuthSystemException {
        return getUserClaims(request);
    }

    private ResponseBuilder getResponseBuilderWithCacheControlHeaders() {
        return Response.status(HttpServletResponse.SC_OK)
                .header(HTTP_RESP_HEADER_CACHE_CONTROL, HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE)
                .header(HTTP_RESP_HEADER_PRAGMA, HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
    }


    /**
     * Build the error message response properly
     *
     * @param e
     * @return
     * @throws OAuthSystemException
     */
    private Response handleError(UserInfoEndpointException e) throws OAuthSystemException {
        if (log.isDebugEnabled()) {
            log.debug("Error while building user info response.", e);
        }
        try {
            if (OAuthError.ResourceResponse.INSUFFICIENT_SCOPE.equals(e.getErrorCode())) {
                return getErrorResponseWithAuthenticateHeader(e, HttpServletResponse.SC_FORBIDDEN);
            } else if (OAuthError.ResourceResponse.INVALID_TOKEN.equals(e.getErrorCode())) {
                return getErrorResponseWithAuthenticateHeader(e, HttpServletResponse.SC_UNAUTHORIZED);
            } else if (OAuthError.ResourceResponse.INVALID_REQUEST.equals(e.getErrorCode())) {
                return getErrorResponseWithAuthenticateHeader(e, HttpServletResponse.SC_BAD_REQUEST);
            } else {
                return buildBadRequestErrorResponse(e, HttpServletResponse.SC_BAD_REQUEST);
            }
        } catch (OAuthSystemException e1) {
            log.error("Error while building the JSON message", e1);
            return buildServerErrorResponse(e1, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private Response buildServerErrorResponse(OAuthSystemException ex, int statusCode) throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse.errorResponse(statusCode)
                        .setError(OAuth2ErrorCodes.SERVER_ERROR)
                        .setErrorDescription(ex.getMessage()).buildJSONMessage();
        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private Response buildBadRequestErrorResponse(UserInfoEndpointException ex,
                                                  int statusCode) throws OAuthSystemException {
        OAuthResponse res = OAuthASResponse.errorResponse(statusCode)
                .setError(ex.getErrorCode())
                .setErrorDescription(ex.getErrorMessage())
                .buildJSONMessage();
        return Response.status(res.getResponseStatus()).entity(res.getBody()).build();
    }

    private Response getErrorResponseWithAuthenticateHeader(UserInfoEndpointException ex,
                                                            int statusCode) throws OAuthSystemException {
        OAuthResponse res = OAuthASResponse.errorResponse(statusCode)
                .setError(ex.getErrorCode())
                .setErrorDescription(ex.getErrorMessage())
                .buildJSONMessage();
        return Response.status(res.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, "Bearer error=\"" + ex.getErrorCode() + "\"")
                .entity(res.getBody())
                .build();
    }
}
