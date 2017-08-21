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

@Path("/userinfo")
public class OpenIDConnectUserEndpoint {

    private static final Log log = LogFactory.getLog(OpenIDConnectUserEndpoint.class);

    @GET
    @Path("/")
    @Produces("application/json")
    public Response getUserClaims(@Context HttpServletRequest request) throws OAuthSystemException {

        String response = null;
        try {
            // validate the request
            UserInfoRequestValidator requestValidator = UserInfoEndpointConfig.getInstance().getUserInfoRequestValidator();
            String accessToken = requestValidator.validateRequest(request);

            // validate the access token
            UserInfoAccessTokenValidator tokenValidator =
                    UserInfoEndpointConfig.getInstance().getUserInfoAccessTokenValidator();
            OAuth2TokenValidationResponseDTO tokenResponse = tokenValidator.validateToken(accessToken);

            /*
               We need to pass the SP's tenantId to the UserInfoResponseBuilder to retrieve the correct OIDC scope
               configurations. We can't do this currently as OAuth2TokenValidationResponseDTO does not contain any
               contextual information that could be used to derive the tenantId of the SP. Therefore we are setting
               the tenantId in a thread local variable.
             */
            setServiceProviderTenantId(accessToken);

            // build the claims
            //ToDO - Validate the grant type to be implicit or authorization_code before retrieving claims
            UserInfoResponseBuilder userInfoResponseBuilder =
                    UserInfoEndpointConfig.getInstance().getUserInfoResponseBuilder();
            response = userInfoResponseBuilder.getResponseString(tokenResponse);

        } catch (UserInfoEndpointException e) {
            return handleError(e);
        } catch (OAuthSystemException e) {
            log.error("UserInfoEndpoint Failed", e);
            throw new OAuthSystemException("UserInfoEndpoint Failed");
        }

        ResponseBuilder respBuilder =
                Response.status(HttpServletResponse.SC_OK)
                        .header(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE)
                        .header(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);

        if(response != null) {
            return respBuilder.entity(response).build();
        }
        return respBuilder.build();
    }

    @POST
    @Path("/")
    @Produces("application/json")
    public Response getUserClaimsPost(@Context HttpServletRequest request) throws OAuthSystemException {
        return getUserClaims(request);
    }


    /**
     * Build the error message response properly
     *
     * @param e
     * @return
     * @throws OAuthSystemException
     */
    private Response handleError(UserInfoEndpointException e) throws OAuthSystemException {
        log.debug(e);
        OAuthResponse res;
        try {
            if (OAuthError.ResourceResponse.INSUFFICIENT_SCOPE.equals(e.getErrorCode())) {
                res = OAuthASResponse.errorResponse(HttpServletResponse.SC_FORBIDDEN)
                        .setError(e.getErrorCode()).setErrorDescription(e.getErrorMessage())
                        .buildJSONMessage();
                return Response.status(res.getResponseStatus())
                        .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                                "Bearer error=\"" + e.getErrorCode() + "\"")
                        .entity(res.getBody())
                        .build();
            } else if (OAuthError.ResourceResponse.INVALID_TOKEN.equals(e.getErrorCode())) {
                res = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setError(e.getErrorCode()).setErrorDescription(e.getErrorMessage())
                        .buildJSONMessage();
                return Response.status(res.getResponseStatus())
                        .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                                "Bearer error=\"" + e.getErrorCode() + "\"")
                        .entity(res.getBody())
                        .build();
            } else if (OAuthError.ResourceResponse.INVALID_REQUEST.equals(e.getErrorCode())) {
                res = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                        .setError(e.getErrorCode()).setErrorDescription(e.getErrorMessage())
                        .buildJSONMessage();
                return Response.status(res.getResponseStatus())
                        .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                                "Bearer error=\"" + e.getErrorCode() + "\"")
                        .entity(res.getBody())
                        .build();
            } else {
                res = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                        .setError(e.getErrorCode()).setErrorDescription(e.getErrorMessage())
                        .buildJSONMessage();
                return Response.status(res.getResponseStatus())
                        .entity(res.getBody())
                        .build();
            }

        } catch (OAuthSystemException e1) {
            log.error("Error while building the JSON message", e1);
            OAuthResponse response =
                    OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                            .setError(OAuth2ErrorCodes.SERVER_ERROR)
                            .setErrorDescription(e1.getMessage()).buildJSONMessage();
            return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
        }
    }

    /**
     * Derive the tenantId of the SP from the accessToken identifier and set a threadLocal variable to be used by
     * the UserInfoResponseBuilder.
     *
     * @param accessToken
     * @throws OAuthSystemException
     */
    private void setServiceProviderTenantId(String accessToken) throws OAuthSystemException {
        try {
            // get client id of OAuth app from the introspection
            String clientId = OAuth2Util.getClientIdForAccessToken(accessToken);
            if (StringUtils.isBlank(clientId)) {
                throw new OAuthSystemException("Cannot find the clientID of the SP that issued the token.");
            }
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            int spTenantId = OAuth2Util.getTenantId(OAuth2Util.getTenantDomainOfOauthApp(appDO));
            // set the tenant id in the thread local variable
            OAuth2Util.setClientTenatId(spTenantId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new OAuthSystemException("Error when obtaining the tenant information of SP.", e);
        }
    }

}
