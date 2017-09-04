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

package org.wso2.carbon.identity.oauth.endpoint.token;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.as.response.OAuthASResponse.OAuthTokenResponseBuilder;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthTokenRequest;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

@Path("/token")
public class OAuth2TokenEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2TokenEndpoint.class);
    public static final String BEARER = "Bearer";

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response issueAccessToken(@Context HttpServletRequest request,
                                     MultivaluedMap<String, String> paramMap) throws OAuthSystemException {

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext
                    .getThreadLocalCarbonContext();
            carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
            carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);

            String consumer_key = null;
            OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
            try {
                if (StringUtils.isNotEmpty(httpRequest.getParameter(OAuth.OAUTH_CLIENT_ID))) {
                    consumer_key = httpRequest.getParameter(OAuth.OAUTH_CLIENT_ID);
                } else if (request.getHeader("authorization") != null) {
                    consumer_key = EndpointUtil.extractCredentialsFromAuthzHeader(request.getHeader("authorization"))[0];
                }
                if (StringUtils.isNotEmpty(consumer_key)) {
                    String appState = oAuthAppDAO.getConsumerAppState(consumer_key);
                    if (!OAuthConstants.OauthAppStates.APP_STATE_ACTIVE.equalsIgnoreCase(appState)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Oauth App is not in active state.");
                        }
                        OAuthResponse oAuthResponse = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                                .setError(OAuth2ErrorCodes.INVALID_CLIENT)
                                .setErrorDescription("Oauth application is not in active state.").buildJSONMessage();
                        return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();
                    }
                }
            } catch (IdentityOAuthAdminException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error in getting oauth app state.", e);
                }
                OAuthResponse oAuthResponse = OAuthASResponse.errorResponse(HttpServletResponse.SC_NOT_FOUND)
                        .setError(OAuth2ErrorCodes.SERVER_ERROR)
                        .setErrorDescription("Error in getting oauth app state.").buildJSONMessage();
                return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();
            } catch (OAuthClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error decoding authorization header. Space delimited \"<authMethod> <base64Hash>\" format violated.", e);
                }
                OAuthResponse oAuthResponse = OAuthASResponse.errorResponse(HttpServletResponse.SC_NOT_FOUND)
                        .setError(OAuth2ErrorCodes.SERVER_ERROR)
                        .setErrorDescription("Error decoding authorization header. Space delimited \"<authMethod> <base64Hash>\" format violated.").buildJSONMessage();
                return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();
            }

            // extract the basic auth credentials if present in the request and use for
            // authentication.
            if (request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ) != null) {

                try {
                    String[] clientCredentials = EndpointUtil.extractCredentialsFromAuthzHeader(
                            request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ));

                    // The client MUST NOT use more than one authentication method in each request
                    if (paramMap.containsKey(OAuth.OAUTH_CLIENT_ID)
                            && paramMap.containsKey(OAuth.OAUTH_CLIENT_SECRET)) {
                        return handleBasicAuthFailure();
                    }

                    //If a client sends an invalid base64 encoded clientid:clientsecret value, it results in this
                    //array to only contain 1 element. This happens on specific errors though.
                    if (clientCredentials.length != 2) {
                        return handleBasicAuthFailure();
                    }

                    // add the credentials available in Authorization header to the parameter map
                    paramMap.add(OAuth.OAUTH_CLIENT_ID, clientCredentials[0]);
                    paramMap.add(OAuth.OAUTH_CLIENT_SECRET, clientCredentials[1]);

                } catch (OAuthClientException e) {
                    // malformed credential string is considered as an auth failure.
                    log.error("Error while extracting credentials from authorization header", e);
                    return handleBasicAuthFailure();
                }
            }

            try {
                CarbonOAuthTokenRequest oauthRequest = new CarbonOAuthTokenRequest(httpRequest);
                // exchange the access token for the authorization grant.
                OAuth2AccessTokenRespDTO oauth2AccessTokenResp = getAccessToken(oauthRequest);
                // if there BE has returned an error
                if (oauth2AccessTokenResp.getErrorMsg() != null) {
                    // if there is an auth failure, HTTP 401 Status Code should be sent back to the client.
                    if (OAuth2ErrorCodes.INVALID_CLIENT.equals(oauth2AccessTokenResp.getErrorCode())) {
                        return handleBasicAuthFailure();
                    } else if ("sql_error".equals(oauth2AccessTokenResp.getErrorCode())) {
                        return handleSQLError();
                    } else if (OAuth2ErrorCodes.SERVER_ERROR.equals(oauth2AccessTokenResp.getErrorCode())) {
                        return handleServerError();
                    } else {
                        // Otherwise send back HTTP 400 Status Code
                        OAuthResponse.OAuthErrorResponseBuilder oAuthErrorResponseBuilder = OAuthASResponse
                                .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                                .setError(oauth2AccessTokenResp.getErrorCode())
                                .setErrorDescription(oauth2AccessTokenResp.getErrorMsg());
                        OAuthResponse response = oAuthErrorResponseBuilder.buildJSONMessage();

                        ResponseHeader[] headers = oauth2AccessTokenResp.getResponseHeaders();
                        ResponseBuilder respBuilder = Response
                                .status(response.getResponseStatus());

                        if (headers != null && headers.length > 0) {
                            for (int i = 0; i < headers.length; i++) {
                                if (headers[i] != null) {
                                    respBuilder.header(headers[i].getKey(), headers[i].getValue());
                                }
                            }
                        }

                        return respBuilder.entity(response.getBody()).build();
                    }
                } else {
                    OAuthTokenResponseBuilder oAuthRespBuilder = OAuthASResponse
                            .tokenResponse(HttpServletResponse.SC_OK)
                            .setAccessToken(oauth2AccessTokenResp.getAccessToken())
                            .setRefreshToken(oauth2AccessTokenResp.getRefreshToken())
                            .setExpiresIn(Long.toString(oauth2AccessTokenResp.getExpiresIn()))
                            .setTokenType(BEARER);
                    oAuthRespBuilder.setScope(oauth2AccessTokenResp.getAuthorizedScopes());

                    // OpenID Connect ID token
                    if (oauth2AccessTokenResp.getIDToken() != null) {
                        oAuthRespBuilder.setParam(OAuthConstants.ID_TOKEN,
                                oauth2AccessTokenResp.getIDToken());
                    }
                    OAuthResponse response = oAuthRespBuilder.buildJSONMessage();
                    ResponseHeader[] headers = oauth2AccessTokenResp.getResponseHeaders();
                    ResponseBuilder respBuilder = Response
                            .status(response.getResponseStatus())
                            .header(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                    OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE)
                            .header(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                    OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);

                    if (headers != null && headers.length > 0) {
                        for (int i = 0; i < headers.length; i++) {
                            if (headers[i] != null) {
                                respBuilder.header(headers[i].getKey(), headers[i].getValue());
                            }
                        }
                    }

                    return respBuilder.entity(response.getBody()).build();
                }

            } catch (OAuthProblemException e) {
                log.error("Error while creating the Carbon OAuth token request", e);
                OAuthResponse res = OAuthASResponse
                        .errorResponse(HttpServletResponse.SC_BAD_REQUEST).error(e)
                        .buildJSONMessage();
                return Response.status(res.getResponseStatus()).entity(res.getBody()).build();
            }

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

    }

    private Response handleBasicAuthFailure() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setError(OAuth2ErrorCodes.INVALID_CLIENT)
                .setErrorDescription("Client Authentication failed.").buildJSONMessage();
        return Response.status(response.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                .entity(response.getBody()).build();
    }

    private Response handleServerError() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error.").buildJSONMessage();

        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();

    }

    private Response handleSQLError() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_GATEWAY).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Service Unavailable Error.").buildJSONMessage();

        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private OAuth2AccessTokenRespDTO getAccessToken(CarbonOAuthTokenRequest oauthRequest) {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        String grantType = oauthRequest.getGrantType();
        tokenReqDTO.setGrantType(grantType);
        tokenReqDTO.setClientId(oauthRequest.getClientId());
        tokenReqDTO.setClientSecret(oauthRequest.getClientSecret());
        tokenReqDTO.setCallbackURI(oauthRequest.getRedirectURI());
        tokenReqDTO.setScope(oauthRequest.getScopes().toArray(new String[oauthRequest.getScopes().size()]));
        tokenReqDTO.setTenantDomain(oauthRequest.getTenantDomain());
        tokenReqDTO.setPkceCodeVerifier(oauthRequest.getPkceCodeVerifier());
        // Set all request parameters to the OAuth2AccessTokenReqDTO
        tokenReqDTO.setRequestParameters(oauthRequest.getRequestParameters());
        // Set all request headers to the OAuth2AccessTokenReqDTO
        tokenReqDTO.setHttpRequestHeaders(oauthRequest.getHttpRequestHeaders());

        // Check the grant type and set the corresponding parameters
        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            tokenReqDTO.setAuthorizationCode(oauthRequest.getCode());
            tokenReqDTO.setPkceCodeVerifier(oauthRequest.getPkceCodeVerifier());
        } else if (GrantType.PASSWORD.toString().equals(grantType)) {
            tokenReqDTO.setResourceOwnerUsername(oauthRequest.getUsername());
            tokenReqDTO.setResourceOwnerPassword(oauthRequest.getPassword());
        } else if (GrantType.REFRESH_TOKEN.toString().equals(grantType)) {
            tokenReqDTO.setRefreshToken(oauthRequest.getRefreshToken());
        } else if (org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString().equals(grantType)) {
            tokenReqDTO.setAssertion(oauthRequest.getAssertion());
        } else if (org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString().equals(grantType)) {
            tokenReqDTO.setWindowsToken(oauthRequest.getWindowsToken());
        } else {
            // Set all request parameters to the OAuth2AccessTokenReqDTO
            tokenReqDTO.setRequestParameters(oauthRequest.getRequestParameters());
        }

        return EndpointUtil.getOAuth2Service().issueAccessToken(tokenReqDTO);
    }
}
