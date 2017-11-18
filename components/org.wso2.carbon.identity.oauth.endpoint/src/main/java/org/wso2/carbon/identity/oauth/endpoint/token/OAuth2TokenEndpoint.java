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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.as.response.OAuthASResponse.OAuthTokenResponseBuilder;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointAccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointBadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthTokenRequest;

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

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.startSuperTenantFlow;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateOauthApplication;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;

@Path("/token")
public class OAuth2TokenEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2TokenEndpoint.class);
    public static final String BEARER = "Bearer";
    private static final String SQL_ERROR = "sql_error";

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response issueAccessToken(@Context HttpServletRequest request,
                                     MultivaluedMap<String, String> paramMap)
            throws OAuthSystemException, InvalidRequestParentException{

        try {
            startSuperTenantFlow();
            validateRepeatedParams(request, paramMap);

            if (isAuthorizationHeaderExists(request)) {
                validateAuthorizationHeader(request, paramMap);
            }

            HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
            String consumerKey = getConsumerKey(httpRequest);
            validateOAuthApplication(consumerKey);

            CarbonOAuthTokenRequest oauthRequest = buildCarbonOAuthTokenRequest(httpRequest);
            OAuth2AccessTokenRespDTO oauth2AccessTokenResp = issueAccessToken(oauthRequest);

            if (oauth2AccessTokenResp.getErrorMsg() != null) {
                return handleErrorResponse(oauth2AccessTokenResp);
            } else {
                return buildTokenResponse(oauth2AccessTokenResp);
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private CarbonOAuthTokenRequest buildCarbonOAuthTokenRequest(HttpServletRequestWrapper httpRequest)
            throws OAuthSystemException, TokenEndpointBadRequestException {

        try {
            return new CarbonOAuthTokenRequest(httpRequest);
        } catch (OAuthProblemException e) {
            return handleInvalidRequest(e);
        }
    }

    private CarbonOAuthTokenRequest handleInvalidRequest(OAuthProblemException e) throws TokenEndpointBadRequestException {

        if (isInvalidRequest(e) || isUnsupportedGrantType(e)) {
            if (log.isDebugEnabled()) {
                log.debug("Error: " + e.getError() + ", description: " + e.getDescription());
            }
        } else {
            log.error("Error while creating the Carbon OAuth token request", e);
        }
        throw new TokenEndpointBadRequestException(e);
    }

    private boolean isUnsupportedGrantType(OAuthProblemException e) {
        return OAuthError.TokenResponse.UNSUPPORTED_GRANT_TYPE.equalsIgnoreCase(e.getError());
    }

    private boolean isInvalidRequest(OAuthProblemException e) {
        return OAuthError.TokenResponse.INVALID_REQUEST.equalsIgnoreCase(e.getError());
    }

    private void validateRepeatedParams(HttpServletRequest request, MultivaluedMap<String, String> paramMap)
            throws TokenEndpointBadRequestException {

        if (!validateParams(request, paramMap)) {
            throw new TokenEndpointBadRequestException("Invalid request with repeated parameters.");
        }
    }

    private void validateOAuthApplication(String consumerKey) throws InvalidApplicationClientException,
            TokenEndpointBadRequestException {

        if (isNotBlank(consumerKey)) {
            validateOauthApplication(consumerKey);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Missing parameters on the request: client_id");
            }
            throw new TokenEndpointBadRequestException("Missing parameters on the request: client_id");
        }
    }

    private Response buildTokenResponse(OAuth2AccessTokenRespDTO oauth2AccessTokenResp) throws OAuthSystemException {

        OAuthTokenResponseBuilder oAuthRespBuilder = OAuthASResponse
                .tokenResponse(HttpServletResponse.SC_OK)
                .setAccessToken(oauth2AccessTokenResp.getAccessToken())
                .setRefreshToken(oauth2AccessTokenResp.getRefreshToken())
                .setExpiresIn(Long.toString(oauth2AccessTokenResp.getExpiresIn()))
                .setTokenType(BEARER);
        oAuthRespBuilder.setScope(oauth2AccessTokenResp.getAuthorizedScopes());

        if (oauth2AccessTokenResp.getIDToken() != null) {
            oAuthRespBuilder.setParam(OAuthConstants.ID_TOKEN, oauth2AccessTokenResp.getIDToken());
        }

        OAuthResponse response = oAuthRespBuilder.buildJSONMessage();
        ResponseHeader[] headers = oauth2AccessTokenResp.getResponseHeaders();
        ResponseBuilder respBuilder = Response
                .status(response.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                        OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE)
                .header(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                        OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);

        if (headers != null) {
            for (ResponseHeader header : headers) {
                if (header != null) {
                    respBuilder.header(header.getKey(), header.getValue());
                }
            }
        }

        return respBuilder.entity(response.getBody()).build();
    }

    private Response handleErrorResponse(OAuth2AccessTokenRespDTO oauth2AccessTokenResp) throws OAuthSystemException {

        // if there is an auth failure, HTTP 401 Status Code should be sent back to the client.
        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(oauth2AccessTokenResp.getErrorCode())) {
            return handleBasicAuthFailure();
        } else if (SQL_ERROR.equals(oauth2AccessTokenResp.getErrorCode())) {
            return handleSQLError();
        } else if (OAuth2ErrorCodes.SERVER_ERROR.equals(oauth2AccessTokenResp.getErrorCode())) {
            return handleServerError();
        } else {
            // Otherwise send back HTTP 400 Status Code
            OAuthResponse response = OAuthASResponse
                    .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(oauth2AccessTokenResp.getErrorCode())
                    .setErrorDescription(oauth2AccessTokenResp.getErrorMsg())
                    .buildJSONMessage();

            ResponseHeader[] headers = oauth2AccessTokenResp.getResponseHeaders();
            ResponseBuilder respBuilder = Response.status(response.getResponseStatus());

            if (headers != null) {
                for (ResponseHeader header : headers) {
                    if (header != null) {
                        respBuilder.header(header.getKey(), header.getValue());
                    }
                }
            }
            return respBuilder.entity(response.getBody()).build();
        }
    }

    private String getConsumerKey(HttpServletRequestWrapper httpRequest) {

        if (log.isDebugEnabled()) {
            log.debug("Consumer key:" + httpRequest.getParameter(OAuth.OAUTH_CLIENT_ID));
        }
        return httpRequest.getParameter(OAuth.OAUTH_CLIENT_ID);
    }

    private void validateAuthorizationHeader(HttpServletRequest request, MultivaluedMap<String, String> paramMap)
            throws TokenEndpointAccessDeniedException {

        try {
            // The client MUST NOT use more than one authentication method in each request
            if (isClientCredentialsExistsAsParams(paramMap)) {
                if (log.isDebugEnabled()) {
                    log.debug("Client Id and Client Secret found in request body and Authorization header" +
                            ". Credentials should be sent in either request body or Authorization header, not both");
                }
                throw new TokenEndpointAccessDeniedException("Client Authentication failed");
            }
            String[] credentials = getClientCredentials(request);
            // add the credentials available in Authorization header to the parameter map
            paramMap.add(OAuth.OAUTH_CLIENT_ID, credentials[0]);
            paramMap.add(OAuth.OAUTH_CLIENT_SECRET, credentials[1]);

            if (log.isDebugEnabled()) {
                log.debug("Client credentials extracted from the Authorization Header");
            }

        } catch (OAuthClientException e) {
            // malformed credential string is considered as an auth failure.
            if (log.isDebugEnabled()) {
                log.error("Error while extracting credentials from authorization header", e);
            }

            throw new TokenEndpointAccessDeniedException("Client Authentication failed. Invalid Authorization Header");
        }
    }

    private boolean isClientCredentialsExistsAsParams(MultivaluedMap<String, String> paramMap) {
        return paramMap.containsKey(OAuth.OAUTH_CLIENT_ID) && paramMap.containsKey(OAuth.OAUTH_CLIENT_SECRET);
    }

    private String[] getClientCredentials(HttpServletRequest request) throws OAuthClientException {
        return EndpointUtil.extractCredentialsFromAuthzHeader(
                request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ));
    }

    private boolean isAuthorizationHeaderExists(HttpServletRequest request) {
        return request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ) != null;
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
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error.")
                .buildJSONMessage();

        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();

    }

    private Response handleSQLError() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_GATEWAY).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Service Unavailable Error.")
                .buildJSONMessage();

        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    private OAuth2AccessTokenRespDTO issueAccessToken(CarbonOAuthTokenRequest oauthRequest) {

        OAuth2AccessTokenReqDTO tokenReqDTO = buildAccessTokenReqDTO(oauthRequest);
        return EndpointUtil.getOAuth2Service().issueAccessToken(tokenReqDTO);
    }

    private OAuth2AccessTokenReqDTO buildAccessTokenReqDTO(CarbonOAuthTokenRequest oauthRequest) {

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
        }
        return tokenReqDTO;
    }
}
