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

package org.wso2.carbon.identity.oauth.endpoint.revoke;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.exception.RevokeEndpointAccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.RevokeEndpointBadRequestException;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_REQ_HEADER_AUTHZ;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_PRAGMA;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.extractCredentialsFromAuthzHeader;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getRealmInfo;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.startSuperTenantFlow;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;

@Path("/revoke")
public class OAuthRevocationEndpoint {

    private static final Log log = LogFactory.getLog(OAuthRevocationEndpoint.class);
    private static final String TOKEN_PARAM = "token";
    private static final String TOKEN_TYPE_HINT_PARAM = "token_type_hint";
    private static final String CALLBACK_PARAM = "callback";
    private static final String APPLICATION_JAVASCRIPT = "application/javascript";
    private static final String TEXT_HTML = "text/html";

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    public Response revokeAccessToken(@Context HttpServletRequest request, MultivaluedMap<String, String> paramMap)
            throws OAuthSystemException, InvalidRequestParentException {

        try {
            startSuperTenantFlow();
            validateRepeatedParams(request, paramMap);

            HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
            String token = getToken(paramMap, httpRequest);
            String callback = getCallback(paramMap, httpRequest);
            if (isEmpty(token)) {
                return handleClientFailure(callback);
            }
            String tokenType = getTokenType(paramMap, httpRequest);

            if (isAuthorizationHeaderExists(request)) {
                validateAuthorizationHeader(request, paramMap, callback);
            }

            OAuthRevocationRequestDTO revokeRequest = buildOAuthRevocationRequest(paramMap, token, tokenType);
            OAuthRevocationResponseDTO oauthRevokeResp = revokeTokens(revokeRequest);

            if (oauthRevokeResp.getErrorMsg() != null) {
                return handleErrorResponse(callback, oauthRevokeResp);
            } else {
                return handleRevokeResponse(callback, oauthRevokeResp);
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

    }

    private Response handleRevokeResponse(String callback, OAuthRevocationResponseDTO oauthRevokeResp) throws OAuthSystemException {

        OAuthResponse response;
        if (isNotEmpty(callback)) {
            response = CarbonOAuthASResponse.revokeResponse(HttpServletResponse.SC_OK).buildBodyMessage();
            response.setBody(callback + "();");
        } else {
            response = CarbonOAuthASResponse.revokeResponse(HttpServletResponse.SC_OK).buildBodyMessage();
        }

        ResponseHeader[] headers = oauthRevokeResp.getResponseHeaders();
        ResponseBuilder respBuilder = Response
                .status(response.getResponseStatus())
                .header(HTTP_RESP_HEADER_CACHE_CONTROL, HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE)
                .header(HTTPConstants.HEADER_CONTENT_LENGTH, "0")
                .header(HTTP_RESP_HEADER_PRAGMA, HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);

        if (headers != null) {
            for (ResponseHeader header : headers) {
                if (header != null) {
                    respBuilder.header(header.getKey(), header.getValue());
                }
            }
        }

        if (isNotEmpty(callback)) {
            respBuilder.header(HttpHeaders.CONTENT_TYPE, APPLICATION_JAVASCRIPT);
        } else {
            respBuilder.header(HttpHeaders.CONTENT_TYPE, TEXT_HTML);
        }
        return respBuilder.entity(response.getBody()).build();
    }

    private Response handleErrorResponse(String callback, OAuthRevocationResponseDTO oauthRevokeResp)
            throws RevokeEndpointAccessDeniedException, OAuthSystemException {
        // if there is an auth failure, HTTP 401 Status Code should be sent back to the client.
        if (isErrorInvalidClient(oauthRevokeResp)) {
            throw new RevokeEndpointAccessDeniedException("Client Authentication failed.", null, callback);
        } else if (isErrorUnauthorizedClient(oauthRevokeResp)) {
            return handleAuthorizationFailure(callback);
        }
        // Otherwise send back HTTP 400 Status Code
        return handleClientFailure(callback, oauthRevokeResp);
    }

    private boolean isErrorUnauthorizedClient(OAuthRevocationResponseDTO oauthRevokeResp) {
        return OAuth2ErrorCodes.UNAUTHORIZED_CLIENT.equals(oauthRevokeResp.getErrorCode());
    }

    private boolean isErrorInvalidClient(OAuthRevocationResponseDTO oauthRevokeResp) {
        return OAuth2ErrorCodes.INVALID_CLIENT.equals(oauthRevokeResp.getErrorCode());
    }

    private OAuthRevocationRequestDTO buildOAuthRevocationRequest(
            MultivaluedMap<String, String> paramMap, String token, String tokenType) {

        OAuthRevocationRequestDTO revokeRequest = new OAuthRevocationRequestDTO();
        if (isClientIdExists(paramMap)) {
            revokeRequest.setConsumerKey(paramMap.getFirst(OAuth.OAUTH_CLIENT_ID));
        }
        if (isClientSecretExists(paramMap)) {
            revokeRequest.setConsumerSecret(paramMap.getFirst(OAuth.OAUTH_CLIENT_SECRET));
        }
        revokeRequest.setToken(token);
        if (isNotEmpty(tokenType)) {
            revokeRequest.setTokenType(tokenType);
        }
        return revokeRequest;
    }

    private boolean isClientSecretExists(MultivaluedMap<String, String> paramMap) {
        return paramMap.get(OAuth.OAUTH_CLIENT_SECRET) != null;
    }

    private boolean isClientIdExists(MultivaluedMap<String, String> paramMap) {
        return paramMap.get(OAuth.OAUTH_CLIENT_ID) != null;
    }

    private void validateAuthorizationHeader(HttpServletRequest request, MultivaluedMap<String, String> paramMap,
                               String callback) throws RevokeEndpointAccessDeniedException {

        try {
            // The client MUST NOT use more than one authentication method in each request
            if (isClientCredentialsExistsAsParams(paramMap)) {
                if (log.isDebugEnabled()) {
                    log.debug("Client Id and Client Secret found in request body and Authorization header" +
                            ". Credentials should be sent in either request body or Authorization header, not both");
                }
                throw new RevokeEndpointAccessDeniedException("Client Authentication failed.", null, callback);
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
                log.debug("Error while extracting credentials from authorization header", e);
            }
            throw new RevokeEndpointAccessDeniedException(
                    "Client Authentication failed. Invalid Authorization Header.", null, callback);
        }
    }

    private boolean isClientCredentialsExistsAsParams(MultivaluedMap<String, String> paramMap) {
        return paramMap.containsKey(OAuth.OAUTH_CLIENT_ID) && paramMap.containsKey(OAuth.OAUTH_CLIENT_SECRET);
    }

    private String[] getClientCredentials(HttpServletRequest request) throws OAuthClientException {
        return extractCredentialsFromAuthzHeader(request.getHeader(HTTP_REQ_HEADER_AUTHZ));
    }

    private boolean isAuthorizationHeaderExists(@Context HttpServletRequest request) {
        return request.getHeader(HTTP_REQ_HEADER_AUTHZ) != null;
    }

    private String getCallback(MultivaluedMap<String, String> paramMap, HttpServletRequestWrapper httpRequest) {

        String callback = httpRequest.getParameter(CALLBACK_PARAM);
        if (isBlank(callback) && isCallbackExistsAsParam(paramMap)) {
            callback = paramMap.getFirst(CALLBACK_PARAM);
        }
        return callback;
    }

    private boolean isCallbackExistsAsParam(MultivaluedMap<String, String> paramMap) {
        return paramMap.get(CALLBACK_PARAM) != null && !paramMap.get(CALLBACK_PARAM).isEmpty();
    }

    private String getTokenType(MultivaluedMap<String, String> paramMap, HttpServletRequestWrapper httpRequest) {

        String tokenType = httpRequest.getParameter(TOKEN_TYPE_HINT_PARAM);
        if (isBlank(tokenType) && isTokenTypeExistsAsParam(paramMap)) {
            tokenType = paramMap.getFirst(TOKEN_TYPE_HINT_PARAM);
        }

        if (log.isDebugEnabled()) {
            log.debug("Token Type is :" + tokenType);
        }
        return tokenType;
    }

    private boolean isTokenTypeExistsAsParam(MultivaluedMap<String, String> paramMap) {
        return paramMap.get(TOKEN_TYPE_HINT_PARAM) != null && !paramMap.get(TOKEN_TYPE_HINT_PARAM).isEmpty();
    }

    private String getToken(MultivaluedMap<String, String> paramMap, HttpServletRequestWrapper httpRequest) {

        String token = httpRequest.getParameter(TOKEN_PARAM);
        if (isBlank(token) && isTokenExistsAsParam(paramMap)) {
            token = paramMap.getFirst(TOKEN_PARAM);
        }
        return token;
    }

    private boolean isTokenExistsAsParam(MultivaluedMap<String, String> paramMap) {
        return paramMap.get(TOKEN_PARAM) != null && !paramMap.get(TOKEN_PARAM).isEmpty();
    }

    private Response handleAuthorizationFailure(String callback)
            throws OAuthSystemException {
        if (isBlank(callback)) {
            OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                    .setError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
                    .setErrorDescription("Client Authentication failed.").buildJSONMessage();
            return Response.status(response.getResponseStatus())
                    .header(HTTP_RESP_HEADER_AUTHENTICATE, getRealmInfo())
                    .header(HttpHeaders.CONTENT_TYPE, TEXT_HTML)
                    .entity(response.getBody()).build();
        } else {
            OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                    .setError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT).buildJSONMessage();
            return Response.status(response.getResponseStatus())
                    .header(HTTP_RESP_HEADER_AUTHENTICATE, getRealmInfo())
                    .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JAVASCRIPT)
                    .entity(callback + "(" + response.getBody() + ");").build();
        }
    }

    private Response handleClientFailure(String callback)
            throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Token parameter is missing in the revoke request");
        }

        if (isBlank(callback)) {
            OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(OAuth2ErrorCodes.INVALID_REQUEST)
                    .setErrorDescription("Invalid revocation request").buildJSONMessage();
            return Response.status(response.getResponseStatus())
                    .header(HttpHeaders.CONTENT_TYPE, TEXT_HTML)
                    .entity(response.getBody()).build();
        } else {
            OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(OAuth2ErrorCodes.INVALID_REQUEST).buildJSONMessage();
            return Response.status(response.getResponseStatus())
                    .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JAVASCRIPT)
                    .entity(callback + "(" + response.getBody() + ");").build();
        }
    }

    private Response handleClientFailure(String callback, OAuthRevocationResponseDTO dto)
            throws OAuthSystemException {

        if (isBlank(callback)) {
            OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(dto.getErrorCode())
                    .setErrorDescription(dto.getErrorMsg()).buildJSONMessage();
            return Response.status(response.getResponseStatus())
                    .header(HttpHeaders.CONTENT_TYPE, TEXT_HTML)
                    .entity(response.getBody()).build();
        } else {
            OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(dto.getErrorCode()).buildJSONMessage();
            return Response.status(response.getResponseStatus())
                    .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JAVASCRIPT)
                    .entity(callback + "(" + response.getBody() + ");").build();
        }
    }

    private OAuthRevocationResponseDTO revokeTokens(OAuthRevocationRequestDTO oauthRequest) {
        return getOAuth2Service().revokeTokenByOAuthClient(oauthRequest);
    }

    private void validateRepeatedParams(HttpServletRequest request, MultivaluedMap<String, String> paramMap)
            throws RevokeEndpointBadRequestException {

        if (!validateParams(request, paramMap)) {
            throw new RevokeEndpointBadRequestException("Invalid request with repeated parameters.");
        }
    }
}
