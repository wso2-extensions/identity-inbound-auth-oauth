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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointBadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuth2ServiceFactory;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthTokenRequest;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.handlers.response.OAuth2TokenResponse;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.PROP_CLIENT_ID;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getHttpServletResponseWrapper;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.parseJsonTokenRequest;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.startSuperTenantFlow;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.triggerOnTokenExceptionListeners;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateAppAccess;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateOauthApplication;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;

/**
 * Rest implementation for OAuthu2 token endpoint.
 */
@Path("/token")
@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
public class OAuth2TokenEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2TokenEndpoint.class);
    public static final String BEARER = "Bearer";
    private static final String SQL_ERROR = "sql_error";

    @POST
    @Path("/")
    @Consumes("application/json")
    @Produces("application/json")
    public Response issueAccessToken(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                     String payload) throws
            OAuthSystemException, InvalidRequestParentException {

        Map<String, List<String>> paramMap;
        try {
            // Start super tenant flow only if tenant qualified URLs are disabled.
            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                startSuperTenantFlow();
            }
            paramMap = parseJsonTokenRequest(payload);
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.RECEIVE_TOKEN_REQUEST);
            if (MapUtils.isNotEmpty(paramMap) && paramMap.containsKey(PROP_CLIENT_ID)) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, paramMap.get(PROP_CLIENT_ID));
            }
            diagnosticLogBuilder.resultMessage("Successfully received the token request.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        } catch (TokenEndpointBadRequestException e) {
            triggerOnTokenExceptionListeners(e, request, null);
            throw e;
        } finally {
            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
        return issueAccessToken(request, response, paramMap);
    }

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response issueAccessToken(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                     MultivaluedMap<String, String> paramMap)
            throws OAuthSystemException, InvalidRequestParentException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.RECEIVE_TOKEN_REQUEST);
            if (MapUtils.isNotEmpty(paramMap) && paramMap.containsKey(PROP_CLIENT_ID)) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, paramMap.getFirst(PROP_CLIENT_ID));
            }
            diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .resultMessage("Successfully received the token request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return issueAccessToken(request, response, (Map<String, List<String>>) paramMap);
    }

    protected Response issueAccessToken(HttpServletRequest request, HttpServletResponse response,
                                        Map<String, List<String>> paramMap) throws
            OAuthSystemException, InvalidRequestParentException {

        try {
            // Start super tenant flow only if tenant qualified URLs are disabled.
            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                startSuperTenantFlow();
            }
            validateRepeatedParams(request, paramMap);
            validateSensitiveDataInQueryParams(request);
            HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
            CarbonOAuthTokenRequest oauthRequest = buildCarbonOAuthTokenRequest(httpRequest);
            OAuthClientAuthnContext oauthClientAuthnContext = oauthRequest.getoAuthClientAuthnContext();

            if (!oauthClientAuthnContext.isAuthenticated()
                    && OAuth2ErrorCodes.INVALID_CLIENT.equals(oauthClientAuthnContext.getErrorCode())) {
                return handleBasicAuthFailure(oauthClientAuthnContext.getErrorMessage());
            }

            validateOAuthApplication(oauthClientAuthnContext);
            validateIfApplicationAccessEnabled(oauthClientAuthnContext);
            OAuth2AccessTokenRespDTO oauth2AccessTokenResp = issueAccessToken(oauthRequest,
                    httpRequest, getHttpServletResponseWrapper(response));

            if (oauth2AccessTokenResp.getErrorMsg() != null) {
                return handleErrorResponse(oauth2AccessTokenResp);
            } else {
                return buildTokenResponse(oauth2AccessTokenResp);
            }
        } catch (TokenEndpointBadRequestException | OAuthSystemException | InvalidApplicationClientException e) {
            triggerOnTokenExceptionListeners(e, request, paramMap);
            throw e;

        } finally {
            UserCoreUtil.setDomainInThreadLocal(null);
            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                PrivilegedCarbonContext.endTenantFlow();
            }
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

    private CarbonOAuthTokenRequest handleInvalidRequest(OAuthProblemException e)
            throws TokenEndpointBadRequestException {

        if (isInvalidRequest(e) || isUnsupportedGrantType(e)) {
            if (log.isDebugEnabled()) {
                log.debug("Error: " + e.getError() + ", description: " + e.getDescription());
            }
        } else {
            log.error("Error while creating the Carbon OAuth token request", e);
        }
        throw new TokenEndpointBadRequestException(e.getDescription(), e);
    }

    private boolean isUnsupportedGrantType(OAuthProblemException e) {

        return OAuthError.TokenResponse.UNSUPPORTED_GRANT_TYPE.equalsIgnoreCase(e.getError());
    }

    private boolean isInvalidRequest(OAuthProblemException e) {

        return OAuthError.TokenResponse.INVALID_REQUEST.equalsIgnoreCase(e.getError());
    }

    private void validateRepeatedParams(HttpServletRequest request, Map<String, List<String>> paramMap)
            throws TokenEndpointBadRequestException {

        if (!validateParams(request, paramMap)) {
            throw new TokenEndpointBadRequestException("Invalid request with repeated parameters.");
        }
    }

    private void validateSensitiveDataInQueryParams(HttpServletRequest request)
            throws TokenEndpointBadRequestException {

        String queryString = request.getQueryString();
        if (StringUtils.isNotBlank(queryString)) {
            boolean containsSensitiveData = Arrays.stream(queryString.split("&"))
                    .map(param -> param.split("=")[0])
                    .anyMatch(OAuthServerConfiguration.getInstance().getRestrictedQueryParameters()::contains);
            if (containsSensitiveData) {
                throw new TokenEndpointBadRequestException("Invalid request with sensitive data in the URL.");
            }
        }
    }

    private void validateOAuthApplication(OAuthClientAuthnContext oAuthClientAuthnContext)
            throws InvalidApplicationClientException {

        if (isNotBlank(oAuthClientAuthnContext.getClientId()) && !oAuthClientAuthnContext
                .isMultipleAuthenticatorsEngaged()) {
            validateOauthApplication(oAuthClientAuthnContext.getClientId());
        }
    }

    private void validateIfApplicationAccessEnabled(OAuthClientAuthnContext oAuthClientAuthnContext)
            throws InvalidApplicationClientException, OAuthSystemException {

        if (isNotBlank(oAuthClientAuthnContext.getClientId())) {
            validateAppAccess(oAuthClientAuthnContext.getClientId());
        }
    }

    private Response buildTokenResponse(OAuth2AccessTokenRespDTO oauth2AccessTokenResp) throws OAuthSystemException {

        if (StringUtils.isBlank(oauth2AccessTokenResp.getTokenType())) {
            oauth2AccessTokenResp.setTokenType(BEARER);
        }

        OAuth2TokenResponse.OAuthTokenResponseBuilder oAuthRespBuilder = OAuth2TokenResponse
                .tokenResponse(HttpServletResponse.SC_OK)
                .setAccessToken(oauth2AccessTokenResp.getAccessToken())
                .setRefreshToken(oauth2AccessTokenResp.getRefreshToken())
                .setExpiresIn(Long.toString(oauth2AccessTokenResp.getExpiresIn()))
                .setTokenType(oauth2AccessTokenResp.getTokenType());

        oAuthRespBuilder.setScope(oauth2AccessTokenResp.getAuthorizedScopes());

        if (oauth2AccessTokenResp.getIDToken() != null) {
            oAuthRespBuilder.setParam(OAuthConstants.ID_TOKEN, oauth2AccessTokenResp.getIDToken());
        }

        // Set custom parameters in token response if supported
        if (MapUtils.isNotEmpty(oauth2AccessTokenResp.getParameters())) {
            oauth2AccessTokenResp.getParameters().forEach(oAuthRespBuilder::setParam);
        }

        // Set custom parameters in token response if supported.
        if (MapUtils.isNotEmpty(oauth2AccessTokenResp.getParameterObjects())) {
            oauth2AccessTokenResp.getParameterObjects().forEach(oAuthRespBuilder::setParam);
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
            return handleBasicAuthFailure(oauth2AccessTokenResp.getErrorMsg());
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

    private Response handleBasicAuthFailure(String errorMessage) throws OAuthSystemException {

        if (StringUtils.isBlank(errorMessage)) {
            errorMessage = "Client Authentication failed.";
        }

        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setError(OAuth2ErrorCodes.INVALID_CLIENT)
                .setErrorDescription(errorMessage).buildJSONMessage();
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

    private OAuth2AccessTokenRespDTO issueAccessToken(CarbonOAuthTokenRequest oauthRequest,
                                                      HttpServletRequestWrapper httpServletRequestWrapper,
                                                      HttpServletResponseWrapper httpServletResponseWrapper) {

        OAuth2AccessTokenReqDTO tokenReqDTO = buildAccessTokenReqDTO(oauthRequest, httpServletRequestWrapper,
                httpServletResponseWrapper);
        return OAuth2ServiceFactory.getOAuth2Service().issueAccessToken(tokenReqDTO);
    }

    private OAuth2AccessTokenReqDTO buildAccessTokenReqDTO(CarbonOAuthTokenRequest oauthRequest,
                                                           HttpServletRequestWrapper httpServletRequestWrapper,
                                                           HttpServletResponseWrapper httpServletResponseWrapper) {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthClientAuthnContext oauthClientAuthnContext = oauthRequest.getoAuthClientAuthnContext();
        tokenReqDTO.setoAuthClientAuthnContext(oauthClientAuthnContext);
        String grantType = oauthRequest.getGrantType();
        tokenReqDTO.setGrantType(grantType);
        tokenReqDTO.setClientId(oauthClientAuthnContext.getClientId());
        tokenReqDTO.setClientSecret(oauthRequest.getClientSecret());
        tokenReqDTO.setCallbackURI(oauthRequest.getRedirectURI());
        tokenReqDTO.setScope(oauthRequest.getScopes().toArray(new String[0]));
        tokenReqDTO.setTenantDomain(oauthRequest.getTenantDomain());
        tokenReqDTO.setPkceCodeVerifier(oauthRequest.getPkceCodeVerifier());
        // Set all request parameters to the OAuth2AccessTokenReqDTO
        tokenReqDTO.setRequestParameters(oauthRequest.getRequestParameters());
        // Set all request headers to the OAuth2AccessTokenReqDTO
        tokenReqDTO.setHttpRequestHeaders(oauthRequest.getHttpRequestHeaders());
        // Set the request wrapper so we can get remote information later.
        tokenReqDTO.setHttpServletRequestWrapper(httpServletRequestWrapper);
        tokenReqDTO.setHttpServletResponseWrapper(httpServletResponseWrapper);

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
        tokenReqDTO.addAuthenticationMethodReference(grantType);

        if (AuthorizationDetailsUtils.isRichAuthorizationRequest(oauthRequest)) {
            final String encodedAuthorizationDetailsJson = oauthRequest
                    .getParam(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS);
            final String authorizationDetailsJson = AuthorizationDetailsUtils
                    .getUrlDecodedAuthorizationDetails(encodedAuthorizationDetailsJson);

            if (log.isDebugEnabled()) {
                log.debug("Adding requested authorization details to tokenReqDTO: " + authorizationDetailsJson);
            }
            tokenReqDTO.setAuthorizationDetails(new AuthorizationDetails(authorizationDetailsJson));
        }

        tokenReqDTO.setActorToken(oauthRequest.getParam(OAuthConstants.ACTOR_TOKEN));

        return tokenReqDTO;
    }
}
