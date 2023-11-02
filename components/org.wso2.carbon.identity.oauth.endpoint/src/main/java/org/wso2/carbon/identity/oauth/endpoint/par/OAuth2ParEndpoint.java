/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthData;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCRequestObjectUtil;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REQUEST;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.RESPONSE_MODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.RESPONSE_TYPE;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuthAuthzRequest;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getParAuthService;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getSPTenantDomainFromClientId;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;

/**
 * REST implementation for OAuth2 PAR endpoint.
 * The endpoint accepts POST request with the authorization parameters.
 * Returns a request_uri as a reference for the submitted parameters and the expiry time.
 */
@Path("/par")
@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
public class OAuth2ParEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2ParEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response par(@Context HttpServletRequest request, @Context HttpServletResponse response,
                        MultivaluedMap<String, String> params) {

        try {
            checkClientAuthentication(request);
            handleValidation(request, params);
            Map<String, String> parameters = transformParams(params);
            ParAuthData parAuthData =
                    getParAuthService().handleParAuthRequest(parameters);
            return createAuthResponse(response, parAuthData);
        } catch (ParClientException e) {
            return handleParClientException(e);
        } catch (ParCoreException e) {
            return handleParCoreException(e);
        }
    }

    private Map<String, String> transformParams(MultivaluedMap<String, String> params) {

        Map<String, String> parameters = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : params.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (!values.isEmpty()) {
                String value = values.get(0);
                parameters.put(key, value);
            }
        }

        return parameters;
    }

    private Response createAuthResponse(HttpServletResponse response, ParAuthData parAuthData) {

        response.setContentType(MediaType.APPLICATION_JSON);
        JSONObject parAuthResponse = new JSONObject();
        parAuthResponse.put(OAuthConstants.OAuth20Params.REQUEST_URI,
                ParConstants.REQUEST_URI_PREFIX + parAuthData.getrequestURIReference());
        parAuthResponse.put(ParConstants.EXPIRES_IN, parAuthData.getExpiryTime());
        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_CREATED);
        return responseBuilder.entity(parAuthResponse.toString()).build();
    }

    private Response handleParClientException(ParClientException exception) {

        String errorCode = exception.getErrorCode();
        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR, errorCode);
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR_DESCRIPTION, exception.getMessage());

        Response.ResponseBuilder responseBuilder;
        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(errorCode)) {
            responseBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED)
                    .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo());
        } else {
            responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        }
        log.debug("Client error while handling the request: ", exception);
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }

    private Response handleParCoreException(ParCoreException parCoreException) {

        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR, OAuth2ErrorCodes.SERVER_ERROR);
        parErrorResponse.put(OAuthConstants.OAUTH_ERROR_DESCRIPTION, ParConstants.INTERNAL_SERVER_ERROR);

        Response.ResponseBuilder respBuilder = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        log.error("Exception occurred when handling the request: ", parCoreException);
        return respBuilder.entity(parErrorResponse.toString()).build();
    }

    private void handleValidation(HttpServletRequest request, MultivaluedMap<String, String> params)
            throws ParCoreException {

        validateInputParameters(request);
        validateClient(request, params);
        validateRepeatedParams(request, params);
        validateAuthzRequest(request);
    }

    private boolean isRequestUriProvided(MultivaluedMap<String, String> params) {

        return params.containsKey(OAuthConstants.OAuth20Params.REQUEST_URI);
    }

    private void checkClientAuthentication(HttpServletRequest request) throws ParCoreException {

        OAuthClientAuthnContext oAuthClientAuthnContext = getClientAuthnContext(request);
        if (oAuthClientAuthnContext.isAuthenticated()) {
            return;
        }
        if (StringUtils.isNotBlank(oAuthClientAuthnContext.getErrorCode())) {
            if (OAuth2ErrorCodes.SERVER_ERROR.equals(oAuthClientAuthnContext.getErrorCode())) {
                throw new ParCoreException(oAuthClientAuthnContext.getErrorCode(),
                        oAuthClientAuthnContext.getErrorMessage());
            } else if (OAuth2ErrorCodes.INVALID_CLIENT.equals(oAuthClientAuthnContext.getErrorCode())) {
                throw new ParClientException(oAuthClientAuthnContext.getErrorCode(),
                        oAuthClientAuthnContext.getErrorMessage());
            }
            throw new ParClientException(oAuthClientAuthnContext.getErrorCode(),
                    oAuthClientAuthnContext.getErrorMessage());
        }

        throw new ParClientException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, ParConstants.CLIENT_AUTH_REQUIRED_ERROR);
    }

    private OAuthClientAuthnContext getClientAuthnContext(HttpServletRequest request) {

        Object oauthClientAuthnContextObj = request.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT);
        if (oauthClientAuthnContextObj instanceof OAuthClientAuthnContext) {
            return (OAuthClientAuthnContext) oauthClientAuthnContextObj;
        }
        return createNewOAuthClientAuthnContext();
    }

    private OAuthClientAuthnContext createNewOAuthClientAuthnContext() {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(false);
        oAuthClientAuthnContext.setErrorMessage(ParConstants.PAR_CLIENT_AUTH_ERROR);
        oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
        return oAuthClientAuthnContext;
    }

    private void validateClient(HttpServletRequest request, MultivaluedMap<String, String> params)
            throws ParClientException {

        OAuth2ClientValidationResponseDTO validationResponse = getOAuth2Service().validateClientInfo(request);

        if (!validationResponse.isValidClient()) {
            if (OAuth2ErrorCodes.INVALID_CLIENT.equals(validationResponse.getErrorCode())) {
                throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST, validationResponse.getErrorMsg());
            }
            throw new ParClientException(validationResponse.getErrorCode(), validationResponse.getErrorMsg());
        }
        if (isRequestUriProvided(params)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    ParConstants.REQUEST_URI_IN_REQUEST_BODY_ERROR);
        }
    }

    private void validateRepeatedParams(HttpServletRequest request, Map<String, List<String>> paramMap)
            throws ParClientException {

        if (!validateParams(request, paramMap)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    ParConstants.REPEATED_PARAMS_IN_REQUEST_ERROR);
        }
    }

    private void validateAuthzRequest(HttpServletRequest request) throws ParCoreException {

        try {
            OAuthAuthzRequest oAuthAuthzRequest = getOAuthAuthzRequest(request);
            RequestObject requestObject = validateRequestObject(oAuthAuthzRequest);
            Map<String, String> oauthParams = overrideRequestObjectParams(request, requestObject);
            if (isFapiConformant(oAuthAuthzRequest.getClientId())) {
                EndpointUtil.validateFAPIAllowedResponseTypeAndMode(oauthParams.get(RESPONSE_TYPE),
                        oauthParams.get(RESPONSE_MODE));
                validatePKCEParameters(oauthParams);
            }
        } catch (OAuthProblemException e) {
            throw new ParClientException(e.getError(), e.getDescription(), e);
        } catch (OAuthSystemException e) {
            throw new ParCoreException(OAuth2ErrorCodes.SERVER_ERROR, e.getMessage(), e);
        }
    }

    /**
     * Return a map of parameters needed for validations overriding the values from the request object if present.
     *
     * @param request       Http servlet request
     * @param requestObject request object
     * @return map of parameters
     */
    private Map<String, String> overrideRequestObjectParams(HttpServletRequest request, RequestObject requestObject) {

        Map<String, String> oauthParams = new HashMap<>();
        oauthParams.put(RESPONSE_MODE, getParameterValue(request, requestObject, RESPONSE_MODE));
        oauthParams.put(RESPONSE_TYPE, getParameterValue(request, requestObject, RESPONSE_TYPE));
        oauthParams.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE,
                getParameterValue(request, requestObject, OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE));
        oauthParams.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD,
                getParameterValue(request, requestObject, OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD));
        return oauthParams;
    }

    /**
     * Get the parameter value from the PAR request or from the request object if present. Request object parameter
     * will be prioritized.
     *
     * @param request       Http servlet request
     * @param requestObject request object
     * @param parameter     parameter name
     * @return parameter value
     */
    private String getParameterValue(HttpServletRequest request, RequestObject requestObject, String parameter) {

        String parameterValue = request.getParameter(parameter);
        if (requestObject != null && requestObject.getClaimsSet() != null &&
                StringUtils.isNotBlank(requestObject.getClaimValue(parameter))) {
            parameterValue = requestObject.getClaimValue(parameter);
        }
        return parameterValue;
    }

    private void validateInputParameters(HttpServletRequest request) throws ParClientException {

        try {
            getOAuth2Service().validateInputParameters(request);
        } catch (InvalidOAuthRequestException e) {
            throw new ParClientException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    private RequestObject validateRequestObject(OAuthAuthzRequest oAuthAuthzRequest) throws ParCoreException {

        try {
            RequestObject requestObject = null;
            if (OAuth2Util.isOIDCAuthzRequest(oAuthAuthzRequest.getScopes())) {
                if (StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST))) {

                    OAuth2Parameters parameters = new OAuth2Parameters();
                    parameters.setClientId(oAuthAuthzRequest.getClientId());
                    parameters.setRedirectURI(oAuthAuthzRequest.getRedirectURI());
                    parameters.setResponseType(oAuthAuthzRequest.getResponseType());
                    parameters.setTenantDomain(getSPTenantDomainFromClientId(oAuthAuthzRequest.getClientId()));

                    requestObject = OIDCRequestObjectUtil.buildRequestObject(oAuthAuthzRequest, parameters);
                    if (requestObject == null) {
                        throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                                ParConstants.INVALID_REQUEST_OBJECT);
                    }
                } else if (isFapiConformant(oAuthAuthzRequest.getClientId())) {
                    /* Mandate request object for FAPI requests
                    https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server (5.2.2-1) */
                    throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST, ParConstants.REQUEST_OBJECT_MISSING);
                }
            }
            return requestObject;
        } catch (RequestObjectException e) {
            if (OAuth2ErrorCodes.SERVER_ERROR.equals(e.getErrorCode())) {
                throw new ParCoreException(e.getErrorCode(), e.getMessage(), e);
            }
            throw new ParClientException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    private boolean isFapiConformant(String clientId) throws ParCoreException {

        try {
            return OAuth2Util.isFapiConformantApp(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_CLIENT, "Could not find an existing app for " +
                    "clientId: " + clientId, e);
        } catch (IdentityOAuth2Exception e) {
            throw new ParCoreException(OAuth2ErrorCodes.SERVER_ERROR, "Error while obtaining the service " +
                    "provider for clientId: " + clientId, e);
        }
    }


    /**
     * Validate PKCE parameters for PAR requests.
     * According to FAPI(5.2.2-18), PAR requests require to use PKCE (RFC7636) with S256 as the code challenge method.
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server">...</a>
     *
     * @param paramMap parameter map
     * @throws ParClientException if PKCE validation fails
     */
    private void validatePKCEParameters(Map<String, String> paramMap) throws ParClientException {

        String codeChallenge = paramMap.get(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE);
        String codeChallengeMethod = paramMap.get(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD);

        if (StringUtils.isEmpty(codeChallenge)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Mandatory parameter code_challenge, not found in the request.");
        }
        if (StringUtils.isEmpty(codeChallengeMethod)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Mandatory parameter code_challenge_method, not found in the request.");
        } else if (!OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(codeChallengeMethod)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST, "Unsupported PKCE Challenge Method.");
        }
    }
}
