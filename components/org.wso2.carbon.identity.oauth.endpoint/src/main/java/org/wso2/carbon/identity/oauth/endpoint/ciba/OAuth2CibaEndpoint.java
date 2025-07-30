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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.ciba.model.CibaUserNotificationContext;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.CibaAuthServiceFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCRequestObjectUtil;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidator;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.user.core.common.User;

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
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.LOGIN_HINT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REQUEST;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.SCOPE;

/**
 * Rest implementation for OAuth2 CIBA endpoint.
 */
@Path("/ciba")
@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
public class OAuth2CibaEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2CibaEndpoint.class);

    private CibaAuthRequestValidator cibaAuthRequestValidator = new CibaAuthRequestValidator();
    private CibaAuthResponseHandler cibaAuthResponseHandler = new CibaAuthResponseHandler();
    private CibaAuthCodeRequest cibaAuthCodeRequest;
    private CibaAuthCodeResponse cibaAuthCodeResponse;
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response ciba(@Context HttpServletRequest request, @Context HttpServletResponse response,
                         MultivaluedMap<String, String> params) {

        OAuthClientAuthnContext oAuthClientAuthnContext =  getClientAuthnContext(request);

        if (!oAuthClientAuthnContext.isAuthenticated()) {
            if (oAuthClientAuthnContext.getErrorCode() != null) {
                return getErrorResponse(new CibaAuthFailureException(oAuthClientAuthnContext.getErrorCode(),
                        oAuthClientAuthnContext.getErrorMessage()));
            }
            return getErrorResponse(new CibaAuthFailureException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    "Client authentication required"));
        }

        Map<String, String> parameters = transformParams(params);
        try {
            /*
              Note: The current CIBA implementation only supports either a request object or parameters,
              but not both simultaneously.
              In the future, we plan to improve this so that a provided request object will override
              any parameters.
             */
            if (StringUtils.isNotBlank(parameters.get(REQUEST))) {
                // Validate authentication request.
                validateAuthenticationRequest(parameters.get(REQUEST), oAuthClientAuthnContext.getClientId());

                // Prepare RequestDTO with validated parameters.
                cibaAuthCodeRequest = getCibaAuthCodeRequest(parameters.get(REQUEST));
            } else {
                if (containsRequiredParameters(parameters)) {
                    cibaAuthCodeRequest = getCibaAuthCodeRequest(parameters);
                } else {
                    return getErrorResponse(new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                            "Missing required parameters."));
                }
            }

            // Resolve user from the login hint. The default user resolver uses the username as the login hint.
            String userLoginIdentifier = CibaAuthServiceFactory.getCibaAuthService()
                    .resolveUser(cibaAuthCodeRequest);

            // Obtain Response from service layer of CIBA.
            cibaAuthCodeResponse = getCibaAuthCodeResponse(cibaAuthCodeRequest);

            // Send a user login request to the user (authorization device). Here we send the CIBA user authentication
            // endpoint (/ciba_auth) with other parameters to the user to complete the authentication.
            CibaAuthServiceFactory.getCibaAuthService()
                    .triggerNotification(getNotificationContext(cibaAuthCodeResponse, userLoginIdentifier));

            // Create and return Ciba Authentication Response.
            return getAuthResponse(response, cibaAuthCodeResponse);

        } catch (CibaAuthFailureException e) {
            // Returning error response.
            return getErrorResponse(e);
        } catch (CibaClientException | CibaCoreException e) {
            return getErrorResponse(new CibaAuthFailureException(e.getErrorCode(), e.getMessage()));
        }
    }

    private CibaUserNotificationContext getNotificationContext(CibaAuthCodeResponse cibaAuthCodeResponse,
                                                               String userLoginIdentifier)
            throws CibaCoreException, CibaClientException {


        CibaUserNotificationContext cibaUserNotificationContext = new CibaUserNotificationContext();
        try {
            String tenantDomain = getSpTenantDomain(cibaAuthCodeResponse.getClientId());
            User user = CibaAuthServiceFactory.getCibaAuthService().getUser(userLoginIdentifier, tenantDomain);
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(cibaAuthCodeResponse.getClientId(), tenantDomain);
            cibaUserNotificationContext.setApplicationName(appDO.getApplicationName());
            cibaUserNotificationContext.setUser(user);
            cibaUserNotificationContext.setAuthCodeKey(cibaAuthCodeResponse.getAuthCodeKey());
            cibaUserNotificationContext.setBindingMessage(cibaAuthCodeResponse.getBindingMessage());
        } catch (IdentityOAuth2Exception e) {
            throw new CibaCoreException("Error while retrieving app information.", e);
        } catch (InvalidOAuthClientException | InvalidRequestException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, e.getMessage());
        }
        return cibaUserNotificationContext;
    }

    /**
     * Creates CIBA Authentication Error Response.
     *
     * @param cibaAuthFailureException Ciba Authentication Failed Exception.
     * @return response Authentication Error Responses for AuthenticationRequest.
     */
    private Response getErrorResponse(CibaAuthFailureException cibaAuthFailureException) {

        return cibaAuthResponseHandler.createErrorResponse(cibaAuthFailureException);
    }

    /**
     * Creates CIBA AuthenticationResponse.
     *
     * @param response             Authentication response object.
     * @param cibaAuthCodeResponse CIBA Authentication Request Data Transfer Object.
     * @return Response for AuthenticationRequest.
     */
    private Response getAuthResponse(@Context HttpServletResponse response, CibaAuthCodeResponse cibaAuthCodeResponse) {

        return cibaAuthResponseHandler.createAuthResponse(response, cibaAuthCodeResponse);
    }

    /**
     * Accepts auth code request  and responds with auth code response.
     *
     * @param cibaAuthCodeRequest CIBA Authentication Request Data Transfer Object.
     * @return CibaAuthCodeResponse CIBA Authentication Response Data Transfer Object.
     * @throws CibaAuthFailureException Core exception from CIBA module.
     */
    private CibaAuthCodeResponse getCibaAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest)
            throws CibaAuthFailureException {

        try {
            cibaAuthCodeResponse = CibaAuthServiceFactory.getCibaAuthService()
                    .generateAuthCodeResponse(cibaAuthCodeRequest);
        } catch (CibaCoreException | CibaClientException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error while generating " +
                    "authentication response.", e);
        }
        return cibaAuthCodeResponse;
    }

    /**
     * Extracts validated parameters from request and prepare a DTO.
     *
     * @param authRequest CIBA Authentication Request as a String.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private CibaAuthCodeRequest getCibaAuthCodeRequest(String authRequest) throws CibaAuthFailureException {

        return cibaAuthRequestValidator.prepareAuthCodeRequest(authRequest);
    }

    /**
     * Extracts validated parameters from request and prepare a DTO.
     *
     * @param parameters CIBA Authentication Request as a String.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private CibaAuthCodeRequest getCibaAuthCodeRequest(Map<String, String> parameters)
            throws CibaAuthFailureException {

        CibaAuthCodeRequest cibaAuthCodeRequest = new CibaAuthCodeRequest();
        cibaAuthCodeRequest.setUserHint(parameters.get(LOGIN_HINT));
        cibaAuthCodeRequest.setScopes(OAuth2Util.buildScopeArray(parameters.get(Constants.SCOPE)));
        cibaAuthCodeRequest.setBindingMessage(parameters.get(CibaConstants.BINDING_MESSAGE));
        cibaAuthCodeRequest.setIssuer(parameters.get(CLIENT_ID));
        if (parameters.get(CibaConstants.REQUESTED_EXPIRY) != null) {
            cibaAuthCodeRequest.setRequestedExpiry(Long.parseLong(parameters.get(CibaConstants.REQUESTED_EXPIRY)));
        } else {
            cibaAuthCodeRequest.setRequestedExpiry(0);
        }
        return cibaAuthCodeRequest;
    }

    /**
     * Validate whether Request JWT is in proper formatting.
     *
     * @param authRequest CIBA Authentication Request as a String.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateAuthenticationRequest(String authRequest, String clientId) throws CibaAuthFailureException {

        // Validation for the proper formatting of signedJWT.
        cibaAuthRequestValidator.validateRequest(authRequest);

        // Validation for the client.
        cibaAuthRequestValidator.validateClient(authRequest, clientId);

        // Validation for the userHint.
        cibaAuthRequestValidator.validateUserHint(authRequest);

        // Validate Authentication request.
        cibaAuthRequestValidator.validateAuthRequestParams(authRequest);

        try {

            RequestObject requestObject;
            RequestObjectBuilder requestObjectBuilder;
            requestObjectBuilder = OAuthServerConfiguration.getInstance().getRequestObjectBuilders().
                    get(REQUEST_PARAM_VALUE_BUILDER);

            OAuth2Parameters parameters = new OAuth2Parameters();
            parameters.setClientId(clientId);
            parameters.setTenantDomain(getSpTenantDomain(clientId));

            if (requestObjectBuilder == null) {
                String error = "Unable to build the OIDC Request Object";
                throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, error);
            }
            requestObject = requestObjectBuilder.buildRequestObject(authRequest,
                    parameters);
            RequestObjectValidator requestObjectValidator = OAuthServerConfiguration.getInstance()
                    .getCIBARequestObjectValidator();

            OIDCRequestObjectUtil.validateRequestObjectSignature(parameters, requestObject, requestObjectValidator);

            if (!requestObjectValidator.validateRequestObject(requestObject, parameters)) {
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid parameters " +
                        "found in the Request Object.");

            }
        } catch (InvalidRequestException | RequestObjectException e) {
            if (log.isDebugEnabled()) {
                log.debug(OAuth2ErrorCodes.INVALID_REQUEST, e);
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, e.getMessage());
        }
    }

    private boolean containsRequiredParameters(Map<String, String> parameters) {

        return parameters.containsKey(CLIENT_ID) && parameters.containsKey(SCOPE) &&
                parameters.containsKey(Constants.LOGIN_HINT);
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

    private OAuthClientAuthnContext getClientAuthnContext(HttpServletRequest request) {
        OAuthClientAuthnContext oAuthClientAuthnContext;
        Object oauthClientAuthnContextObj = request.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT);
        if (oauthClientAuthnContextObj instanceof OAuthClientAuthnContext) {
            oAuthClientAuthnContext = (OAuthClientAuthnContext) oauthClientAuthnContextObj;
        } else {
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorMessage("Client Authentication Failed");
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }
        return oAuthClientAuthnContext;
    }

    private String getSpTenantDomain(String clientId) throws InvalidRequestException {

        try {
            // At this point we have verified that a valid app exists for the client_id. So we directly get the SP
            // tenantDomain.
            return OAuth2Util.getTenantDomainOfOauthApp(clientId);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(OAuth2ErrorCodes.INVALID_REQUEST, e);
            }
            throw new InvalidRequestException("Error retrieving Service Provider tenantDomain for client_id: "
                    + clientId, OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes
                    .UNEXPECTED_SERVER_ERROR);
        }
    }
}
