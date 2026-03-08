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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
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
                         MultivaluedMap paramMap) {

        OAuthClientAuthnContext oAuthClientAuthnContext =  getClientAuthnContext(request);
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        if (!oAuthClientAuthnContext.isAuthenticated()) {
            if (oAuthClientAuthnContext.getErrorCode() != null) {
                return getErrorResponse(new CibaAuthFailureException(oAuthClientAuthnContext.getErrorCode(),
                        oAuthClientAuthnContext.getErrorMessage()));
            }
            return getErrorResponse(new CibaAuthFailureException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    "Client authentication required"));
        }

        request = new OAuthRequestWrapper(request, (Map<String, List<String>>) paramMap);

        if (log.isDebugEnabled()) {
            log.debug("Authentication request has hit Client Initiated Back-channel Authentication EndPoint.");
        }

        try {
            // Check if request has the 'request' JWT parameter or individual parameters
            String authRequest = request.getParameter(CibaConstants.REQUEST);
            
            if (authRequest != null) {
                // JWT-based request flow
                // Validate authentication request.
                validateAuthenticationRequest(authRequest, oAuthClientAuthnContext.getClientId());

                // Prepare RequestDTO with validated parameters from JWT.
                cibaAuthCodeRequest = getCibaAuthCodeRequest(authRequest);
            } else {
                // Parameter-based request flow (for simpler testing)
                // Check for required parameters
                Map<String, String> params = transformParams(paramMap);
                if (!containsRequiredParameters(params)) {
                    throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                            "Missing required parameters. Either 'request' JWT or (scope, login_hint) " +
                                    "are required.");
                }

                // Validate that the client has CIBA grant type enabled.
                validateCibaGrantType(oAuthClientAuthnContext.getClientId(), tenantDomain);
                
                // Validate binding_message.
                if (params.containsKey(CibaConstants.BINDING_MESSAGE)) {
                    validateBindingMessage(params.get(CibaConstants.BINDING_MESSAGE));
                }

                // Validate requested_expiry.
                if (params.containsKey(CibaConstants.REQUESTED_EXPIRY)) {
                    validateRequestedExpiry(params.get(CibaConstants.REQUESTED_EXPIRY));
                }

                // Validate notification_channel.
                if (params.containsKey(CibaConstants.NOTIFICATION_CHANNEL)) {
                    validateNotificationChannel(params.get(CibaConstants.NOTIFICATION_CHANNEL),
                            oAuthClientAuthnContext.getClientId(), tenantDomain);
                }

                // Build CibaAuthCodeRequest from individual parameters
                cibaAuthCodeRequest = getCibaAuthCodeRequestFromParams(params, oAuthClientAuthnContext.getClientId());
            }

            // Obtain Response from service layer of CIBA.
            // The service handles: auth code generation, user resolution, and notification
            cibaAuthCodeResponse = getCibaAuthCodeResponse(cibaAuthCodeRequest);

            // Create and return Ciba Authentication Response.
            return getAuthResponse(response, cibaAuthCodeResponse);

        } catch (CibaAuthFailureException e) {
            // Returning error response.
            return getErrorResponse(e);
        }
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
        } catch (CibaClientException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, e.getMessage(), e);
        } catch (CibaCoreException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Internal server error occurred.", e);
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
     * Check if required parameters are present for parameter-based request.
     *
     * @param params Request parameters map
     * @return true if required parameters are present
     */
    private boolean containsRequiredParameters(Map<String, String> params) {
        return params.containsKey(Constants.SCOPE) && params.containsKey(Constants.LOGIN_HINT);
    }

    /**
     * Transform MultivaluedMap to simple Map.
     *
     * @param params MultivaluedMap of request parameters
     * @return Map of parameters
     */
    private Map<String, String> transformParams(MultivaluedMap<String, String> params) {
        Map<String, String> parameters = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : params.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (values != null && !values.isEmpty()) {
                parameters.put(key, values.get(0));
            }
        }
        return parameters;
    }

    /**
     * Build CibaAuthCodeRequest from individual request parameters.
     *
     * @param params   Request parameters
     * @param clientId Authenticated client ID
     * @return CibaAuthCodeRequest
     * @throws CibaAuthFailureException If parameter validation fails
     */
    private CibaAuthCodeRequest getCibaAuthCodeRequestFromParams(Map<String, String> params, String clientId)
            throws CibaAuthFailureException {

        CibaAuthCodeRequest cibaAuthCodeRequest = new CibaAuthCodeRequest();
        cibaAuthCodeRequest.setIssuer(clientId);
        cibaAuthCodeRequest.setUserHint(params.get(Constants.LOGIN_HINT));
        cibaAuthCodeRequest.setScopes(OAuth2Util.buildScopeArray(params.get(Constants.SCOPE)));
        
        if (params.get(CibaConstants.BINDING_MESSAGE) != null) {
            cibaAuthCodeRequest.setBindingMessage(params.get(CibaConstants.BINDING_MESSAGE));
        }
        
        if (params.get(CibaConstants.REQUESTED_EXPIRY) != null) {
            try {
                cibaAuthCodeRequest.setRequestedExpiry(Long.parseLong(params.get(CibaConstants.REQUESTED_EXPIRY)));
            } catch (NumberFormatException e) {
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, 
                        "Invalid value for requested_expiry");
            }
        } else {
            cibaAuthCodeRequest.setRequestedExpiry(0);
        }

        if (params.get(CibaConstants.NOTIFICATION_CHANNEL) != null) {
            cibaAuthCodeRequest.setNotificationChannel(params.get(CibaConstants.NOTIFICATION_CHANNEL));
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

    /**
     * Validates the binding message.
     *
     * @param bindingMessage Binding message
     * @throws CibaAuthFailureException If validation fails
     */
    private void validateBindingMessage(String bindingMessage) throws CibaAuthFailureException {

        if (StringUtils.isBlank(bindingMessage)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request. The request is with invalid value for " +
                        "(binding_message).");
            }
            throw new CibaAuthFailureException(ErrorCodes.INVALID_BINDING_MESSAGE,
                    "Invalid value for (binding_message).");
        }
        // Validate binding message contains only printable characters. Reject control characters and
        // HTML-dangerous characters (< and >) to prevent XSS.
        if (!bindingMessage.matches("^[^<>\\x00-\\x1F\\x7F]+$")) {
            throw new CibaAuthFailureException(ErrorCodes.INVALID_BINDING_MESSAGE,
                    "Invalid characters present in (binding_message).");
        }
    }

    /**
     * Validates the requested expiry.
     *
     * @param requestedExpiry Requested expiry
     * @throws CibaAuthFailureException If validation fails
     */
    private void validateRequestedExpiry(String requestedExpiry) throws CibaAuthFailureException {

        if (StringUtils.isBlank(requestedExpiry)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request. The request is with invalid value for" +
                        " (requested_expiry).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Invalid value for (requested_expiry).");
        }
        try {
            long expiry = Long.parseLong(requestedExpiry);
            if (expiry <= 0) {
                 throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Invalid value for (requested_expiry). Must be greater than 0.");
            }
        } catch (NumberFormatException e) {
             throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Invalid value for (requested_expiry).");
        }
    }

    /**
     * Validates the notification channel.
     *
     * @param notificationChannel Notification channel.
     * @param clientId Client ID.
     * @param tenantDomain Tenant domain.
     * @throws CibaAuthFailureException If validation fails.
     */
    private void validateNotificationChannel(String notificationChannel, String clientId, String tenantDomain)
            throws CibaAuthFailureException {

        if (StringUtils.isBlank(notificationChannel)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request. The request is with invalid value for " +
                        "(notification_channel).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Invalid value for (notification_channel).");
        }

        CibaNotificationChannelValidator.validateChannelForClient(
                notificationChannel, clientId, tenantDomain);
    }

    /**
     * Validates that the client has the CIBA grant type configured.
     *
     * @param clientId     Client ID.
     * @param tenantDomain Tenant domain.
     * @throws CibaAuthFailureException If the client does not have CIBA grant type enabled.
     */
    private void validateCibaGrantType(String clientId, String tenantDomain) throws CibaAuthFailureException {

        OAuthAppDO appDO;
        try {
            appDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
        } catch (InvalidOAuthClientException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Unknown client: " + clientId);
        } catch (IdentityOAuth2Exception e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error validating grant type for client.", e);
        }

        String grantTypes = appDO.getGrantTypes();
        if (StringUtils.isBlank(grantTypes) || !grantTypes.contains(CibaConstants.OAUTH_CIBA_GRANT_TYPE)) {
            if (log.isDebugEnabled()) {
                log.debug("Client: " + clientId + " has not configured grant_type: " +
                        CibaConstants.OAUTH_CIBA_GRANT_TYPE);
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    "Client has not configured grant_type properly.");
        }
    }
}
