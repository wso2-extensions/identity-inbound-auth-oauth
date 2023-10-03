/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.client.authentication;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

/**
 * OAuth Client Authentication Service which will be registered as an OSGI service
 */
public class OAuthClientAuthnService {

    private static final Log log = LogFactory.getLog(OAuthClientAuthnService.class);
    private static final String FAPI_CLIENT_AUTH_METHOD_CONFIGURATION = "OAuth.OpenIDConnect.FAPI." +
            "AllowedClientAuthenticationMethods.AllowedClientAuthenticationMethod";

    /**
     * Retrieve OAuth2 client authenticators which are reigstered dynamically.
     *
     * @return List of OAuth2 client authenticators.
     */
    public List<OAuthClientAuthenticator> getClientAuthenticators() {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving registered OAuth client authenticator list.");
        }
        return OAuth2ServiceComponentHolder.getAuthenticationHandlers();
    }

    /**
     * Authenticate the OAuth client for an incoming request.
     *
     * @param request           Incoming HttpServletReqeust
     * @param bodyContentParams Content of the body of the request as parameter map.
     * @return OAuth Client Authentication context which contains information about the results of client
     * authentication.
     */
    public OAuthClientAuthnContext authenticateClient(HttpServletRequest request, Map<String, List> bodyContentParams) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        executeClientAuthenticators(request, oAuthClientAuthnContext, bodyContentParams);
        failOnMultipleAuthenticators(oAuthClientAuthnContext);
        return oAuthClientAuthnContext;
    }

    /**
     * Execute an OAuth client authenticator.
     *
     * @param oAuthClientAuthenticator OAuth client authenticator.
     * @param oAuthClientAuthnContext  OAuth client authentication context.
     * @param request                  HttpServletReqeust which is the incoming request.
     * @param bodyContentMap           Body content as a parameter map.
     */
    private void executeAuthenticator(OAuthClientAuthenticator oAuthClientAuthenticator, OAuthClientAuthnContext
            oAuthClientAuthnContext, HttpServletRequest request, Map<String, List> bodyContentMap) {

        if (isAuthenticatorDisabled(oAuthClientAuthenticator)) {
            if (log.isDebugEnabled()) {
                log.debug("Authenticator " + oAuthClientAuthenticator.getName() + " is disabled. Hence not " +
                        "evaluating");
            }
            return;
        }

        if (canAuthenticate(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap)) {

            if (log.isDebugEnabled()) {
                log.debug(oAuthClientAuthenticator.getName() + " authenticator can handle incoming request.");
            }
            // If multiple authenticators are engaged, there is no point in evaluating them.
            if (oAuthClientAuthnContext.isPreviousAuthenticatorEngaged()) {
                if (log.isDebugEnabled()) {
                    log.debug("Previously an authenticator is evaluated. Hence authenticator " +
                            oAuthClientAuthenticator.getName() + " is not evaluating");
                }
                addAuthenticatorToContext(oAuthClientAuthenticator, oAuthClientAuthnContext);
                return;
            }
            addAuthenticatorToContext(oAuthClientAuthenticator, oAuthClientAuthnContext);
            try {
                // Client ID should be retrieved first since it's a must to have. If it fails authentication fails.
                oAuthClientAuthnContext.setClientId(oAuthClientAuthenticator.getClientId(request, bodyContentMap,
                        oAuthClientAuthnContext));
                authenticateClient(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap);
            } catch (OAuthClientAuthnException e) {
                handleClientAuthnException(oAuthClientAuthenticator, oAuthClientAuthnContext, e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(oAuthClientAuthenticator.getName() + " authenticator cannot handle this request.");
            }
        }
    }

    /**
     * Fails authentication if multiple authenticators are eligible of handling the request.
     *
     * @param oAuthClientAuthnContext OAuth client authentication context.
     */
    private void failOnMultipleAuthenticators(OAuthClientAuthnContext oAuthClientAuthnContext) {

        if (oAuthClientAuthnContext.isMultipleAuthenticatorsEngaged()) {

            if (log.isDebugEnabled()) {
                log.debug(oAuthClientAuthnContext.getExecutedAuthenticators().size() + " Authenticators were " +
                        "executed previously. Hence failing client authentication");
            }
            setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "The client MUST NOT use more than one " +
                    "authentication method in each", oAuthClientAuthnContext);
        }
    }

    /**
     * Executes registered client authenticators.
     *
     * @param request                 Incoming HttpServletRequest
     * @param oAuthClientAuthnContext OAuth client authentication context.
     */
    private void executeClientAuthenticators(HttpServletRequest request, OAuthClientAuthnContext
            oAuthClientAuthnContext, Map<String, List> bodyContentMap) {

        if (log.isDebugEnabled()) {
            log.debug("Executing OAuth client authenticators.");
        }
        try {
            String clientId = extractClientId(request, bodyContentMap);
            if (StringUtils.isNotBlank(clientId)) {
                if (OAuth2Util.isFapiConformantApp(clientId)) {
                    List<OAuthClientAuthenticator> authenticatorsForFAPIApp = getAuthenticatorsForFAPI(clientId);
                    if (authenticatorsForFAPIApp.isEmpty()) {
                        setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "No valid authenticators found for " +
                                "the application.", oAuthClientAuthnContext);
                    } else {
                        authenticatorsForFAPIApp.forEach(oAuthClientAuthenticator -> {
                            executeAuthenticator(oAuthClientAuthenticator, oAuthClientAuthnContext, request,
                                    bodyContentMap);
                        });
                    }
                    return;
                }
            } else {
                setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Client ID not found in the request.",
                        oAuthClientAuthnContext);
            }
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while processing the request to validate the client authentication method.");
            }
            setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Error occurred while validating the " +
                    "request auth method with the configured token endpoint auth methods.", oAuthClientAuthnContext);
        }
        this.getClientAuthenticators().forEach(oAuthClientAuthenticator -> {
            executeAuthenticator(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap);
        });
    }

    /**
     * Sets error messages to context after failing authentication.
     *
     * @param errorCode               Error code.
     * @param errorMessage            Error message.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     */
    private void setErrorToContext(String errorCode, String errorMessage, OAuthClientAuthnContext
            oAuthClientAuthnContext) {

        if (log.isDebugEnabled()) {
            log.debug("Setting error to client authentication context : Error code : " + errorCode + ", Error " +
                    "message : " + errorMessage);
        }
        oAuthClientAuthnContext.setAuthenticated(false);
        oAuthClientAuthnContext.setErrorCode(errorCode);
        oAuthClientAuthnContext.setErrorMessage(errorMessage);
    }

    /**
     * Checks whether the authenticaion is enabled or disabled.
     *
     * @param oAuthClientAuthenticator OAuth client authentication context
     * @return Whether the client authenticator is enabled or disabled.
     */
    private boolean isAuthenticatorDisabled(OAuthClientAuthenticator oAuthClientAuthenticator) {

        return !oAuthClientAuthenticator.isEnabled();
    }

    /**
     * @param oAuthClientAuthenticator OAuth client Authenticator.
     * @param oAuthClientAuthnContext  OAuth client authentication context.
     * @param e                        OAuthClientAuthnException.
     */
    private void handleClientAuthnException(OAuthClientAuthenticator oAuthClientAuthenticator, OAuthClientAuthnContext
            oAuthClientAuthnContext, OAuthClientAuthnException e) {

        if (log.isDebugEnabled()) {
            log.debug("Error while evaluating client authenticator : " + oAuthClientAuthenticator.getName(),
                    e);
        }
        setErrorToContext(e.getErrorCode(), e.getMessage(), oAuthClientAuthnContext);
    }

    /**
     * Authenticate an OAuth client using a given client authenticator.
     *
     * @param oAuthClientAuthenticator OAuth client authenticator.
     * @param oAuthClientAuthnContext  OAuth client authentication context.
     * @param request                  Incoming HttpServletRequest.
     * @param bodyContentMap           Content of the body as a parameter map.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    private void authenticateClient(OAuthClientAuthenticator oAuthClientAuthenticator,
                                    OAuthClientAuthnContext oAuthClientAuthnContext, HttpServletRequest request,
                                    Map<String, List> bodyContentMap) throws OAuthClientAuthnException {

        boolean isAuthenticated = oAuthClientAuthenticator.authenticateClient(request, bodyContentMap,
                oAuthClientAuthnContext);

        if (log.isDebugEnabled()) {
            log.debug("Authentication result from OAuth client authenticator " + oAuthClientAuthenticator.getName()
                    + " is : " + isAuthenticated);
        }
        oAuthClientAuthnContext.setAuthenticated(isAuthenticated);
        if (!isAuthenticated) {
            setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Client credentials are invalid.",
                    oAuthClientAuthnContext);
        }
    }

    /**
     * Adds the authenticator name to the OAuth client authentication context.
     *
     * @param oAuthClientAuthenticator OAuth client authenticator.
     * @param oAuthClientAuthnContext  OAuth client authentication context.
     */
    private void addAuthenticatorToContext(OAuthClientAuthenticator oAuthClientAuthenticator, OAuthClientAuthnContext
            oAuthClientAuthnContext) {

        if (log.isDebugEnabled()) {
            log.debug("Authenticator " + oAuthClientAuthenticator.getName() + " can authenticate the " +
                    "client request.  Hence trying to evaluate authentication");
        }

        oAuthClientAuthnContext.addAuthenticator(oAuthClientAuthenticator.getName());
    }

    /**
     * Returns whether an OAuth client authenticator can authenticate a given request or not.
     *
     * @param oAuthClientAuthenticator OAuth client authenticator.
     * @param oAuthClientAuthnContext  OAuth client authentication context.
     * @param request                  Incoming HttpServletRequest.
     * @param bodyContentMap           Body content of the reqeust as a parameter map.
     * @return Whether the authenticator can authenticate the incoming request or not.
     */
    private boolean canAuthenticate(OAuthClientAuthenticator oAuthClientAuthenticator,
                                    OAuthClientAuthnContext oAuthClientAuthnContext,
                                    HttpServletRequest request, Map<String, List> bodyContentMap) {

        if (log.isDebugEnabled()) {
            log.debug("Evaluating canAuthenticate of authenticator : " + oAuthClientAuthenticator.getName());
        }

        return oAuthClientAuthenticator.canAuthenticate(request, bodyContentMap, oAuthClientAuthnContext);
    }

    /**
     * Obtain the client authentication method configured for the application.
     *
     * @param clientId     Client ID of the application.
     * @return Configured client authentication method for the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    public List<String> getConfiguredClientAuthMethods(String clientId) throws OAuthClientAuthnException {

        try {
            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
            ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
            for (ServiceProviderProperty serviceProviderProperty : serviceProviderProperties) {
                if (OAuthConstants.TOKEN_ENDPOINT_AUTH_METHOD.equals(serviceProviderProperty.getName())) {
                    return Arrays.asList(serviceProviderProperty.getValue());
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException("Error occurred while retrieving the service provider.",
                    OAuth2ErrorCodes.INVALID_REQUEST, e);
        }

        return IdentityUtil.getPropertyAsList(FAPI_CLIENT_AUTH_METHOD_CONFIGURATION);
    }

    /**
     * Obtain the client ID of the application from the request.
     *
     * @param request       Http servlet request.
     * @return Client ID of the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    private String extractClientId(HttpServletRequest request, Map<String, List> contentParams)
            throws OAuthClientAuthnException {

        /* This method was required to obtain the Client ID of the application before the authenticators are triggered
           in order to determine the set of authenticators which should be triggered for FAPI applications.
           Therefore the different methods in which the Client ID could exist in the request is being tested here. */
        try {
            Optional<List> signedObject =
                    Optional.ofNullable(contentParams.get(OAuthConstants.OAUTH_JWT_ASSERTION));
            Optional<List> clientIdInRequestBody =
                    Optional.ofNullable(contentParams.get(OAuth.OAUTH_CLIENT_ID));
            //   Obtain client ID from the JWT in the request.
            if (signedObject.isPresent()) {
                return getClientIdFromJWT((String) signedObject.get().get(0));
            //   Obtain client ID from the request body.
            } else if (clientIdInRequestBody.isPresent()) {
                return (String) clientIdInRequestBody.get().get(0);
            //   Obtain client ID from the authorization header when basic authentication is used.
            } else if (request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ) != null) {
                return getClientIdFromBasicAuth(request);
            } else {
                throw new OAuthClientAuthnException("Unable to find client id in the request.",
                        OAuth2ErrorCodes.INVALID_CLIENT);
            }
        } catch (ParseException e) {
            throw new OAuthClientAuthnException("Error occurred while parsing the signed assertion.",
                    OAuth2ErrorCodes.INVALID_REQUEST, e);
        }
    }

    /**
     * Obtain the client ID of the application from the JWT in the request.
     *
     * @param signedObject       Client assertion sent in the request.
     * @return Client ID of the application.
     * @throws ParseException An exception is thrown when the signed JWT cannot be processed.
     */
    private String getClientIdFromJWT(String signedObject) throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(signedObject);
        return signedJWT.getJWTClaimsSet().getIssuer();
    }

    /**
     * Obtain the client ID of the application from the authorization header of the request.
     *
     * @param request       Http servlet request.
     * @return Client ID of the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    private String getClientIdFromBasicAuth(HttpServletRequest request) throws OAuthClientAuthnException {

        String basicAuthErrorMessage = "Unable to find client id in the request. Invalid Authorization header found.";
        String authorizationHeader = request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);
        if (authorizationHeader.split(" ").length == 2) {
            if (authorizationHeader.split(" ")[0].equals(OAuthConstants.HTTP_REQ_HEADER_AUTH_METHOD_BASIC)) {
                String authToken = authorizationHeader.split(" ")[1];
                byte[] decodedBytes = Base64.getUrlDecoder().decode(authToken.getBytes(StandardCharsets.UTF_8));
                String decodedAuthToken = new String(decodedBytes, StandardCharsets.UTF_8);
                if (decodedAuthToken.split(":").length == 2) {
                    return decodedAuthToken.split(":")[0];
                }
            }
        }
        throw new OAuthClientAuthnException(basicAuthErrorMessage, OAuth2ErrorCodes.INVALID_CLIENT);
    }

    /**
     * Map the configured client authentication methods with the client authenticators.
     *
     * @param authMethods     The list of configured client authentication methods for the application.
     * @return The list of client authenticator names which are allowed for the application.
     */
    private List<String> mapAuthenticatorForClientAuthMethod(List<String> authMethods) {

        /* This mapping cannot be avoided as we need to reference the authenticator based on the auth method configured.
        Therefore if a new authenticator is added for FAPI, the relevant mapping should also be updated accordingly. */
        List<String> authenticatorList = new ArrayList<>();
        for (String authMethod : authMethods) {
            if (authMethod.equals(OAuthConstants.PRIVATE_KEY_JWT)) {
                authenticatorList.add(OAuthConstants.PRIVATE_KEY_JWT_AUTHENTICATOR);
            } else if (authMethod.equals(OAuthConstants.TLS_CLIENT_AUTH)) {
                authenticatorList.add(OAuthConstants.TLS_CLIENT_AUTHENTICATOR);
            } else {
                authenticatorList.add(authMethod);
            }
        }
        return authenticatorList;
    }

    /**
     * Obtain the list of client authenticators which should be triggered for the FAPI application.
     *
     * @param clientId     Client ID of the application.
     * @return The list of allowed client authenticators for the FAPI application.
     */
    private List<OAuthClientAuthenticator> getAuthenticatorsForFAPI(String clientId) throws OAuthClientAuthnException {

        //  Obtain the list of available client authenticators.
        List<OAuthClientAuthenticator> availableClientAuthenticators = this.getClientAuthenticators();
        //  Obtain the list of client authentication methods configured for the application.
        List<String> configuredClientAuthMethods = getConfiguredClientAuthMethods(clientId);
        //  Map the configured client authentication methods to the client authenticators.
        List<String> configuredAuthenticators = mapAuthenticatorForClientAuthMethod(configuredClientAuthMethods);
        //  Obtain the list of authenticators which should be triggered for the application.
        List<OAuthClientAuthenticator> updatedAuthenticators = new ArrayList<>();
        for (OAuthClientAuthenticator authenticator : availableClientAuthenticators) {
            if (configuredAuthenticators.contains(authenticator.getName())) {
                updatedAuthenticators.add(authenticator);
            }
        }
        return updatedAuthenticators;
    }
}
