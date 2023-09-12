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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.ParseException;
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
        try {
            String clientId = extractClientId(request, bodyContentParams);
            if (!StringUtils.isBlank(clientId) && OAuth2Util.isFapiConformantApp(clientId)) {
                if (!isMTLSEnforced(request)) {
                    setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "Transport certificate not passed " +
                            "through the request or the certificate is not valid", oAuthClientAuthnContext);
                    return oAuthClientAuthnContext;
                }
                if (!isRegisteredClientAuthMethod(request, bodyContentParams)) {
                    setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "Request does not follow the " +
                            "registered token endpoint auth method", oAuthClientAuthnContext);
                    return oAuthClientAuthnContext;
                }
            }
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while processing the request to validate the client authentication method");
            }
            setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "Error occurred while validating the " +
                    "request auth method with the registered token endpoint auth method", oAuthClientAuthnContext);
            return oAuthClientAuthnContext;
        }
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
     * Validate whether the client authentication method of the request is registered for the application.
     *
     * @param request                Http servlet request.
     * @param contentParams          Map of request body params.
     * @return Whether the client authentication method of the request is registered for the application.
     * @throws OAuthClientAuthnException
     */
    private boolean isRegisteredClientAuthMethod(HttpServletRequest request, Map<String, List> contentParams)
            throws OAuthClientAuthnException {

        String registeredClientAuthMethod = retrieveRegisteredAuthMethod(extractClientId(request, contentParams));

        if (registeredClientAuthMethod.equals(OAuthConstants.NOT_APPLICABLE)) {
            return false;
        }

        // There can be multiple registered client auth methods
        if (!(registeredClientAuthMethod.contains(retrieveRequestAuthMethod(request, contentParams)))) {
            throw new OAuthClientAuthnException("Request does not follow the registered token endpoint auth " +
                    "method", OAuth2ErrorCodes.INVALID_REQUEST);
        } else {
            return true;
        }
    }

    /**
     * Obtain the client authentication method of the request.
     *
     * @param request                Http servlet request.
     * @param contentParams          Map of request body params.
     * @return Client authentication method of the request.
     * @throws OAuthClientAuthnException
     */
    public String retrieveRequestAuthMethod(HttpServletRequest request, Map<String, List> contentParams) throws
            OAuthClientAuthnException {

        try {
            if (isPrivateKeyJWTAuthentication(request)) {
                log.debug("Validating request with JWT client authentication method");
                return OAuthConstants.PRIVATE_KEY_JWT;
            } else if (isMTLSAuthentication(request, contentParams)) {
                log.debug("Validating request with MTLS client authentication method");
                return OAuthConstants.TLS_CLIENT_AUTH;
            }
            return "INVALID_AUTH";
        } catch (OAuthClientAuthnException e) {
            throw new OAuthClientAuthnException("Error occurred when obtaining request authentication method",
                    OAuth2ErrorCodes.INVALID_REQUEST, e);
        }
    }

    /**
     * Obtain the client authentication method registered for the application.
     *
     * @param clientId     Client ID of the application.
     * @return Registered client authentication method for the application.
     * @throws OAuthClientAuthnException
     */
    public String retrieveRegisteredAuthMethod(String clientId) throws OAuthClientAuthnException {

        try {
            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
            if (StringUtils.isEmpty(serviceProvider.getCertificateContent())) {
                ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
                for (ServiceProviderProperty serviceProviderProperty : serviceProviderProperties) {
                    if (OAuthConstants.TOKEN_ENDPOINT_AUTH_METHOD.equals(serviceProviderProperty.getName())) {
                        return serviceProviderProperty.getValue();
                    }
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException("Token signing algorithm not registered",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return OAuthConstants.NOT_APPLICABLE;
    }

    /**
     * Obtain the client ID of the application from the request.
     *
     * @param request       Http servlet request.
     * @return Client ID of the application.
     * @throws OAuthClientAuthnException
     */
    private String extractClientId(HttpServletRequest request, Map<String, List> contentParams)
            throws OAuthClientAuthnException {

        String basicAuthErrorMessage = "Unable to find client id in the request. Invalid Authorization header found.";
        String authHeader = "Authorization";

        try {
            Optional<String> signedObject =
                    Optional.ofNullable(request.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION));
            Optional<String> clientIdAsReqParam =
                    Optional.ofNullable(request.getParameter(OAuth.OAUTH_CLIENT_ID));
            Optional<List> clientIdInContentParamList =
                    Optional.ofNullable(contentParams.get(OAuth.OAUTH_CLIENT_ID));
            //   Obtain client ID from the JWT in the request
            if (signedObject.isPresent()) {
                SignedJWT signedJWT = SignedJWT.parse(signedObject.get());
                return signedJWT.getJWTClaimsSet().getIssuer();
            //   Obtain client ID from request parameters
            } else if (clientIdAsReqParam.isPresent()) {
                return clientIdAsReqParam.get();
            //   Obtain client ID from the request body
            } else if (clientIdInContentParamList.isPresent()) {
                return (String) clientIdInContentParamList.get().get(0);
            //   Obtain client ID from the authorization header when basic authentication is used
            } else if (request.getHeader(authHeader) != null) {
                String authorizationHeader = request.getHeader(authHeader);
                if (authorizationHeader.split(" ").length == 2) {
                    if (request.getHeader(authHeader).split(" ")[0].equals("Basic")) {
                        String authToken = request.getHeader(authHeader).split(" ")[1];
                        byte[] decodedBytes = Base64.getUrlDecoder().decode(authToken.getBytes(StandardCharsets.UTF_8));
                        String decodedAuthToken = new String(decodedBytes, StandardCharsets.UTF_8);
                        if (decodedAuthToken.split(":").length == 2) {
                            return decodedAuthToken.split(":")[0];
                        } else {
                            throw new OAuthClientAuthnException(basicAuthErrorMessage, OAuth2ErrorCodes.INVALID_CLIENT);
                        }
                    } else {
                        return null;
                    }
                } else {
                    throw new OAuthClientAuthnException(basicAuthErrorMessage, OAuth2ErrorCodes.INVALID_CLIENT);
                }
            } else {
                throw new OAuthClientAuthnException("Unable to find client id in the request",
                        OAuth2ErrorCodes.INVALID_CLIENT);
            }
        } catch (ParseException e) {
            throw new OAuthClientAuthnException("Error occurred while parsing the signed assertion",
                    OAuth2ErrorCodes.INVALID_REQUEST, e);
        }
    }

    /**
     * Validate whether the request follows MTLS client authentication.
     *
     * @param request               Http servlet request.
     * @param contentParam          Map of request body params.
     * @return Whether the request follows MTLS client authentication.
     * @throws OAuthClientAuthnException
     */
    private boolean isMTLSAuthentication(HttpServletRequest request, Map<String, List> contentParam)
            throws OAuthClientAuthnException {

        String certificate = Optional.ofNullable(IdentityUtil.getProperty(OAuthConstants.MTLS_AUTH_HEADER))
                .orElse("CONFIG_NOT_FOUND");

        String oauthClientID =  request.getParameter(OAuth.OAUTH_CLIENT_ID);
        if (StringUtils.isBlank(OAuth.OAUTH_CLIENT_ID)) {
            oauthClientID = (String) contentParam.get(OAuth.OAUTH_CLIENT_ID).get(0);
        }
        try {
            String oauthClientSecretValue = request.getParameter(OAuth.OAUTH_CLIENT_SECRET);
            String oauthJWTAssertion = request.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION);
            String oauthJWTAssertionType = request.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION_TYPE);
            String authorizationHeaderValue = request.getHeader(OAuthConstants.AUTHORIZATION_HEADER);
            String x509Certificate = request.getHeader(certificate);
            if (StringUtils.isEmpty(x509Certificate)) {
                x509Certificate = IdentityUtil.convertCertificateToPEM((Certificate) request
                        .getAttribute(certificate));
            }
            return (StringUtils.isNotEmpty(oauthClientID) && StringUtils.isEmpty(oauthClientSecretValue) &&
                    StringUtils.isEmpty(oauthJWTAssertion) && StringUtils.isEmpty(oauthJWTAssertionType) &&
                    StringUtils.isEmpty(authorizationHeaderValue) && x509Certificate != null &&
                    OAuth2Util.parseCertificate(x509Certificate) != null);
        } catch (CertificateException e) {
            throw new OAuthClientAuthnException("Error occurred while parsing the certificate",
                    OAuth2ErrorCodes.INVALID_REQUEST, e);
        }
    }

    /**
     * Validate whether the request follows Private Key JWT client authentication.
     *
     * @param request       Http servlet request.
     * @return Whether the request follows Private Key JWT client authentication.
     */
    public boolean isPrivateKeyJWTAuthentication(HttpServletRequest request) {

        String oauthJWTAssertionType = request.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION_TYPE);
        String oauthJWTAssertion = request.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION);
        return OAuthConstants.OAUTH_JWT_BEARER_GRANT_TYPE.equals(oauthJWTAssertionType) &&
                StringUtils.isNotEmpty(oauthJWTAssertion);
    }

    /**
     * Validate whether a TLS certificate is passed through the request.
     *
     * @param request     Http servlet request.
     * @return Whether a TLS certificate is passed through the request.
     * @throws OAuthClientAuthnException
     */
    private boolean isMTLSEnforced(HttpServletRequest request) throws OAuthClientAuthnException {

        String mtlsAuthHeader = Optional.ofNullable(IdentityUtil.getProperty(OAuthConstants.MTLS_AUTH_HEADER))
                .orElse("CONFIG_NOT_FOUND");
        String x509Certificate = request.getHeader(mtlsAuthHeader);
        try {
            if (!(StringUtils.isNotEmpty(x509Certificate) &&
                    OAuth2Util.parseCertificate(x509Certificate) != null)) {
                log.error("Transport certificate not passed through the request or the certificate is not valid");
                return false;
            }
        } catch (CertificateException e) {
            log.error("Invalid transport certificate.", e);
            return false;
        }
        return true;
    }
}
