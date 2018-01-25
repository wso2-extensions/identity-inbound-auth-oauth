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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * OAuth Client Authentication Service which will be registered as an OSGI service
 */
public class OAuthClientAuthnService {

    private Log log = LogFactory.getLog(OAuthClientAuthnService.class);

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
}
