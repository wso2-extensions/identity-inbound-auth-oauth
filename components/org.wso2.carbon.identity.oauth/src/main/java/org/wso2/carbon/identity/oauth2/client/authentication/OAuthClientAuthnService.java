/*
 * Copyright (c) 2018-2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
            if (StringUtils.isBlank(clientId)) {
                setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Client ID not found in the request.",
                        oAuthClientAuthnContext);
                return;
            }
            try {
                List<OAuthClientAuthenticator> configuredClientAuthMethods = getConfiguredClientAuthMethods(clientId);
                List<OAuthClientAuthenticator> applicableAuthenticators;
                if (OAuth2Util.isFapiConformantApp(clientId)) {
                    applicableAuthenticators = filterClientAuthenticatorsForFapi(configuredClientAuthMethods);
                } else {
                    if (configuredClientAuthMethods.isEmpty()) {
                        applicableAuthenticators = this.getClientAuthenticators();
                    } else {
                        applicableAuthenticators = configuredClientAuthMethods;
                    }
                }
                if (applicableAuthenticators.isEmpty()) {
                    setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "No valid authenticators found for " +
                            "the application.", oAuthClientAuthnContext);
                    return;
                }
                applicableAuthenticators.forEach(oAuthClientAuthenticator -> {
                    executeAuthenticator(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap);
                });
            } catch (InvalidOAuthClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("A valid OAuth client could not be found for client_id: " + clientId, e);
                }
                setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Client credentials are invalid.",
                        oAuthClientAuthnContext);
            } catch (IdentityOAuth2Exception e) {
                throw new OAuthClientAuthnException("Error while obtaining the service provider for client_id: " +
                        clientId, OAuth2ErrorCodes.SERVER_ERROR);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while processing the request to validate the client authentication method.", e);
            setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Error occurred while validating the " +
                    "request auth method with the configured token endpoint auth methods.", oAuthClientAuthnContext);
        }
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
     * Obtain the client authentication methods configured for the application.
     *
     * @param clientId     Client ID of the application.
     * @return Configured client authentication methods for the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    private List<OAuthClientAuthenticator> getConfiguredClientAuthMethods(String clientId)
            throws OAuthClientAuthnException, InvalidOAuthClientException {

        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        String appOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        /*
         If appOrgId is not empty, then the request comes for an application which is registered directly in the
         organization of the appOrgId. Therefore, we need to resolve the tenant domain of the organization.
        */
        if (StringUtils.isNotEmpty(appOrgId)) {
            try {
                tenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(appOrgId);
            } catch (OrganizationManagementException e) {
                throw new InvalidOAuthClientException("Error while resolving tenant domain for the organization ID: " +
                        appOrgId, e);
            }
        }
        List<String> configuredClientAuthMethods = new ArrayList<>();
        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
            String tokenEndpointAuthMethod = oAuthAppDO.getTokenEndpointAuthMethod();
            if (StringUtils.isNotBlank(tokenEndpointAuthMethod)) {
                configuredClientAuthMethods = Arrays.asList(tokenEndpointAuthMethod);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException("Error occurred while retrieving app information for client id: " +
                    clientId + " of tenantDomain: " + tenantDomain, OAuth2ErrorCodes.INVALID_REQUEST, e);
        }
        if (configuredClientAuthMethods.isEmpty()) {
            return Collections.emptyList();
        } else {
            return getApplicableClientAuthenticators(configuredClientAuthMethods);
        }

    }

    /**
     * Obtain the client ID of the application from the request.
     *
     * @param request                   Http servlet request.
     * @param bodyContentMap            Content of the body of the request as a parameter map.
     * @return Client ID of the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    public String extractClientId(HttpServletRequest request, Map<String, List> bodyContentMap)
            throws OAuthClientAuthnException {

        String clientId = null;
        for (OAuthClientAuthenticator oAuthClientAuthenticator : this.getClientAuthenticators()) {
            try {
                /* As we just need to extract the Client ID here to move forward, we do not want to add any parameters
                   to the original OAuthClientAuthnContext. Therefore a new context is being used every time. */
                OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
                clientId = oAuthClientAuthenticator.getClientId(request, bodyContentMap, oAuthClientAuthnContext);
                if (StringUtils.isNotBlank(clientId)) {
                    break;
                }
            } catch (OAuthClientAuthnException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Client ID cannot be extracted using the " + oAuthClientAuthenticator.getName(), e);
                }
            }
        }
        return clientId;
    }

    /**
     * Obtain the list of client auth methods that could be used to authenticate the request for a FAPI app.
     *
     * @param configuredAuthenticators  List of client authenticators configured for the application.
     * @return   List of applicable client authentication methods for the application.
     */
    private List<OAuthClientAuthenticator> filterClientAuthenticatorsForFapi(
                List<OAuthClientAuthenticator> configuredAuthenticators) {

        List<String> fapiAllowedAuthMethods = IdentityUtil.getPropertyAsList(FAPI_CLIENT_AUTH_METHOD_CONFIGURATION);
        if (configuredAuthenticators.isEmpty()) {
            return getApplicableClientAuthenticators(fapiAllowedAuthMethods);
        }

        List<OAuthClientAuthenticator> filteredAuthenticators = new ArrayList<>();
        for (OAuthClientAuthenticator authenticator : configuredAuthenticators) {
            List<String> supportedClientAuthMethods = new ArrayList<>();
            for (ClientAuthenticationMethodModel authMethod : authenticator.getSupportedClientAuthenticationMethods()) {
                supportedClientAuthMethods.add(authMethod.getName());
            }
            if (fapiAllowedAuthMethods.stream().anyMatch(supportedClientAuthMethods::contains)) {
                filteredAuthenticators.add(authenticator);
            }
        }

        return filteredAuthenticators;
    }

    /**
     * Obtain the list of client auth methods that could be used to authenticate the request for an app.
     *
     * @param configuredAuthenticators  List of client authenticators configured for the application.
     * @return   List of applicable client authentication methods for the application.
     */
    private List<OAuthClientAuthenticator> getApplicableClientAuthenticators(List<String> configuredAuthenticators) {

        List<OAuthClientAuthenticator> applicableClientAuthenticators = new ArrayList<>();
        for (OAuthClientAuthenticator authenticator : this.getClientAuthenticators()) {
            List<String> supportedClientAuthMethods = new ArrayList<>();
            for (ClientAuthenticationMethodModel authMethod : authenticator.getSupportedClientAuthenticationMethods()) {
                supportedClientAuthMethods.add(authMethod.getName());
            }
            if (configuredAuthenticators.stream().anyMatch(supportedClientAuthMethods::contains)) {
                applicableClientAuthenticators.add(authenticator);
            }
        }
        return applicableClientAuthenticators;
    }
}
