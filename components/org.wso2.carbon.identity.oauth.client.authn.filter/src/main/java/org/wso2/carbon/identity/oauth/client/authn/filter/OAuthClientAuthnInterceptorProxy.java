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

package org.wso2.carbon.identity.oauth.client.authn.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.impl.MetadataMap;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JAX-RS interceptor which intercepts requests. This interceptor will act as a proxy for OAuth2 Client Authenticators.
 * This will pick correct authenticator which can handle OAuth client authentication and engage it.
 */
public class OAuthClientAuthnInterceptorProxy extends AbstractPhaseInterceptor<Message> {

    protected Log log = LogFactory.getLog(OAuthClientAuthnInterceptorProxy.class);
    private static String HTTP_REQUEST = "HTTP.REQUEST";

    public OAuthClientAuthnInterceptorProxy() {
        // Since the body is consumed and body parameters are available at this phase we use "PRE_INVOKE"
        super(Phase.PRE_INVOKE);
    }

    /**
     * Handles the incoming JAX-RS message.
     *
     * @param message JAX-RS message
     */
    @Override
    public void handleMessage(Message message) {

        HttpServletRequest request = ((HttpServletRequest) message.get(HTTP_REQUEST));
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();

        executeClientAuthenticators(message, oAuthClientAuthnContext);
        failOnMultipleAuthenticators(oAuthClientAuthnContext);
        setContextToRequest(request, oAuthClientAuthnContext);
    }

    /**
     * Retrieve body content as a String, List map.
     *
     * @param message JAX-RS incoming message
     * @return Body parameter of the incoming request message
     */
    protected Map<String, List> getContentParams(Message message) {
        Map<String, List> contentMap = new HashMap<>();
        List contentList = message.getContent(List.class);
        contentList.forEach(item -> {
            if (item instanceof MetadataMap) {
                MetadataMap metadataMap = (MetadataMap) item;
                metadataMap.forEach((key, value) -> {
                    if (key instanceof String && value instanceof List) {
                        contentMap.put((String) key, (List) value);
                    }
                });
            }
        });
        return contentMap;
    }

    /**
     * Execute an OAuth client authenticator.
     * @param oAuthClientAuthenticator OAuth client authenticator.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @param request HttpServletReqeust which is the incoming request.
     * @param bodyContentMap Body content as a parameter map.
     */
    protected void executeAuthenticator(OAuthClientAuthenticator oAuthClientAuthenticator, OAuthClientAuthnContext
            oAuthClientAuthnContext, HttpServletRequest request, Map<String, List> bodyContentMap) {

        if (isAuthenticatorDisabled(oAuthClientAuthenticator)) {
            if (log.isDebugEnabled()) {
                log.debug("Authenticator " + oAuthClientAuthenticator.getName() + " is disabled. Hence not " +
                        "evaluating");
            }
            return;
        }

        try {
            if (canAuthenticate(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap)) {

                // If multiple authenticators are engaged, there is no point in evaluating them.
                if (foundPreviouslyExecutedAuthenticators(oAuthClientAuthnContext)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Previously an authenticator is evaluated. Hence authenticator " +
                                oAuthClientAuthenticator.getName() + " is not evaluating");
                    }
                    return;
                }
                addAuthenticatorToContext(oAuthClientAuthenticator, oAuthClientAuthnContext);
                authenticateClient(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap);
            }
        } catch (OAuthClientAuthnException e) {
            handleClientAuthnException(oAuthClientAuthenticator, oAuthClientAuthnContext, e);
        }
    }

    /**
     * Fails authentication if multiple authenticators are eligible of handling the request.
     * @param oAuthClientAuthnContext
     */
    protected void failOnMultipleAuthenticators(OAuthClientAuthnContext oAuthClientAuthnContext) {
        if (oAuthClientAuthnContext.getExecutedAuthenticators().size() > 1) {

            if (log.isDebugEnabled()) {
                log.debug(oAuthClientAuthnContext.getExecutedAuthenticators().size() + " Authenticators were " +
                        "executed. Hence failing client authentication");
            }
            setErrorToContext(OAuth2ErrorCodes.INVALID_REQUEST, "The client MUST NOT use more than one " +
                    "authentication method in each", oAuthClientAuthnContext);
        }
    }

    private void setContextToRequest(HttpServletRequest request, OAuthClientAuthnContext oAuthClientAuthnContext) {
        if (log.isDebugEnabled()) {
            log.debug("Setting OAuth client authentication context to request");
        }

        request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT,
                oAuthClientAuthnContext);
    }

    private void executeClientAuthenticators(Message message, OAuthClientAuthnContext oAuthClientAuthnContext) {

        HttpServletRequest request = ((HttpServletRequest) message.get(HTTP_REQUEST));
        OAuthClientAuthnService oAuthClientAuthnService = (OAuthClientAuthnService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuthClientAuthnService.class, null);

        Map<String, List> bodyContentMap = getContentParams(message);
        if (log.isDebugEnabled()) {
            log.debug("Retriving registered OAuth client authenticator list.");
        }

        oAuthClientAuthnService.getClientAuthenticators().forEach(oAuthClientAuthenticator -> {
            executeAuthenticator(oAuthClientAuthenticator, oAuthClientAuthnContext, request, bodyContentMap);
        });
    }

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

    private boolean isAuthenticatorDisabled(OAuthClientAuthenticator oAuthClientAuthenticator) {
        return !oAuthClientAuthenticator.isEnabled();
    }

    private void handleClientAuthnException(OAuthClientAuthenticator oAuthClientAuthenticator, OAuthClientAuthnContext
            oAuthClientAuthnContext, OAuthClientAuthnException e) {

        if (log.isDebugEnabled()) {
            log.debug("Error while evaluating client authenticator : " + oAuthClientAuthenticator.getName(),
                    e);
        }
        setErrorToContext(e.getErrorCode(), e.getMessage(), oAuthClientAuthnContext);
    }

    private void authenticateClient(OAuthClientAuthenticator oAuthClientAuthenticator,
                                    OAuthClientAuthnContext oAuthClientAuthnContext, HttpServletRequest request,
                                    Map<String, List> bodyContentMap) throws OAuthClientAuthnException {

        oAuthClientAuthnContext.setClientId(oAuthClientAuthenticator.getClientId(request, bodyContentMap,
                oAuthClientAuthnContext));

        boolean isAuthenticated = oAuthClientAuthenticator.authenticateClient(request, bodyContentMap,
                oAuthClientAuthnContext);

        if (log.isDebugEnabled()) {
            log.debug("Authentication result from OAuth client authenticator is : " + isAuthenticated);
        }

        oAuthClientAuthnContext.setAuthenticated(isAuthenticated);
        if (!isAuthenticated) {
            setErrorToContext(OAuth2ErrorCodes.INVALID_CLIENT, "Client credentials are invalid.",
                    oAuthClientAuthnContext);
        }
    }

    private boolean foundPreviouslyExecutedAuthenticators(OAuthClientAuthnContext oAuthClientAuthnContext) {
        return oAuthClientAuthnContext.getExecutedAuthenticators().size() > 0;
    }

    private void addAuthenticatorToContext(OAuthClientAuthenticator oAuthClientAuthenticator, OAuthClientAuthnContext
            oAuthClientAuthnContext) {

        if (log.isDebugEnabled()) {
            log.debug("Authenticator " + oAuthClientAuthenticator.getName() + " can authenticate the " +
                    "client request.  Hence trying to evaluate authentication");
        }

        oAuthClientAuthnContext.addAuthenticator(oAuthClientAuthenticator.getName());
    }

    private boolean canAuthenticate(OAuthClientAuthenticator oAuthClientAuthenticator,
                                    OAuthClientAuthnContext oAuthClientAuthnContext,
                                    HttpServletRequest request, Map<String, List> bodyContentMap) {
        if (log.isDebugEnabled()) {
            log.debug("Evaluating canAuthenticate of authenticator : " + oAuthClientAuthenticator.getName());
        }
        return oAuthClientAuthenticator.canAuthenticate(request, bodyContentMap, oAuthClientAuthnContext);
    }
}
