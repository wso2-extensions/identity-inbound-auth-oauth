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

        HttpServletRequest request = ((HttpServletRequest) message.get("HTTP.REQUEST"));
        OAuthClientAuthnService oAuthClientAuthnService = (OAuthClientAuthnService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuthClientAuthnService.class, null);
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();

        Map<String, List> contentMap = getContentParams(message);
        if (log.isDebugEnabled()) {
            log.debug("Retriving registered OAuth client authenticator list. " + oAuthClientAuthnService.getClientAuthenticators());
        }

        oAuthClientAuthnService.getClientAuthenticators().forEach(oAuthClientAuthenticator -> {
            try {

                if (log.isDebugEnabled()) {
                    log.debug("Evaluating canAuthenticate of authenticator : " + oAuthClientAuthenticator.getName());
                }

                if (oAuthClientAuthenticator.canAuthenticate(request, contentMap, oAuthClientAuthnContext)) {

                    if (log.isDebugEnabled()) {
                        log.debug("Authenticator " + oAuthClientAuthenticator.getName() + " can authenticate the " +
                                "client request.  Hence evaluating authentication");
                    }

                    oAuthClientAuthnContext.addAuthenticator(oAuthClientAuthenticator.getName());
                    oAuthClientAuthnContext.setClientId(oAuthClientAuthenticator.getClientId(request, contentMap,
                            oAuthClientAuthnContext));
                    boolean isAuthenticated = oAuthClientAuthenticator.authenticateClient(request, contentMap,
                            oAuthClientAuthnContext);

                    if (log.isDebugEnabled()) {
                        log.debug("Authentication result from OAuth client authenticator is : " + isAuthenticated);
                    }

                    if (isAuthenticated) {
                        oAuthClientAuthnContext.setAuthenticated(true);
                    } else {
                        oAuthClientAuthnContext.setAuthenticated(false);
                        oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
                    }
                }
            } catch (OAuthClientAuthnException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while evaluating client authenticator : " + oAuthClientAuthenticator.getName(),
                            e);
                }
                oAuthClientAuthnContext.setAuthenticated(false);
                oAuthClientAuthnContext.setErrorCode(e.getErrorCode());
                oAuthClientAuthnContext.setErrorMessage(e.getMessage());
            }

        });

        if (oAuthClientAuthnContext.isAuthenticated() && oAuthClientAuthnContext.getExecutedAuthenticators().size() >
                1) {

            if (log.isDebugEnabled()) {
                log.debug(oAuthClientAuthnContext.getExecutedAuthenticators().size() + " Authenticators were " +
                        "executed. Hence failing client authentication");
            }
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
            oAuthClientAuthnContext.setErrorMessage("The client MUST NOT use more than one authentication method in " +
                    "each");
        }
        if (log.isDebugEnabled()) {
            log.debug("Setting OAuth client authentication context to request");
        }
        request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT,
                oAuthClientAuthnContext);
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
}
