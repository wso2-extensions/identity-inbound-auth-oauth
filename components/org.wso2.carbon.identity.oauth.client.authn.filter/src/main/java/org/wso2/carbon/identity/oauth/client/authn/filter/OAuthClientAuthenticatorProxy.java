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
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JAX-RS interceptor which intercepts requests. This interceptor will act as a proxy for OAuth2 Client Authenticators.
 * This will pick correct authenticator which can handle OAuth client authentication and engage it.
 */
public class OAuthClientAuthenticatorProxy extends AbstractPhaseInterceptor<Message> {

    private Log log = LogFactory.getLog(OAuthClientAuthenticatorProxy.class);
    private static String HTTP_REQUEST = "HTTP.REQUEST";

    public OAuthClientAuthenticatorProxy() {

        // Since the body is consumed and body parameters are available at this phase we use "PRE_INVOKE"
        super(Phase.PRE_INVOKE);
    }

    /**
     * Handles the incoming JAX-RS message for the purpose of OAuth2 client authentication.
     *
     * @param message JAX-RS message
     */
    @Override
    public void handleMessage(Message message) {

        OAuthClientAuthnService oAuthClientAuthnService = (OAuthClientAuthnService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuthClientAuthnService.class, null);
        Map<String, List> bodyContentParams = getContentParams(message);
        HttpServletRequest request = ((HttpServletRequest) message.get(HTTP_REQUEST));
        OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService.authenticateClient(request,
                bodyContentParams);
        if (!oAuthClientAuthnContext.isPreviousAuthenticatorEngaged()) {
            oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
            oAuthClientAuthnContext.setErrorMessage("Unsupported client authentication mechanism");
        }
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

    private void setContextToRequest(HttpServletRequest request, OAuthClientAuthnContext oAuthClientAuthnContext) {

        if (log.isDebugEnabled()) {
            log.debug("Setting OAuth client authentication context to request");
        }
        request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT,
                oAuthClientAuthnContext);
    }

}
