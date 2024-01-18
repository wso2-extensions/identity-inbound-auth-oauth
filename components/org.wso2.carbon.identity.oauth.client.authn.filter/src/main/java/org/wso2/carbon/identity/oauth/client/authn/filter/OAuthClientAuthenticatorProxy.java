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
import org.json.JSONObject;
import org.wso2.carbon.identity.core.persistence.DBConnectionException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

/**
 * JAX-RS interceptor which intercepts requests. This interceptor will act as a proxy for OAuth2 Client Authenticators.
 * This will pick correct authenticator which can handle OAuth client authentication and engage it.
 */
public class OAuthClientAuthenticatorProxy extends AbstractPhaseInterceptor<Message> {

    private static final Log log = LogFactory.getLog(OAuthClientAuthenticatorProxy.class);
    private static final String HTTP_REQUEST = "HTTP.REQUEST";
    private static final List<String> PROXY_ENDPOINT_LIST = Arrays.asList("/oauth2/token", "/oauth2/revoke",
            "/oauth2/device_authorize", "/oauth2/ciba", "/oauth2/par", "/oauth2/authorize");
    private OAuthClientAuthnService oAuthClientAuthnService;
    private static final String SLASH = "/";

    public OAuthClientAuthenticatorProxy() {

        // Since the body is consumed and body parameters are available at this phase we use "PRE_INVOKE"
        super(Phase.PRE_INVOKE);
    }

    public OAuthClientAuthnService getOAuthClientAuthnService() {

        return oAuthClientAuthnService;
    }

    public void setOAuthClientAuthnService(OAuthClientAuthnService oAuthClientAuthnService) {

        this.oAuthClientAuthnService = oAuthClientAuthnService;
    }

    /**
     * Handles the incoming JAX-RS message for the purpose of OAuth2 client authentication.
     *
     * @param message JAX-RS message
     */
    @Override
    public void handleMessage(Message message) {

        Map<String, List> bodyContentParams = getContentParams(message);
        HttpServletRequest request = ((HttpServletRequest) message.get(HTTP_REQUEST));
        if (canHandle(message)) {
            try {
                OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService
                        .authenticateClient(request, bodyContentParams);
                if (!oAuthClientAuthnContext.isPreviousAuthenticatorEngaged()) {
                    oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
                    oAuthClientAuthnContext.setErrorMessage("Unsupported client authentication mechanism");
                }
                setContextToRequest(request, oAuthClientAuthnContext);
            } catch (DBConnectionException e) {
                log.error("Unable to retrieve a connection to DB while authenticating the client", e);
                String errorMessage = new JSONObject().put("error_description", "Internal Server Error.")
                        .put("error", "server_error").toString();
                Response response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(errorMessage).build();
                throw new WebApplicationException(response);
            }
        }
    }

    /**
     * Determines whether the respective endpoint should be the handled through the authenticator proxy interceptor.
     *
     * @param message           The CXF Message object representing the incoming request.
     * @return True if the endpoint should be the handled through the interceptor, false otherwise.
     */
    private boolean canHandle(Message message) {

        String requestPath = (String) message.get(Message.REQUEST_URI);
        requestPath = removeTrailingSlash(requestPath);
        return PROXY_ENDPOINT_LIST.stream().anyMatch(requestPath::equalsIgnoreCase);
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

    private String removeTrailingSlash(String url) {

        if (url != null && url.endsWith(SLASH)) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }
}
