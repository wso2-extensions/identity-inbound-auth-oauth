/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.discovery.servlet;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.io.Serial;
import java.util.Collections;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet to serve the OIDC discovery document at /.well-known/openid-configuration.
 * <p>
 * Handles:
 * GET /.well-known/openid-configuration            → super-tenant discovery
 * GET /t/{tenant}/.well-known/openid-configuration → tenant-specific discovery
 */
@Component(
        service = Servlet.class,
        immediate = true,
        property = {
                "osgi.http.whiteboard.servlet.pattern=/.well-known/openid-configuration",
                "osgi.http.whiteboard.servlet.name=OIDCDiscovery",
                "osgi.http.whiteboard.servlet.asyncSupported=true"
        }
)
public class OIDCDiscoveryServlet extends HttpServlet {

    @Serial
    private static final long serialVersionUID = -4599438512732128049L;

    private static final Log LOG = LogFactory.getLog(OIDCDiscoveryServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        final String tenantDomain = OAuth2Util.resolveTenantDomain(request);
        final DefaultOIDCProcessor oidcProcessor = DefaultOIDCProcessor.getInstance();
        try {
            OIDProviderConfigResponse configResponse = oidcProcessor.getResponse(request, tenantDomain);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(OAuthConstants.HTTP_RESP_CONTENT_TYPE_JSON);
            response.getWriter().print(new Gson().toJson(configResponse.getConfigMap()));
        } catch (OIDCDiscoveryEndPointException e) {
            response.setStatus(oidcProcessor.handleError(e));
            response.setContentType(OAuthConstants.HTTP_RESP_CONTENT_TYPE_JSON);
            response.getWriter().print(new Gson().toJson(Collections.singletonMap("error", e.getMessage())));
        } catch (ServerConfigurationException e) {
            LOG.error("Server Configuration error while serving OIDC discovery.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType(OAuthConstants.HTTP_RESP_CONTENT_TYPE_JSON);
            response.getWriter().print(new Gson()
                    .toJson(Collections.singletonMap("error", "Error in reading configuration.")));
        }
    }
}
