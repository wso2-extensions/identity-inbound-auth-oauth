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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.io.IOException;
import java.io.Serial;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
                "osgi.http.whiteboard.servlet.pattern=/.well-known/openid-configuration/*",
                "osgi.http.whiteboard.servlet.name=OIDCDiscovery",
                "osgi.http.whiteboard.servlet.asyncSupported=true"
        }
)
public class OIDCDiscoveryServlet extends HttpServlet {

    @Serial
    private static final long serialVersionUID = -4599438512732128049L;

    private static final Log log = LogFactory.getLog(OIDCDiscoveryServlet.class);
    private static final Pattern TENANT_PATH_PATTERN = Pattern.compile("^/(|t/[^/]+)$");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String tenantDomain = resolveTenantDomain(request);
        if (tenantDomain == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        DefaultOIDCProcessor oidcProcessor = DefaultOIDCProcessor.getInstance();
        try {
            OIDProviderConfigResponse configResponse = oidcProcessor.getResponse(request, tenantDomain);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().print(new Gson().toJson(configResponse.getConfigMap()));
        } catch (OIDCDiscoveryEndPointException e) {
            response.setStatus(oidcProcessor.handleError(e));
            response.setContentType("application/json");
            response.getWriter().print(e.getMessage());
        } catch (ServerConfigurationException e) {
            log.error("Server Configuration error while serving OIDC discovery.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().print("Error in reading configuration.");
        }
    }

    /**
     * Resolves the tenant domain from the request.
     * <p>
     * Returns null if the path info is not a recognised pattern (triggers a 404).
     */
    private String resolveTenantDomain(HttpServletRequest request) {

        String pathInfo = request.getPathInfo();

        // No path info → /.well-known/openid-configuration (super-tenant or tenant from thread-local)
        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            String tenantFromContext = (String) IdentityUtil.threadLocalProperties.get()
                    .get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
            return StringUtils.isNotEmpty(tenantFromContext)
                    ? tenantFromContext
                    : MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        Matcher matcher = TENANT_PATH_PATTERN.matcher(pathInfo);
        if (matcher.matches()) {
            return matcher.group(1);
        }

        return null;
    }
}
