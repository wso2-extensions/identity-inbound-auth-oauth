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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Servlet to serve /.well-known/oauth-authorization-server endpoint.
 */
@Component(
        service = Servlet.class,
        immediate = true,
        property = {
                "osgi.http.whiteboard.servlet.pattern=/.well-known/oauth-authorization-server/*",
                "osgi.http.whiteboard.servlet.name=AuthzServerMetadata",
                "osgi.http.whiteboard.servlet.asyncSupported=true"
        }
)
public class AuthzServerMetadataServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Log log = LogFactory.getLog(AuthzServerMetadataServlet.class);
    private static final Pattern ALLOWED_PATH_PATTERN =
            Pattern.compile("^/(oauth2/token|t/[^/]+/oauth2/token)$");
    private static final String[] AUTHZ_SERVER_METADATA_FIELDS = {
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "scopes_supported",
            "response_types_supported",
            "grant_types_supported",
            "response_modes_supported",
            "registration_endpoint",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "revocation_endpoint",
            "revocation_endpoint_auth_methods_supported",
            "introspection_endpoint",
            "introspection_endpoint_auth_methods_supported",
            "code_challenge_methods_supported",
            "pushed_authorization_request_endpoint",
            "device_authorization_endpoint",
            "tls_client_certificate_bound_access_tokens",
            "mtls_endpoint_aliases",
            "authorization_details_types_supported"
    };

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (!isValidPath(request.getPathInfo())) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        String tenantDomain = (String) IdentityUtil.threadLocalProperties.get()
                .get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        DefaultOIDCProcessor oidcProcessor = DefaultOIDCProcessor.getInstance();
        try {
            OIDProviderConfigResponse configResponse = oidcProcessor.getResponse(request, tenantDomain);
            Map<String, Object> configs = configResponse.getConfigMap();
            Set<String> allowedKeys = new HashSet<>(Arrays.asList(AUTHZ_SERVER_METADATA_FIELDS));
            configs.keySet().retainAll(allowedKeys);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().print(new Gson().toJson(configs));
        } catch (OIDCDiscoveryEndPointException e) {
            response.setStatus(oidcProcessor.handleError(e));
            response.getWriter().print(e.getMessage());
        } catch (ServerConfigurationException e) {
            log.error("Server Configuration error occurred.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().print("Error in reading configuration.");
        }
    }

    private boolean isValidPath(String pathInfo) {

        if (StringUtils.isBlank(pathInfo)) {
            return false;
        }

        return AuthzServerMetadataServlet.ALLOWED_PATH_PATTERN.matcher(pathInfo).matches();
    }
}
