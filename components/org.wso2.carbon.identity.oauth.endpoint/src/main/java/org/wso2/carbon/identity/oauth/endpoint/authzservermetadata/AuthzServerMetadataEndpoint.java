/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.authzservermetadata;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OIDCProviderServiceFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Rest implementation of OIDC discovery endpoint.
 */
@Path("/{issuer}/.well-known/oauth-authorization-server")
public class AuthzServerMetadataEndpoint {

    private static final Log log = LogFactory.getLog(AuthzServerMetadataEndpoint.class);
    private static final String AUTHZ_SERVER_METADATA_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN = "token";

    @GET
    @Produces("application/json")
    public Response getOIDProviderConfiguration(
            @PathParam("issuer") String discoveryEpPathComponent, @Context HttpServletRequest request) {

        String tenantDomain = null;
        Object tenantObj = IdentityUtil.threadLocalProperties.get().get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        if (tenantObj != null) {
            tenantDomain = (String) tenantObj;
        }
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        if (isValidIssuer(discoveryEpPathComponent)) {
            return this.getResponse(request, tenantDomain);
        } else {
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_BAD_REQUEST);
            if (log.isDebugEnabled()) {
                log.debug("The discovery path component is " + discoveryEpPathComponent +
                        " . The expected discovery path component is either '"
                        + AUTHZ_SERVER_METADATA_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN);
            }
            return errorResponse.entity("Invalid path to the discovery document. " +
                    "Received path : " + discoveryEpPathComponent + " is not resolvable").build();
        }
    }

    private boolean isValidIssuer(String issuer) {

        if (AUTHZ_SERVER_METADATA_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN.equals(issuer)) {
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("DiscoveryEndpointPathComponent validation failed. DiscoveryEndpointPathComponent value: " +
                    issuer + ", not matched to '"
                    + AUTHZ_SERVER_METADATA_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN);
        }
        return false;
    }

    private Response getResponse(HttpServletRequest request, String tenant) {

        String response;
        OIDCProcessor processor = OIDCProviderServiceFactory.getOIDCService();
        try {
            AuthzServerMetadataJsonResponseBuilder responseBuilder = new AuthzServerMetadataJsonResponseBuilder();
            response = responseBuilder.getAuthzServerMetadataConfigString(processor.getResponse(request, tenant));

        } catch (OIDCDiscoveryEndPointException e) {
            Response.ResponseBuilder errorResponse = Response.status(processor.handleError(e));
            return errorResponse.entity(e.getMessage()).build();
        } catch (ServerConfigurationException e) {
            log.error("Server Configuration error occurred.", e);
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return errorResponse.entity("Error in reading configuration.").build();
        }
        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_OK);
        return responseBuilder.entity(response).build();
    }
}
