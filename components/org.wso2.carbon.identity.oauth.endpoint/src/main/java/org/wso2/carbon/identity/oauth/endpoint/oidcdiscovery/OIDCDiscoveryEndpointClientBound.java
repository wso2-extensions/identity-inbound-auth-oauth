/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.OIDProviderResponseBuilder;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OIDCProviderServiceFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigOrgUsageScopeMgtException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.services.OAuth2OIDCConfigOrgUsageScopeMgtService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Rest implementation of OIDC discovery endpoint for client-bound issuer resolution.
 * This endpoint is only accessible via the /t/{rootTenant}/o/{orgId}/client/{clientId} path pattern,
 */
@Path("/{issuer}/client/{clientId}/.well-known/openid-configuration")
public class OIDCDiscoveryEndpointClientBound {

    private static final Log log = LogFactory.getLog(OIDCDiscoveryEndpointClientBound.class);
    private static final String DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN = "token";
    private static final String DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_OIDCDISCOVERY = "oidcdiscovery";
    private OIDProviderResponseBuilder oidProviderResponseBuilder;

    @GET
    @Produces("application/json")
    public Response getOIDProviderConfiguration(
            @PathParam("issuer") String discoveryEpPathComponent,
            @PathParam("clientId") String clientId,
            @Context HttpServletRequest request) {

        String tenantDomain = null;
        Object tenantObj = IdentityUtil.threadLocalProperties.get().get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        if (tenantObj != null) {
            tenantDomain = (String) tenantObj;
        }
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        if (isValidIssuer(discoveryEpPathComponent)) {
            return this.getResponse(request, tenantDomain, clientId);
        } else {
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_BAD_REQUEST);
            if (log.isDebugEnabled()) {
                log.debug("The discovery path component is " + discoveryEpPathComponent +
                        " . The expected discovery path component is either '"
                        + DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN + "' or '" +
                        DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_OIDCDISCOVERY);
            }
            return errorResponse.entity("Invalid path to the discovery document. " +
                    "Received path : " + discoveryEpPathComponent + " is not resolvable").build();
        }
    }

    private boolean isValidIssuer(String issuer) {

        if (DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN.equals(issuer) ||
                DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_OIDCDISCOVERY.equals(issuer)) {
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("DiscoveryEndpointPathComponent validation failed. DiscoveryEndpointPathComponent value: " +
                    issuer + ", not matched to '"
                    + DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_TOKEN + "' or '" +
                    DISCOVERY_ENDPOINT_PATH_COMPONENT_VALUE_OIDCDISCOVERY + "'");
        }
        return false;
    }

    private Response getResponse(HttpServletRequest request, String tenant, String clientId) {

        String response;
        OIDCProcessor processor = OIDCProviderServiceFactory.getOIDCService();
        try {
            OIDProviderResponseBuilder responseBuilder = OIDCDiscoveryServiceFactory.getOIDProviderResponseBuilder();
            response = responseBuilder.getOIDProviderConfigString(processor.getResponse(request, tenant));
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId,
                    OAuth2Util.getAppResidentTenantDomain());
            if (StringUtils.isNotBlank(oAuthAppDO.getIssuerOrg())) {
                OAuth2OIDCConfigOrgUsageScopeMgtService oauth2OIDCConfigMgtService =
                        OAuth2ServiceComponentHolder.getInstance().getOAuth2OIDCConfigOrgUsageScopeMgtService();
                List<IssuerDetails> issuerDetailsList = oauth2OIDCConfigMgtService.getAllowedIssuerDetails();
                for (IssuerDetails issuerDetails : issuerDetailsList) {
                    if (oAuthAppDO.getIssuerOrg().equals(issuerDetails.getIssuerOrgId())) {
                        String issuer = issuerDetails.getIssuer();
                        response = response.replaceFirst(
                                "\"issuer\"\\s*:\\s*\"[^\"]+\"",
                                "\"issuer\":\"" + issuer + "\""
                        );
                        break;
                    }
                }
            }
        } catch (OIDCDiscoveryEndPointException e) {
            Response.ResponseBuilder errorResponse = Response.status(processor.handleError(e));
            return errorResponse.entity(e.getMessage()).build();
        } catch (ServerConfigurationException e) {
            log.error("Server Configuration error occurred.", e);
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return errorResponse.entity("Error in reading configuration.").build();
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error occurred while retrieving OAuth application information for clientId: " + clientId, e);
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_BAD_REQUEST);
            String errorJson = "{\"error\":\"invalid_client\",\"error_description\":" +
                    "\"Error in retrieving OAuth application information.\"}";
            return errorResponse.entity(errorJson).build();
        } catch (OAuth2OIDCConfigOrgUsageScopeMgtException e) {
            log.error("Error occurred while retrieving allowed issuer information.", e);
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            String errorJson = "{\"error\":\"server_error\",\"error_description\":" +
                    "\"Error in retrieving allowed issuer information.\"}";
            return errorResponse.entity(errorJson).build();
        }
        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_OK);
        return responseBuilder.entity(response).build();
    }
}
