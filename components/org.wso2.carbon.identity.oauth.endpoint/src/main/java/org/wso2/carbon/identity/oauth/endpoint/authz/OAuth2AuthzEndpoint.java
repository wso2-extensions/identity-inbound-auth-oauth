/*
 * Copyright (c) 2013-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.authz;

import org.apache.commons.lang.StringUtils;
import org.apache.cxf.interceptor.InInterceptors;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.client.attestation.filter.ClientAttestationProxy;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.AuthzUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.RequestUtil;

import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getErrorPageURL;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.validateParams;

/**
 * Rest implementation of OAuth2 authorize endpoint.
 */
@Path("/authorize")
@InInterceptors(classes = {OAuthClientAuthenticatorProxy.class, ClientAttestationProxy.class})
public class OAuth2AuthzEndpoint {

    public static final String COMMA_SEPARATOR = ",";
    public static final String SPACE_SEPARATOR = " ";

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws URISyntaxException, InvalidRequestParentException {

        OAuthMessage oAuthMessage;

        // TODO: 2021-01-22 Check for the flag in request.
        AuthzUtil.setCommonAuthIdToRequest(request, response);

        // Using a separate try-catch block as this next try block has operations in the final block.
        try {
            request = RequestUtil.buildRequest(request);
            oAuthMessage = AuthzUtil.buildOAuthMessage(request, response);

        } catch (InvalidRequestParentException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            throw e;
        } catch (IdentityException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleIdentityException(request, e);
        }

        // Perform request authentication for API based auth flow.
        if (OAuth2Util.isApiBasedAuthenticationFlow(request)) {
            OAuthClientAuthnContext oAuthClientAuthnContext = AuthzUtil.getClientAuthnContext(request);
            if (!oAuthClientAuthnContext.isAuthenticated()) {
                return AuthzUtil.handleAuthFailureResponse(oAuthClientAuthnContext);
            }

            ClientAttestationContext clientAttestationContext = AuthzUtil.getClientAttestationContext(request);
            if (clientAttestationContext.isAttestationEnabled() && !clientAttestationContext.isAttested()) {
                return AuthzUtil.handleAttestationFailureResponse(clientAttestationContext);
            }

            if (!OAuth2Util.isApiBasedAuthSupportedGrant(request)) {
                return AuthzUtil.handleUnsupportedGrantForApiBasedAuth(request);
            }
        }

        try {
            // Start tenant domain flow if the tenant configuration is not enabled.
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                String tenantDomain = null;
                if (StringUtils.isNotEmpty(oAuthMessage.getClientId())) {
                    tenantDomain = EndpointUtil.getSPTenantDomainFromClientId(oAuthMessage.getClientId());
                } else if (oAuthMessage.getSessionDataCacheEntry() != null) {
                    OAuth2Parameters oauth2Params = AuthzUtil.getOauth2Params(oAuthMessage);
                    tenantDomain = oauth2Params.getTenantDomain();
                }
                FrameworkUtils.startTenantFlow(tenantDomain);
            }

            Response oauthResponse;
            if (AuthzUtil.isPassthroughToFramework(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleAuthFlowThroughFramework(oAuthMessage);
            } else if (AuthzUtil.isInitialRequestFromClient(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleInitialAuthorizationRequest(oAuthMessage);
            } else if (AuthzUtil.isAuthenticationResponseFromFramework(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleAuthenticationResponse(oAuthMessage);
            } else if (AuthzUtil.isConsentResponseFromUser(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleResponseFromConsent(oAuthMessage);
            } else {
                oauthResponse = AuthzUtil.handleInvalidRequest(oAuthMessage);
            }
            if (AuthzUtil.isApiBasedAuthenticationFlow(oAuthMessage)) {
                oauthResponse = AuthzUtil.handleApiBasedAuthenticationResponse(oAuthMessage, oauthResponse);
            }

            return oauthResponse;
        } catch (OAuthProblemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleOAuthProblemException(oAuthMessage, e);
        } catch (OAuthSystemException e) {
            EndpointUtil.triggerOnAuthzRequestException(e, request);
            return AuthzUtil.handleOAuthSystemException(oAuthMessage, e);
        } finally {
            AuthzUtil.handleCachePersistence(oAuthMessage);
            if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"text/html", "application/json"})
    public Response authorizePost(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                  MultivaluedMap paramMap)
            throws URISyntaxException, InvalidRequestParentException {

        // Validate repeated parameters
        if (!validateParams(request, paramMap)) {
            return Response.status(HttpServletResponse.SC_BAD_REQUEST).location(new URI(getErrorPageURL(request,
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes
                            .INVALID_AUTHORIZATION_REQUEST, "Invalid authorization request with repeated parameters",
                    null)))
                    .build();
        }
        HttpServletRequestWrapper httpRequest = new OAuthRequestWrapper(request, paramMap);
        return authorize(httpRequest, response);
    }
}
