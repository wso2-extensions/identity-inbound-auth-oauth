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

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * This class is dedicated for authenticating 'Public Clients'. Public clients do not need a client secret to be
 * authenticated. This type of authentication is regularly utilised by native OAuth2 clients.
 */
public class PublicClientAuthenticator extends AbstractOAuthClientAuthenticator {

    public static final String PUBLIC_CLIENT_AUTHENTICATOR = "PublicClientAuthenticator";
    private static final Log log = LogFactory.getLog(PublicClientAuthenticator.class);
    private static final String GRANT_TYPE = "grant_type";
    private static final String RESPONSE_MODE = "response_mode";

    /**
     * Returns the execution order of this authenticator.
     *
     * @return Execution place within the order.
     */
    @Override
    public int getPriority() {

        return 200;
    }

    /**
     * Authenticates the client.
     *
     * @param request                 HttpServletRequest which is the incoming request.
     * @param bodyParams              Body parameter map of the request.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @return Whether the authentication is successful or not.
     * @throws OAuthClientAuthnException
     */
    @Override
    public boolean authenticateClient(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) {

        return true;
    }

    /**
     * Returns whether the incoming request can be authenticated or not using the given inputs.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param bodyParams Body parameters present in the request.
     * @param context    OAuth2 client authentication context.
     * @return True if can be authenticated, False otherwise.
     */
    @Override
    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            context) {

        List<String> publicClientSupportedGrantTypes = OAuthServerConfiguration.getInstance().
                getPublicClientSupportedGrantTypesList();
        List grantTypes = bodyParams.get(GRANT_TYPE);

        if (publicClientSupportedGrantTypes.isEmpty()) {
            log.warn("No grant types are specified for public clients.");
            return false;
        }

        if (grantTypes != null) {
            for (Object grantType : grantTypes) {
                if (!publicClientSupportedGrantTypes.contains(grantType.toString())) {
                    log.warn("The request contained grant type : '" + grantType + "' which is not " +
                            "allowed for public clients.");
                    return false;
                }
            }
        }

        String clientId = getClientId(request, bodyParams, context);

        try {
            if (isClientIdExistsAsParams(request, bodyParams)) {
                if (canBypassClientCredentials(context.getClientId())) {
                    if (clientId != null) {
                        context.setClientId(clientId);
                    }
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("The Application (Service Provider) with client ID : " + clientId
                                + " has not enabled the option \"Allow authentication without the client secret\".");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Client ID " + clientId + " is not found among the request body parameters.");
                }
            }
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in retrieving an Application (Service Provider) with client ID : " + clientId, e);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error in Application (Service Provider) with client ID : " + clientId, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("The Client ID is not present in the request.");
        }

        return false;
    }

    /**
     * Get the name of the OAuth2 client authenticator.
     *
     * @return The name of the OAuth2 client authenticator.
     */
    @Override
    public String getName() {

        return PUBLIC_CLIENT_AUTHENTICATOR;
    }

    /**
     * Retrieves the client ID which is extracted from incoming request.
     *
     * @param request                 HttpServletRequest.
     * @param bodyParams              Body paarameter map of the incoming request.
     * @param oAuthClientAuthnContext OAuthClientAuthentication context.
     * @return Client ID of the OAuth2 client.
     */
    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) {

        if (StringUtils.isBlank(oAuthClientAuthnContext.getClientId())) {
            setClientCredentialsFromParam(request, bodyParams, oAuthClientAuthnContext);
        }
        return oAuthClientAuthnContext.getClientId();
    }

    /**
     * Checks if the client can bypass credentials.
     *
     * @param clientId Client ID
     * @return True is the client can bypass credentials, False otherwise.
     * @throws IdentityOAuth2Exception OAuth2 exception.
     * @throws InvalidOAuthClientException Invalid OAuth2 client exception.
     */
    private boolean canBypassClientCredentials(String clientId) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        return OAuth2Util.getAppInformationByClientId(clientId).isBypassClientCredentials();
    }

    /**
     * Checks for the client ID in body parameters.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param contentParam Request body parameters.
     * @return True if client ID exists as a body parameter, false otherwise.
     */
    private boolean isClientIdExistsAsParams(HttpServletRequest request, Map<String, List> contentParam) {

        Map<String, String> stringContent = getBodyParameters(contentParam);
        String clientId = stringContent.get(OAuth.OAUTH_CLIENT_ID);
        /* With API based authentication, client authentication is provided for the authorization endpoint.
         When calling /GET authorization ep, the client ID is not available in the request body.
         Hence, the client ID is extracted from the request parameter.*/
        if (StringUtils.isBlank(clientId) && isApiBasedAuthenticationFlow(request)) {
            clientId = request.getParameter(OAuth.OAUTH_CLIENT_ID);
        }
        return (StringUtils.isNotEmpty(clientId));
    }

    /**
     * Sets client id from body parameters to the OAuth client authentication context.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param params Body parameters of the incoming request.
     * @param context      OAuth client authentication context.
     */
    private void setClientCredentialsFromParam(HttpServletRequest request, Map<String, List> params,
                                               OAuthClientAuthnContext context) {

        Map<String, String> stringContent = getBodyParameters(params);
        String clientId = stringContent.get(OAuth.OAUTH_CLIENT_ID);
        /* With API based authentication, client authentication is provided for the authorization endpoint.
         When calling /GET authorization ep, the client ID is not available in the request body.
         Hence, the client ID is extracted from the request parameter.*/
        if (StringUtils.isBlank(clientId) && isApiBasedAuthenticationFlow(request)) {
            clientId = request.getParameter(OAuth.OAUTH_CLIENT_ID);
        }
        context.setClientId(clientId);
    }

    private boolean isApiBasedAuthenticationFlow(HttpServletRequest request) {

        return StringUtils.equals(OAuthConstants.ResponseModes.DIRECT,
                request.getParameter(RESPONSE_MODE));
    }
}
