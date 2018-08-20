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

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * This class is dedicated for authenticating 'Public Clients'. Public clients do not need a client secret to be
 * authorised. This type of authentication is regularly utilised by native OAuth2 clients.
 */
public class PublicClientAuthenticator extends AbstractOAuthClientAuthenticator {

    private static Log log = LogFactory.getLog(PublicClientAuthenticator.class);
    private static String SIMPLE_CASE_AUTHORIZATION_HEADER = "authorization";
    private static String CREDENTIAL_SEPARATOR = ":";
    private static int CREDENTIAL_LENGTH = 2;

    /**
     * Returns the execution order of this authenticator
     *
     * @return Execution place within the order
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

        try {
            if (isAuthorizationHeaderExists(request)) {
                if (isClientSecretExists(getAuthorizationHeader(request))) {
                    return false;
                }
            }

            context.setClientId(getClientId(request, bodyParams, context));
            if (isClientIdExistsAsParams(bodyParams)) {
                if (OAuth2Util.isBypassClientCredentials(context.getClientId())) {
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Client is not public.");
                    }
                    return false;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Client ID could not be retrieved.");
                }
            }
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Client ID could not be retrieved.");
            }
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Client ID could not be retrieved.");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Client ID not present as Authorization header nor as body params. Hence " +
                    "returning false");
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

        return "PublicOAuthClientAuthenticator";
    }

    /**
     * Retrieves the client ID which is extracted from incoming request.
     *
     * @param request                 HttpServletRequest.
     * @param bodyParams              Body paarameter map of the incoming request.
     * @param oAuthClientAuthnContext OAuthClientAuthentication context.
     * @return Client ID of the OAuth2 client.
     * @throws OAuthClientAuthnException OAuth client authentication context.
     */
    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) {

        setClientCredentialsFromParam(bodyParams, oAuthClientAuthnContext);
        return oAuthClientAuthnContext.getClientId();
    }

    /**
     * Checks for an authorization header.
     *
     * @param request HttpServletRequest.
     * @return True if auth header exists, false otherwise.
     */
    protected boolean isAuthorizationHeaderExists(HttpServletRequest request) {
        String authorizationHeader = getAuthorizationHeader(request);
        if (StringUtils.isNotEmpty(authorizationHeader)) {
            return true;
        }
        return false;
    }

    /**
     * Checks for the client ID in body parameters.
     *
     * @param contentParam Request body parameters.
     * @return True if client ID exists as a body parameter, false otherwise.
     */
    protected boolean isClientIdExistsAsParams(Map<String, List> contentParam) {

        Map<String, String> stringContent = getBodyParameters(contentParam);
        return (StringUtils.isNotEmpty(stringContent.get(OAuth.OAUTH_CLIENT_ID)));
    }

    /**
     * Checks if the client secret exists in the header.
     *
     * @param authorizationHeader Authorization header.
     * @return True if the client secret exists, false otherwise.
     */
    protected boolean isClientSecretExists(String authorizationHeader) {
        try {
            if (extractCredentialsFromAuthzHeader(authorizationHeader).length == CREDENTIAL_LENGTH) {
                return true;
            }
        } catch (OAuthClientAuthnException e) {
            if (log.isDebugEnabled()) {
                log.error("Could not extract client credentials from header.");
            }
        }
        return false;
    }

    /**
     * Extracts client id and secret from Authorization header.
     *
     * @param authorizationHeader     Authroization header.
     * @return An array which has client id as the first element and secret as the second element.
     * @throws OAuthClientAuthnException
     */
    protected static String[] extractCredentialsFromAuthzHeader(String authorizationHeader) throws OAuthClientAuthnException {

        String[] splitValues = authorizationHeader.trim().split(" ");
        if (splitValues.length == CREDENTIAL_LENGTH) {
            byte[] decodedBytes = Base64Utils.decode(splitValues[1].trim());
            String userNamePassword = new String(decodedBytes, Charsets.UTF_8);
            String[] credentials = userNamePassword.split(CREDENTIAL_SEPARATOR);
            if (credentials.length == CREDENTIAL_LENGTH) {
                return credentials;
            }
        }
        String errMsg = "Error decoding authorization header. Space delimited \"<authMethod> <base64Hash>\" format " +
                "violated.";
        throw new OAuthClientAuthnException(errMsg, OAuth2ErrorCodes.INVALID_REQUEST);
    }

    /**
     * Retrieves the authorization header from the request.
     *
     * @param request HttpServletRequest.
     * @return Authorization header of the request.
     */
    protected String getAuthorizationHeader(HttpServletRequest request) {

        String authorizationHeader = request.getHeader(HTTPConstants.HEADER_AUTHORIZATION);
        if (StringUtils.isEmpty(authorizationHeader)) {
            authorizationHeader = request.getHeader(SIMPLE_CASE_AUTHORIZATION_HEADER);
        }
        return authorizationHeader;
    }

    /**
     * Sets client id from body parameters to the OAuth client authentication context.
     *
     * @param params Body parameters of the incoming request.
     * @param context      OAuth client authentication context.
     */
    protected void setClientCredentialsFromParam(Map<String, List> params, OAuthClientAuthnContext context) {

        Map<String, String> stringContent = getBodyParameters(params);
        context.setClientId(stringContent.get(OAuth.OAUTH_CLIENT_ID));
    }

}
