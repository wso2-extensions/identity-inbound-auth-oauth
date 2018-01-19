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
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * This classs is esponsible for authenticating OAuth clients which are client id and secret to authenticate. This
 * authenticator will handle basic client authentication where client id and secret are present either as
 * Authroization header or in the body of the request.
 */
public class BasicAuthClientAuthenticator extends AbstractOAuthClientAuthenticator {

    private static Log log = LogFactory.getLog(BasicAuthClientAuthenticator.class);

    /**
     * Returns the execution order of this authenticator
     *
     * @return Execution place within the order
     */
    @Override
    public int getPriority() {
        return 100;
    }

    /**
     * @param request                 HttpServletRequest which is the incoming request.
     * @param contentMap              Body parameter map of the request.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @return Whether the authentication is successful or not.
     * @throws OAuthClientAuthnException
     */
    @Override
    public boolean authenticateClient(HttpServletRequest request, Map<String, List> contentMap, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        validateAuthenticationInfo(request, contentMap);
        // Sets client id from canAuthenticate to void reading them again.
        if (StringUtils.isEmpty(oAuthClientAuthnContext.getClientId())) {
            if (log.isDebugEnabled()) {
                log.debug("Couldn't find client ID in context. Hence returning false");
            }
            return false;
        } else {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticating client: " + oAuthClientAuthnContext.getClientId() + " with client " +
                            "secret.");
                }
                return OAuth2Util.authenticateClient(oAuthClientAuthnContext.getClientId(),
                        (String) oAuthClientAuthnContext.getParameter(OAuth.OAUTH_CLIENT_SECRET));
            } catch (IdentityOAuthAdminException e) {
                throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_CLIENT, "Error while authenticating " +
                        "client", e);
            } catch (InvalidOAuthClientException e) {
                throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_CLIENT,
                        "Invalid Client : " + oAuthClientAuthnContext.getClientId(), e);
            } catch (IdentityOAuth2Exception e) {
                throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_CLIENT, "Error while authenticating " +
                        "client", e);
            }
        }
    }

    private void validateAuthenticationInfo(HttpServletRequest request, Map<String, List> contentMap)
            throws OAuthClientAuthnException {
        if (isAuthorizationHeaderExists(request)) {
            if (log.isErrorEnabled()) {
                log.debug("Authorization header exists. Hence validating whether body params also present");
            }
            validateDuplicatedBasicAuthInfo(request, contentMap);
        }
    }

    /**
     * Returns whether the incoming request can be authenticated or not using the given inputs.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param contentMap Body parameters present in the request.
     * @param context    OAuth2 client authentication context.
     * @return
     */
    @Override
    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> contentMap, OAuthClientAuthnContext
            context) {

        if (isAuthorizationHeaderExists(request)) {
            if (log.isDebugEnabled()) {
                log.debug("Basic auth credentials exists as Authorization header. Hence returning true.");
            }
            return true;
        } else if (isClientCredentialsExistsAsParams(contentMap)) {
            if (log.isDebugEnabled()) {
                log.debug("Basic auth credentials present as body params. Hence returning true");
            }
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("Client id and secret neither present as Authorization header nor as body params. Hence " +
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
        return "BasicOAuthClientCredAuthenticator";
    }

    /**
     * Retrives the client ID which is extracted from incoming request.
     *
     * @param request                 HttpServletRequest.
     * @param contentMap              Body paarameter map of the incoming request.
     * @param oAuthClientAuthnContext OAuthClientAuthentication context.
     * @return Client ID of the OAuth2 client.
     * @throws OAuthClientAuthnException OAuth client authentication context.
     */
    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> contentMap, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        if (isAuthorizationHeaderExists(request)) {
            validateDuplicatedBasicAuthInfo(request, contentMap);
            String[] credentials = extractCredentialsFromAuthzHeader(getAuthorizationHeader(request),
                    oAuthClientAuthnContext);
            oAuthClientAuthnContext.setClientId(credentials[0]);
            oAuthClientAuthnContext.addParameter(OAuth.OAUTH_CLIENT_SECRET, credentials[1]);

        } else {
            setClientCredentialsFromParam(contentMap, oAuthClientAuthnContext);
        }
        return oAuthClientAuthnContext.getClientId();
    }


    /**
     * Validates that basic authentication information is only present either in body or as authorization headers.
     *
     * @param request      HttpServletRequest which is the incoming request.
     * @param contentParam Parameter map of the body content.
     * @throws OAuthClientAuthnException
     */
    protected void validateDuplicatedBasicAuthInfo(HttpServletRequest request, Map<String, List> contentParam) throws
            OAuthClientAuthnException {

        // The client MUST NOT use more than one authentication method in each request.
        if (isClientCredentialsExistsAsParams(contentParam)) {
            if (log.isDebugEnabled()) {
                log.debug("Client Id and Client Secret found in request body and Authorization header" +
                        ". Credentials should be sent in either request body or Authorization header, not both");
            }
            throw new OAuthClientAuthnException("Request body and headers contain authorization information",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    protected boolean isAuthorizationHeaderExists(HttpServletRequest request) {
        return StringUtils.isNotEmpty(getAuthorizationHeader(request));
    }

    protected String getAuthorizationHeader(HttpServletRequest request) {
        return request.getHeader(HTTPConstants.HEADER_AUTHORIZATION);
    }

    protected boolean isClientCredentialsExistsAsParams(Map<String, List> contentParam) {
        Map<String, String> stringContent = getBodyParameters(contentParam);
        return (StringUtils.isNotEmpty(stringContent.get(OAuth.OAUTH_CLIENT_ID)) && StringUtils.isNotEmpty
                (stringContent.get(OAuth.OAUTH_CLIENT_SECRET)));
    }

    /**
     * Extracts client id and secret from Authorization header.
     *
     * @param authorizationHeader     Authroization header.
     * @param oAuthClientAuthnContext OAuth Client Authentication context.
     * @return An array which has client id as the first element and secret as the second element.
     * @throws OAuthClientAuthnException
     */
    protected static String[] extractCredentialsFromAuthzHeader(String authorizationHeader, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        if (authorizationHeader == null) {
            throw new OAuthClientAuthnException("Authorization header value is null");
        }
        String[] splitValues = authorizationHeader.trim().split(" ");
        if (splitValues.length == 2) {
            byte[] decodedBytes = Base64Utils.decode(splitValues[1].trim());
            String userNamePassword = new String(decodedBytes, Charsets.UTF_8);
            String[] credentials = userNamePassword.split(":");
            if (credentials.length == 2) {
                return credentials;
            }
        }
        String errMsg = "Error decoding authorization header. Space delimited \"<authMethod> <base64Hash>\" format " +
                "violated.";
        throw new OAuthClientAuthnException(errMsg, OAuth2ErrorCodes.INVALID_REQUEST);
    }

    /**
     * Sets client id to the OAuth client authentication context.
     *
     * @param contentParam Body parameters of the incoming request.
     * @param context      OAuth client authentication context.
     */
    protected void setClientCredentialsFromParam(Map<String, List> contentParam, OAuthClientAuthnContext context) {
        Map<String, String> stringContent = getBodyParameters(contentParam);
        context.setClientId(stringContent.get(OAuth.OAUTH_CLIENT_ID));
        context.addParameter(OAuth.OAUTH_CLIENT_SECRET, stringContent.get(OAuth.OAUTH_CLIENT_SECRET));
    }

}
