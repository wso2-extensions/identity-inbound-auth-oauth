/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm;

import com.sun.jna.platform.win32.Sspi;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util.SimpleFilterChain;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util.SimpleHttpRequest;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util.SimpleHttpResponse;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.util.Base64;
import waffle.windows.auth.IWindowsCredentialsHandle;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import java.io.IOException;


public class NTLMAuthenticationGrantHandler extends AbstractAuthorizationGrantHandler {
    private static Log log = LogFactory.getLog(NTLMAuthenticationGrantHandler.class);
    String securityPackage = "Negotiate";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if(!super.validateGrant(tokReqMsgCtx)){
            return false;
        }

        NegotiateSecurityFilter filter;

        filter = new NegotiateSecurityFilter();
        filter.setAuth(new WindowsAuthProviderImpl());
        try {
            filter.init(null);
        } catch (ServletException e) {
            log.error("Error while initializing Negotiate Security Filter", e);
            throw new IdentityOAuth2Exception("Error while initializing Negotiate Security Filter", e);
        }
        String token = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getWindowsToken();
        boolean authenticated;
        IWindowsCredentialsHandle clientCredentials;
        WindowsSecurityContextImpl clientContext;
        filter.setRoleFormat("both");
        if (token != null) {

            // Logging the windows authentication object
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.NTLM_TOKEN)) {
                log.debug("Received NTLM Token : " + tokReqMsgCtx.getOauth2AccessTokenReqDTO().getWindowsToken());
            }

            // client credentials handle
            clientCredentials = WindowsCredentialsHandleImpl.getCurrent(securityPackage);
            clientCredentials.initialize();
            // initial client security context
            clientContext = new WindowsSecurityContextImpl();
            clientContext.setPrincipalName(WindowsAccountImpl.getCurrentUsername());
            clientContext.setCredentialsHandle(clientCredentials.getHandle());
            clientContext.setSecurityPackage(securityPackage);
            clientContext.initialize(null, null, WindowsAccountImpl.getCurrentUsername());

            SimpleHttpRequest request = new SimpleHttpRequest();
            SimpleFilterChain filterChain = new SimpleFilterChain();

            while (true) {

                try {
                    request.addHeader("Authorization", securityPackage + " " + token);
                    SimpleHttpResponse response = new SimpleHttpResponse();

                    try {
                        filter.doFilter(request, response, filterChain);
                    } catch (IOException e) {
                        log.error("You have been given wrong inputs to negotiate filter", e);
                        throw new IdentityOAuth2Exception("Error while processing negotiate the filter.", e);
                    }

                    Subject subject = (Subject) request.getSession().getAttribute("javax.security.auth.subject");
                    authenticated = (subject != null && subject.getPrincipals().size() > 0);

                    if (authenticated) {
                        if (log.isDebugEnabled()) {
                            log.debug("NTLM token is authenticated");
                        }
                        String resourceOwnerUserNameWithDomain = WindowsAccountImpl.getCurrentUsername();
                        String[] splitValues = resourceOwnerUserNameWithDomain.split("\\\\");
                        if (splitValues.length == 2) {
                            String resourceOwnerUserName = splitValues[1];

                            if (log.isDebugEnabled()) {
                                log.debug("Username of resource owner: " + resourceOwnerUserName);
                            }

                            tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(resourceOwnerUserName));
                            break;
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Invalid format for username: " + resourceOwnerUserNameWithDomain);
                            }
                        }
                    }
                    String continueToken = response.getHeader("WWW-Authenticate").
                            substring(securityPackage.length() + 1);
                    byte[] continueTokenBytes = Base64.decode(continueToken);
                    Sspi.SecBufferDesc continueTokenBuffer = new Sspi.
                            SecBufferDesc(Sspi.SECBUFFER_TOKEN, continueTokenBytes);
                    clientContext.initialize(clientContext.getHandle(), continueTokenBuffer, "localhost");
                    token = Base64.encode(clientContext.getToken());
                } catch (Exception e) {
                    log.error("Error while validating the NTLM authentication grant", e);
                    throw new IdentityOAuth2Exception("Error while validating the NTLM authentication grant", e);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("NTLM token is null");
            }
            throw new IdentityOAuth2Exception("NTLM token is null");
        }
        return authenticated;

    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.GrantTypes.IWA_NTLM);
    }
}
