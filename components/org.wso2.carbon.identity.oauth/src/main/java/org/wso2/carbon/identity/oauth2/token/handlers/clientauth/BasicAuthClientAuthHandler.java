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

package org.wso2.carbon.identity.oauth2.token.handlers.clientauth;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class BasicAuthClientAuthHandler extends AbstractClientAuthHandler {

    private static Log log = LogFactory.getLog(BasicAuthClientAuthHandler.class);

    @Override
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        boolean isAuthenticated = super.authenticateClient(tokReqMsgCtx);

        if (!isAuthenticated && StringUtils.isEmpty(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId())) {
            return false;
        }
        if (!isAuthenticated) {
            OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO =
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO();
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticating client: " + oAuth2AccessTokenReqDTO.getClientId() + " with client " +
                            "secret.");
                }
                return OAuth2Util.authenticateClient(oAuth2AccessTokenReqDTO.getClientId(),
                        oAuth2AccessTokenReqDTO.getClientSecret());
            } catch (IdentityOAuthAdminException e) {
                throw new IdentityOAuth2Exception("Error while authenticating client", e);
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Invalid Client : " + oAuth2AccessTokenReqDTO.getClientId(), e);
            }
        } else {
            return true;
        }

    }

    @Override
    public boolean canAuthenticate(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        if (super.canAuthenticate(tokReqMsgCtx)) {
            return true;
        } else {
            HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
            if (httpRequestHeaders != null) {
                for (HttpRequestHeader header : httpRequestHeaders) {
                    if (HTTPConstants.HEADER_AUTHORIZATION.equalsIgnoreCase(header.getName()) && header.getValue()
                            .length > 0 && StringUtils.isNotEmpty(header.getValue()[0]) && header.getValue()[0]
                            .contains("Basic")) {
                        String[] splitValues = header.getValue()[0].trim().split(" ");
                        if (splitValues.length == 2) {
                            byte[] decodedBytes = Base64Utils.decode(splitValues[1].trim());
                            String userNamePassword = new String(decodedBytes, Charsets.UTF_8);
                            String[] credentials = userNamePassword.split(":");
                            if (credentials.length == 2) {
                                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setClientId(credentials[0]);
                                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setClientSecret(credentials[1]);
                            }
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
