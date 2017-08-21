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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class BasicAuthClientAuthHandler extends AbstractClientAuthHandler {

    private static Log log = LogFactory.getLog(BasicAuthClientAuthHandler.class);

    @Override
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        boolean isAuthenticated = super.authenticateClient(tokReqMsgCtx);

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

}
