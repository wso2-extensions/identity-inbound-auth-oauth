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

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Properties;

public interface ClientAuthenticationHandler {

    /**
     * Initialize the OAuth 2.0 client authentication handler
     *
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception Error when initializing the OAuth 2.0 client authentication handler.
     */
    public void init(Properties properties) throws IdentityOAuth2Exception;

    /**
     * Tells if the request contains required information for the OAuth 2.0 client to be authenticated
     *
     * @return <Code>true</Code>|<Code>false</Code> if the client can be authenticated or not.
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception Error when finding out if the OAuth 2.0 client can be authenticated.
     */
    public boolean canAuthenticate(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception;

    /**
     * Authenticate the OAuth 2.0 client
     *
     * @return <Code>true</Code>|<Code>false</Code> if the client authentication succeeded or not.
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception Error when validating the OAuth 2.0 client.
     */
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception;

    /**
     * Extract the client-id from the token message context for the implemented auth mechanism
     * @param tokReqMsgCtx
     * @return client-id that can be identified by the given authentication mechanism
     */
    default public String getClientId(OAuthTokenReqMessageContext tokReqMsgCtx){
        return tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
    }

}
