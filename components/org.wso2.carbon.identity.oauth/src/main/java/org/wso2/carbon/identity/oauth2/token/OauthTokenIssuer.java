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


package org.wso2.carbon.identity.oauth2.token;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;

public interface OauthTokenIssuer {

    String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException;

    String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException;

    String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException;

    String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException;

    String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException;

    /**
     * This is used to generate a hash of the access token. Eg. when JWTTokenIssuer is used, use JWTID as the hash
     * @param accessToken Access Token
     * @return hash of the access token
     * @throws OAuthSystemException {@link OAuthSystemException} OAuth System Exception.
     */
    default String getAccessTokenHash(String accessToken) throws OAuthSystemException {
        return accessToken;
    }

    /**
     * Renew access token per request
     * @return true if new access token per each request
     */
    default boolean renewAccessTokenPerRequest() {
        return false;
    }
}
