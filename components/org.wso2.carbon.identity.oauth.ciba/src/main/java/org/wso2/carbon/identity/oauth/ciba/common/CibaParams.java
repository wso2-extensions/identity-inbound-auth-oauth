/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.common;

/**
 * Contains the required constants for Ciba Feature.
 */
public class CibaParams {

    // Parameters required for authentication  requests and responses.
    public static final long INTERVAL_INCREMENT = 3;
    public static final long expiresIn = 3600;
    public static final long interval = 2;
    public static final long MAXIMUM_REQUESTED_EXPIRY = 3600;
    public static final String EXPIRES_IN = "expires_in";
    public static final String INTERVAL = "interval";
    public static final String AUTH_REQ_ID = "auth_req_id";
    public static final String REQUEST = "request";
    public static final String CLIENT_NOTIFICATION_TOKEN = "client_notification_token";
    public static final String ACR_VALUES = "acr";
    public static final String USER_CODE = "user_code";
    public static final String REQUESTED_EXPIRY = "requested_expiry";
    public static final String LOGIN_HINT = "login_hint";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String LOGIN_HINT_TOKEN = "login_hint_token";

    // Parameters for authorize request and to validate token request.
    public static final String OAUTH_CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    public static final String RESPONSE_TYPE_VALUE = "cibaAuthCode";
    public static final String CLIENT_ID = "client_id";
    public static final String STATE_PARAMATER = "state";
    public static final String USER_IDENTITY = "user";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String NONCE = "nonce";
    public static final String SCOPE = "scope";
    public static final String BINDING_MESSAGE = "binding_message";
    public static final String TRANSACTION_CONTEXT = "transaction_context";
    public static final String USER_HINT = "user_hint";

    private CibaParams() {

    }
}
