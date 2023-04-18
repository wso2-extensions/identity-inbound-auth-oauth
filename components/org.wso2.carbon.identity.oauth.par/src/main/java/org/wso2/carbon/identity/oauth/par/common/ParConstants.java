/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.common;

/**
 * Contains the required constants for PAR feature.
 */
public class ParConstants {
    // Parameters required for authentication  requests and responses.
    public static final long INTERVAL_INCREMENT_VALUE_IN_SEC = 3;
    public static final long EXPIRES_IN_DEFAULT_VALUE_IN_SEC = 60; //according to PAR spec (60 seconds)
//    public static final String uuid = java.util.UUID.randomUUID().toString();
    public static final long INTERVAL_DEFAULT_VALUE_IN_SEC = 2;
    public static final long MAXIMUM_REQUESTED_EXPIRY_IN_SEC = 600; //according to PSR spec
    public static final long MAXIMUM_NOT_BEFORE_TIME_IN_SEC = 3600;
    public static final long SEC_TO_MILLISEC_FACTOR = 1000;
    public static final String INTERVAL = "interval";
    public static final String AUTH_REQ_ID = "auth_req_id";
    public static final String REQUEST = "request";
    public static final String CLIENT_NOTIFICATION_TOKEN = "client_notification_token";
    public static final String USER_CODE = "user_code";
    public static final String REQUESTED_EXPIRY = "requested_expiry";
    public static final String LOGIN_HINT_TOKEN = "login_hint_token";
    public static final String OAUTH_PAR_GRANT_TYPE = "urn:openid:params:grant-type:par";
    public static final String OAUTH_PAR_RESPONSE_TYPE = "par";
    public static final String RESPONSE_TYPE_VALUE = "parAuthCode";
    public static final String USER_IDENTITY = "user";
    public static final String BINDING_MESSAGE = "binding_message";
    public static final String TRANSACTION_CONTEXT = "transaction_context";
    public static final String UTC = "UTC";
    public static final String REQUEST_URI = "request_uri";
    public static final String EXPIRES_IN = "expires_in";


    private ParConstants() {

    }
}
