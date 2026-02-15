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
 * Contains the required constants for CIBA feature.
 */
public class CibaConstants {

    // Parameters required for authentication  requests and responses.
    public static final long INTERVAL_INCREMENT_VALUE_IN_SEC = 3;
    public static final long EXPIRES_IN_DEFAULT_VALUE_IN_SEC = 3600;
    public static final long INTERVAL_DEFAULT_VALUE_IN_SEC = 2;
    public static final long MAXIMUM_REQUESTED_EXPIRY_IN_SEC = 3600;
    public static final long MAXIMUM_NOT_BEFORE_TIME_IN_SEC = 3600;
    public static final long SEC_TO_MILLISEC_FACTOR = 1000;
    public static final String INTERVAL = "interval";
    public static final String AUTH_REQ_ID = "auth_req_id";
    public static final String REQUEST = "request";
    public static final String CLIENT_NOTIFICATION_TOKEN = "client_notification_token";
    public static final String USER_CODE = "user_code";
    public static final String REQUESTED_EXPIRY = "requested_expiry";
    public static final String LOGIN_HINT_TOKEN = "login_hint_token";
    public static final String OAUTH_CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    public static final String OAUTH_CIBA_RESPONSE_TYPE = "ciba";
    public static final String RESPONSE_TYPE_VALUE = "cibaAuthCode";
    public static final String USER_IDENTITY = "user";
    public static final String BINDING_MESSAGE = "binding_message";
    public static final String TRANSACTION_CONTEXT = "transaction_context";
    public static final String UTC = "UTC";
    public static final String EXPIRES_IN = "expires_in";
    public static final String NOTIFICATION_CHANNEL = "notification_channel";
    public static final String AUTH_URL = "auth_url";

    // CIBA User Authentication Endpoint constants.
    public static final String CIBA_AUTH_CODE_KEY = "authCodeKey";
    public static final String CIBA_USER_AUTH_ENDPOINT = "/oauth2/ciba_authorize";
    public static final String CIBA_SUCCESS_ENDPOINT_PATH = "/authenticationendpoint/device_success.do";

    private CibaConstants() {

    }

    /**
     * Contains the constants related to CIBA notification channels.
     */
    public static class CibaNotificationChannel {

        public static final String EMAIL = "email";
        public static final String SMS = "sms";
        public static final String EXTERNAL = "external";
    }
}
