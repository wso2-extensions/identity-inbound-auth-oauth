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
    public static final String LOGIN_HINT = "login_hint";
    public static final String TRANSACTION_CONTEXT = "transaction_context";
    public static final String UTC = "UTC";
    public static final String EXPIRES_IN = "expires_in";
    public static final String CIBA_USER_AUTH_ENDPOINT = "/oauth2/ciba_auth";
    public static final String CIBA_AUTH_CODE_KEY = "authCodeKey";
    public static final String DEFAULT_CIBA_USER_LOGIN_TEMPLATE_NAME = "CIBAUserLoginRequest";
    public static final String CIBA_USER_LOGIN_LINK_PLACEHOLDER_NAME = "user-login-link";
    public static final String CIBA_BINDING_MESSAGE_PLACEHOLDER_NAME = "binding-message";
    public static final String CIBA_APP_PLACEHOLDER_NAME = "application-name";
    public static final String SMS_EVENT_TRIGGER_NAME = "TRIGGER_SMS_NOTIFICATION_LOCAL";
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String ARBITRARY_SEND_TO = "send-to";
    public static final String CIBA_SUCCESS_ENDPOINT_PATH = "/authenticationendpoint/device_success.do";
    public static final String PUSH_NOTIFICATION_CHANNEL = "PUSH_NOTIFICATION";
    public static final String NOTIFICATION_SCENARIO = "NOTIFICATION_SCENARIO";
    public static final String CIBA_NOTIFICATION_SCENARIO = "AUTHENTICATION";
    public static final String PUSH_ID = "pushId";
    public static final String DEVICE_TOKEN = "deviceToken";
    public static final String NOTIFICATION_PROVIDER = "notificationProvider";
    public static final String CHALLENGE = "challenge";
    public static final String DEVICE_ID = "deviceId";
    public static final String PUSH_NOTIFICATION_EVENT_NAME = "TRIGGER_PUSH_NOTIFICATION";

    private CibaConstants() {

    }
}
