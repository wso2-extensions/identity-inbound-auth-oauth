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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.common;

/**
 * This class contains the default error codes for OAuth2 request.
 */
public class OAuth2ErrorCodes {

    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String SERVER_ERROR = "server_error";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String INVALID_CALLBACK = "invalid_callback";
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String LOGIN_REQUIRED = "login_required";
    public static final String TEMPORARY_UNAVAILABLE = "temporarily_unavailable";
    public static final String CONSENT_REQUIRED = "consent_required";

    private OAuth2ErrorCodes(){

    }

    /**
     * This class contains sub error codes for OAuth2 requests apart from the default error codes.
     */
    public class OAuth2SubErrorCodes {

        public static final String INVALID_PKCE_CHALLENGE_CODE = "invalid_pkce_challenge_code";
        public static final String INVALID_CLIENT = "invalid_client";
        public static final String INVALID_REDIRECT_URI = "invalid_redirect_uri";
        public static final String SESSION_TIME_OUT = "session_time_out";
        public static final String CERTIFICATE_ERROR = "certificate_error";
        public static final String INVALID_AUTHORIZATION_REQUEST = "invalid_authorization_request";
        public static final String INVALID_REQUEST_OBJECT = "invalid_request_object";
        public static final String UNEXPECTED_SERVER_ERROR = "unexpected_server_error";
        public static final String INVALID_REQUEST = "invalid_request";
        public static final String CONSENT_DENIED = "consent_denied";
        public static final String ACCESS_DENIED = "access_denied";
        public static final String INVALID_PARAMETERS = "invalid_parameters";

    }
}
