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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.exceptions;

/**
 * Possess the error codes to be set in responses.
 */
public class ErrorCodes {

    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String UNKNOWN_USER_ID = "unknown_user_id";
    public static final String MISSING_USER_CODE = "missing_user_code";
    public static final String INVALID_USER_CODE = "invalid_user_code";
    public static final String INVALID_BINDING_MESSAGE = "invalid_binding_message";
    public static final String SLOW_DOWN = "slow_down";
    public static final String AUTHORIZATION_PENDING = "authorization_pending";
    public static final String EXPIRED_AUTH_REQ_ID = "expired_token";
    public static final String UNAUTHORIZED_USER = "unauthorized_user";

    private ErrorCodes() {

    }
}
