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

package org.wso2.carbon.identity.oauth.user;

/**
 * Exception for user info endpoint.
 */
public class UserInfoEndpointException extends Exception {

    public static final String ERROR_CODE_INVALID_SCHEMA = "invalid_schema";
    public static final String ERROR_CODE_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_CODE_INVALID_TOKEN = "invalid_token";
    public static final String ERROR_CODE_INSUFFICIENT_SCOPE = "insufficient_scope";
    private static final long serialVersionUID = -1057626324560880329L;
    private final String errorCode;
    private final String errorMessage;

    public UserInfoEndpointException(String errorCode, String errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public UserInfoEndpointException(String errorMessage) {
        super(errorMessage);
        errorCode = null;
        this.errorMessage = errorMessage;
    }

    public UserInfoEndpointException(String errorMessage, Throwable e) {
        super(errorMessage, e);
        errorCode = null;
        this.errorMessage = errorMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

}
