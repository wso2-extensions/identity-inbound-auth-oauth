/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth;

/**
 * Container for error codes related to OAuth consumer apps management.
 */
public enum Error {

    // Client errors starts with 60, server errors starts with 65.
    INVALID_REQUEST("60001"),
    INVALID_OAUTH_CLIENT("60002"),
    AUTHENTICATED_USER_NOT_FOUND("60003"),

    UNEXPECTED_SERVER_ERROR("65001");

    private static final String OAUTH_PREFIX = "OAUTH";
    private String errorCode;

    Error(String errorCode) {

        this.errorCode = errorCode;
    }

    public String getErrorCode() {

        return OAUTH_PREFIX + "-" + errorCode;
    }

    @Override
    public String toString() {

        return getErrorCode();
    }
}
