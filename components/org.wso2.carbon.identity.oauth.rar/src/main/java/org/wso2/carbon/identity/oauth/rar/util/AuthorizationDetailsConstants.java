/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.rar.util;

/**
 * Stores constants related to OAuth2 Rich Authorization Requests.
 */
public final class AuthorizationDetailsConstants {

    public static final String AUTHORIZATION_DETAILS = "authorization_details";
    public static final String AUTHORIZATION_DETAILS_ID_PREFIX = "authorization_detail_id_";
    public static final String PARAM_SEPARATOR = "&&";
    public static final String TYPE_NOT_SUPPORTED_ERR_FORMAT = "%s is an unknown authorization details type value";
    public static final String TYPE_VALIDATION_FAILED_ERR_MSG_FORMAT =
            "The payload of the authorization details type '%s' contains errors: %s";
    public static final String SCHEMA_VALIDATION_FAILED_ERR_MSG_FORMAT =
            "The schema of the authorization details type contains errors: %s";
    public static final String VALIDATION_FAILED_ERR_MSG = "Authorization details validation failed";
    public static final String VALIDATION_FAILED_ERR_CODE = "invalid_authorization_details";
    public static final String EMPTY_JSON_OBJECT = "{}";
    public static final String EMPTY_JSON_ARRAY = "[]";

    private AuthorizationDetailsConstants() {
        // Private constructor to prevent instantiation
    }
}
