/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

/**
 * This class holds the constants used by OAuth2ScopeService.
 */
public class Oauth2ScopeConstants {

    public static final int MAX_FILTER_COUNT = 30;
    public static final int INVALID_SCOPE_ID = -1;
    public static final String SCOPE_ID = "SCOPE_ID";

    public enum ErrorMessages {
        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED("41001", "Scope Name is not specified."),
        ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_NOT_SPECIFIED("41002", "Scope Display Name is not specified."),
        ERROR_CODE_NOT_FOUND_SCOPE("41003", "Scope %s is not found."),
        ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE("41004",
                "Scope with the name %s already exists in the system. Please use a different scope name."),
        ERROR_CODE_BAD_REQUEST_SCOPE_NOT_SPECIFIED("41005", "Scope is not specified."),

        ERROR_CODE_FAILED_TO_REGISTER_SCOPE("51001", "Error occurred while registering scope %s."),
        ERROR_CODE_FAILED_TO_GET_ALL_SCOPES("51002", "Error occurred while retrieving all available scopes."),
        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME("51003", "Error occurred while retrieving scope %s."),
        ERROR_CODE_FAILED_TO_DELETE_SCOPE_BY_NAME("51004", "Error occurred while deleting scope %s."),
        ERROR_CODE_FAILED_TO_UPDATE_SCOPE_BY_NAME("51005", "Error occurred while updating scope %s."),
        ERROR_CODE_FAILED_TO_GET_ALL_SCOPES_PAGINATION("51006", "Error occurred while retrieving scopes with pagination."),
        ERROR_CODE_UNEXPECTED("51007", "Unexpected error");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return code + " - " + message;
        }

    }

    /**
     * SQL Placeholders
     */
    public static final class SQLPlaceholders {
        public static final String TENANT_ID = "tenant_id";

        public static final String LIMIT = "limit";
        public static final String OFFSET = "offset";
    }

    public static final class DataBaseType {
        public static final String ORACLE = "Oracle";
    }

}
