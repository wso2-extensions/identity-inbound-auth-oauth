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
    public static final int MAX_LENGTH_OF_SCOPE_NAME = 255;
    public static final int MAX_LENGTH_OF_SCOPE_DISPLAY_NAME = 255;
    public static final int MAX_LENGTH_OF_SCOPE_DESCRIPTION = 512;
    public static final String SCOPE_ID = "SCOPE_ID";
    public static final String DEFAULT_SCOPE_BINDING = "DEFAULT";
    public static final String PERMISSIONS_BINDING_TYPE = "PERMISSION";
    public static final String SYSTEM_SCOPE = "SYSTEM";
    public static final String SCOPE_TYPE_OAUTH2 = "OAUTH2";
    public static final String SCOPE_TYPE_OIDC = "OIDC";
    public static final String CONSOLE_SCOPE_PREFIX = "console:";
    public static final String INTERNAL_SCOPE_PREFIX = "internal_";
    public static final String INTERNAL_ORG_SCOPE_PREFIX = "internal_org_";
    public static final String CORRELATION_ID_MDC = "Correlation-ID";

    /**
     * Enums for error messages.
     */
    public enum ErrorMessages {
        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED("41001", "Scope Name is not specified."),
        ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_NOT_SPECIFIED("41002", "Scope Display Name is not specified."),
        ERROR_CODE_NOT_FOUND_SCOPE("41003", "Scope %s is not found."),
        ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE("41004",
                "Scope with the name %s already exists in the system. Please use a different scope name."),
        ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE_OIDC("41004",
                "Scope with the name %s already exists as an OIDC scope in the system. Please use a different scope " +
                        "name."),
        ERROR_CODE_BAD_REQUEST_SCOPE_NOT_SPECIFIED("41005", "Scope is not specified."),
        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_CONTAINS_WHITESPACES("41006", "Scope name: %s contains white spaces."),
        ERROR_CODE_BAD_REQUEST("41007", "Invalid request"),
        ERROR_CODE_NOT_AUTHORIZED_ADD_INTERNAL_SCOPE("41008", "User %s is not authorized to add internal scopes"),
        ERROR_CODE_NOT_AUTHORIZED_UPDATE_INTERNAL_SCOPE("41009", "User %s is not authorized to update internal scopes"),
        ERROR_CODE_NOT_AUTHORIZED_DELETE_INTERNAL_SCOPE("41010", "User %s is not authorized to delete internal scopes"),
        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SATIFIED_THE_REGEX("41011", "Invalid scope name. Scope name %s cannot " +
                "contain special characters ?,#,/,( or )"),
        ERROR_CODE_INTERNAL_SCOPE_MANAGED_AT_SYSTEM_LEVEL("41012", "The internal scopes are managed at " +
                "system level"),
        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_TOO_LONG("41013", "Scope name: %s is too long. The maximum " +
                "allowed length is 255 characters."),
        ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_TOO_LONG("41014", "Scope display name: %s is too long. " +
                "The maximum allowed length is 255 characters."),
        ERROR_CODE_BAD_REQUEST_SCOPE_DESCRIPTION_TOO_LONG("41015", "Scope description: %s is too " +
                "long. The maximum allowed length is 512 characters."),
        ERROR_CODE_FAILED_TO_REGISTER_SCOPE("51001", "Error occurred while registering scope %s."),
        ERROR_CODE_FAILED_TO_GET_ALL_SCOPES("51002", "Error occurred while retrieving all available scopes."),
        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME("51003", "Error occurred while retrieving scope %s."),
        ERROR_CODE_FAILED_TO_DELETE_SCOPE_BY_NAME("51004", "Error occurred while deleting scope %s."),
        ERROR_CODE_FAILED_TO_UPDATE_SCOPE_BY_NAME("51005", "Error occurred while updating scope %s."),
        ERROR_CODE_FAILED_TO_GET_ALL_SCOPES_PAGINATION("51006",
                "Error occurred while retrieving scopes with pagination."),
        ERROR_CODE_UNEXPECTED("51007", "Unexpected error"),
        ERROR_CODE_FAILED_TO_GET_REQUESTED_SCOPES("51008", "Error occurred while retrieving requested scopes."),
        ERROR_CODE_FAILED_TO_RETRIEVE_USER_CONSENTS_FOR_APP("51009", "Error occurred while retrieving " +
                "user consent for OAuth scopes for user : %s, application : %s and tenant Id : %d."),
        ERROR_CODE_FAILED_TO_RETRIEVE_USER_CONSENTS("51010", "Error occurred while retrieving " +
                "user consents for OAuth scopes for user : %s in tenant with tenant Id : %d."),
        ERROR_CODE_FAILED_TO_ADD_USER_CONSENT_FOR_APP("51011", "Error occurred while adding " +
                "user consent for OAuth scopes for user : %s, application : %s and tenant Id : %d."),
        ERROR_CODE_FAILED_TO_UPDATE_USER_CONSENT_FOR_APP("51012", "Error occurred while updating " +
                "user consent for OAuth scopes for user : %s, application : %s and tenant Id : %d."),
        ERROR_CODE_FAILED_TO_REVOKE_USER_CONSENT_FOR_APP("51013", "Error occurred while revoking " +
                "user consent for OAuth scopes for user : %s, application : %s and tenant Id : %d."),
        ERROR_CODE_FAILED_TO_REVOKE_USER_CONSENT("51014", "Error occurred while revoking " +
                "user consent for OAuth scopes for user : %s in tenant with tenant Id : %d."),
        ERROR_CODE_FAILED_TO_CHECK_ALREADY_USER_CONSENTED("51015", "Error occurred while checking " +
                "whether user : %s is already consented for all scopes for application : %s in tenant with Id : %d."),
        ERROR_CODE_FAILED_TO_CHECK_EXISTING_CONSENTS_FOR_USER("51016", "Error occurred while checking " +
                "whether user : %s has an existing consent for app : %s in tenant with id : %d"),
        ERROR_CODE_FAILED_TO_GET_SCOPE_METADATA("51017", "Error occurred while retrieving scope metadata " +
                                                        "for scope %s.");
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
        public static final String SCOPE_TYPE = "scope_type";
        public static final String SCOPE_LIST_PLACEHOLDER = "_SCOPE_LIST_";
    }

    /**
     * Database types constants.
     */
    public static final class DataBaseType {
        public static final String ORACLE = "Oracle";
    }

}
