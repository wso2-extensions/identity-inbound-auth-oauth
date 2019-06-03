/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dcr;

public class DCRMConstants {

    public enum ErrorMessages {

        CONFLICT_EXISTING_APPLICATION("Application with the name %s already exist in the system"),
        FAILED_TO_REGISTER_SP("Error occurred while creating service provider %s" ),
        FAILED_TO_GET_SP("Error occurred while retrieving service provider %s" ),
        FAILED_TO_UPDATE_SP("Error occurred while updating service provider %s" ),
        FAILED_TO_DELETE_SP("Error occurred while deleting service provider %s" ),
        FAILED_TO_REGISTER_APPLICATION("Error occurred while creating application with application name:  %s" ),
        FAILED_TO_GET_APPLICATION("Error occurred while retrieving application with application name: %s" ),
        FAILED_TO_GET_APPLICATION_BY_ID("Error occurred while retrieving application with client key: %s" ),
        FAILED_TO_UPDATE_APPLICATION("Error occurred while updating application with client key: %s" ),
        BAD_REQUEST_INVALID_REDIRECT_URI("Invalid redirect URI: %s"),
        BAD_REQUEST_INVALID_BACKCHANNEL_LOGOUT_URI("Invalid back-channel logout URI: %s"),
        BAD_REQUEST_INVALID_SP_NAME("Client Name is not adhering to the regex: %s"),
        BAD_REQUEST_INVALID_SP_TEMPLATE_NAME("Invalid service provider template name: %s"),
        BAD_REQUEST_INVALID_INPUT("%s"),
        BAD_REQUEST_INSUFFICIENT_DATA("Insufficient data in the request"),
        NOT_FOUND_APPLICATION_WITH_ID("Application not available for given client key: %s"),
        NOT_FOUND_APPLICATION_WITH_NAME("Application not available for given client name: %s"),
        CONFLICT_EXISTING_CLIENT_ID("Client id %s already exist in the system"),
        BAD_REQUEST_CLIENT_ID_VIOLATES_PATTERN("Provided client id is not adhering to the provided regex %s"),
        FORBIDDEN_UNAUTHORIZED_USER("User does not have access to the application %s"),
        ERROR_CODE_UNEXPECTED("Unexpected error");


        private final String message;

        ErrorMessages(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }

    }

    public static class ErrorCodes {
        public static String INVALID_REDIRECT_URI = "invalid_redirect_uri";
        public static String INVALID_CLIENT_METADATA = "invalid_client_metadata";
        public static String INVALID_SOFTWARE_STATEMENT = "invalid_software_statement";
        public static String UNAPPROVED_SOFTWARE_STATEMENT = "unapproved_software_statement";
    }

    public static final String OAUTH2 = "oauth2";
}
