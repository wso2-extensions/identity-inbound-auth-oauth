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

/**
 * This class holds the constants used by DCRM component.
 */
public class DCRMConstants {

    public static final String CORRELATION_ID_MDC = "Correlation-ID";

    /**
     * Enum for OAuth DCR service related error messages.
     */
    public enum ErrorMessages {

        CONFLICT_EXISTING_APPLICATION("Application with the name %s already exist in the system"),
        FAILED_TO_REGISTER_SP("Error occurred while creating service provider %s"),
        FAILED_TO_GET_SP("Error occurred while retrieving service provider %s"),
        FAILED_TO_UPDATE_SP("Error occurred while updating service provider %s"),
        FAILED_TO_DELETE_SP("Error occurred while deleting service provider %s"),
        FAILED_TO_REGISTER_APPLICATION("Error occurred while creating application with application name:  %s"),
        FAILED_TO_GET_APPLICATION("Error occurred while retrieving application with application name: %s"),
        FAILED_TO_GET_APPLICATION_BY_ID("Error occurred while retrieving application with client key: %s"),
        FAILED_TO_UPDATE_APPLICATION("Error occurred while updating application with client key: %s"),
        BAD_REQUEST_INVALID_REDIRECT_URI("Invalid redirect URI: %s"),
        BAD_REQUEST_INVALID_BACKCHANNEL_LOGOUT_URI("Invalid back-channel logout URI: %s"),
        BAD_REQUEST_INVALID_SP_NAME("Client Name is not adhering to the regex: %s"),
        BAD_REQUEST_INVALID_SP_TEMPLATE_NAME("Invalid service provider template name: %s"),
        BAD_REQUEST_INVALID_INPUT("%s"),
        BAD_REQUEST_INSUFFICIENT_DATA("Insufficient data in the request"),
        NOT_FOUND_APPLICATION_WITH_ID("Application not available for given client key: %s"),
        NOT_FOUND_APPLICATION_WITH_NAME("Application not available for given client name: %s"),
        NOT_FOUND_OAUTH_APPLICATION_WITH_NAME("OAuth application not available for given client name: %s"),
        CONFLICT_EXISTING_CLIENT_ID("Client id %s already exist in the system"),
        BAD_REQUEST_CLIENT_ID_VIOLATES_PATTERN("Provided client id is not adhering to the provided regex %s"),
        FORBIDDEN_UNAUTHORIZED_USER("User does not have access to the application %s"),
        ERROR_CODE_UNEXPECTED("Unexpected error"),
        TENANT_DOMAIN_MISMATCH("NOT_FOUND_60001", "Tenant domain in request does not match with the application " +
                "tenant domain for consumer key: %s"),
        FAILED_TO_VALIDATE_TENANT_DOMAIN("Error occurred during validating tenant domain for consumer key: %s"),
        FAILED_TO_GET_TENANT_ADMIN("Error occurred during white getting tenant admin."),
        SIGNATURE_VALIDATION_FAILED("Signature validation failed for the software statement"),
        MANDATORY_SOFTWARE_STATEMENT("Mandatory software statement is missing"),
        FAILED_TO_READ_SSA("Error occurred while reading the software statement"),
        ADDITIONAL_ATTRIBUTE_ERROR("Error occurred while handling additional attributes");

        private final String message;
        private final String errorCode;

        ErrorMessages(String message) {

            this.message = message;
            this.errorCode = null;
        }

        ErrorMessages(String errorCode, String message) {

            this.message = message;
            this.errorCode = errorCode;
        }

        public String getMessage() {

            return message;
        }

        public String getErrorCode() {

            return errorCode;
        }
    }

    /**
     * OAuth DCR service related error codes.
     */
    public static class ErrorCodes {

        public static final String INVALID_REDIRECT_URI = "invalid_redirect_uri";
        public static final String INVALID_CLIENT_METADATA = "invalid_client_metadata";
        public static final String INVALID_SOFTWARE_STATEMENT = "invalid_software_statement";
        public static final String UNAPPROVED_SOFTWARE_STATEMENT = "unapproved_software_statement";
    }

    public static final String OAUTH2 = "oauth2";
    public static final String DCR_CONFIG_RESOURCE_TYPE_NAME = "DCR_CONFIGURATION";
    public static final String DCR_CONFIG_RESOURCE_NAME = "TENANT_DCR_CONFIGURATION";
    public static final String ENABLE_FAPI_ENFORCEMENT = "enableFapiEnforcement";
    public static final String CLIENT_AUTHENTICATION_REQUIRED = "clientAuthenticationRequired";
    public static final String SSA_JWKS = "ssaJwks";
    public static final String MANDATE_SSA = "mandateSSA";

    /**
     * Enum for DCR Configuration related error messages.
     */
    public enum DCRConfigErrorMessage {

        /**
         * Unable to retrieve DCR configuration.
         */
        ERROR_CODE_DCR_CONFIGURATION_RETRIEVE("65020",
                "Unable to retrieve DCR configuration.",
                "Server encountered an error while retrieving the DCR configuration of %s."),

        /**
         * SSA JWKS not found.
         */
        ERROR_CODE_SSA_JWKS_REQUIRED("65021",
                "SSA JWKS not found.",
                "SSA JWKS url is required to mandate SSA validation."),

        /**
         * SSA not Mandated Error.
         */
        ERROR_CODE_SSA_NOT_MANDATED("65022",
                                             "SSA not mandated.",
                                             "Authentication is disabled but mandateSSA is not set to True.");

        /**
         * The error code.
         */
        private final String code;

        /**
         * The error message.
         */
        private final String message;

        /**
         * The error description.
         */
        private final String description;


        DCRConfigErrorMessage(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        /**
         * Get the {@code code}.
         *
         * @return Returns the {@code code} to be set.
         */
        public String getCode() {

            return code;
        }

        /**
         * Get the {@code message}.
         *
         * @return Returns the {@code message} to be set.
         */
        public String getMessage() {

            return message;
        }

        /**
         * Get the {@code description}.
         *
         * @return Returns the {@code description} to be set.
         */
        public String getDescription() {

            return description;
        }

        @Override
        public String toString() {

            return code + ":" + message;
        }
    }
}
