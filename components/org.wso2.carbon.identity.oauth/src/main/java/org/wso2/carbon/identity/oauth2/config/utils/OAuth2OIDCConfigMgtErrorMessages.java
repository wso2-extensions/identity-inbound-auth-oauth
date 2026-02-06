/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.config.utils;

/**
 * Error message enum for OAuth2 / OIDC config management Exceptions.
 */
public enum OAuth2OIDCConfigMgtErrorMessages {

    // Client Error Codes
    ERROR_CODE_OAUTH2_OIDC_CONFIG_EMPTY_PATCH_OBJECT("60001",
            "Unable to update OAuth2 / OIDC configurations.",
            "Provided OAuth2 / OIDC configuration patch object is empty for %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_CHANGE_REJECT("60002",
            "Unable to update OAuth2 / OIDC configurations.",
            "Cannot modify issuer usage scope. It is currently in use by sub-organization applications."),
    // Server Error Codes
    ERROR_CODE_OAUTH2_OIDC_CONFIG_RETRIEVE("65001",
            "Unable to retrieve OAuth2 / OIDC configurations.",
            "Server encountered an error while retrieving the OAuth2 / OIDC configurations of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_BUILD("65002",
            "Unable to retrieve OAuth2 / OIDC configurations.",
            "Server encountered an error while constructing the issuer of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_ADD("65003",
            "Unable to add OAuth2 / OIDC configurations.",
            "Server encountered an error while adding the issuer usage scope of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_UPDATE("65004",
            "Unable to update OAuth2 / OIDC configurations.",
            "Server encountered an error while updating the issuer usage scope of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ORG_RESOLVE("65005",
            "Unable to update OAuth2 / OIDC configurations.",
            "Server encountered an error while resolving the organization details of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_APP_RETRIEVE("65006",
            "Unable to update OAuth2 / OIDC configurations.",
            "Server encountered an error while retrieving the applications of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_APP_INFO_RETRIEVE("65007",
            "Unable to update OAuth2 / OIDC configurations.",
            "Server encountered an error while retrieving the application details."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_GET("65008",
            "Unable to get OAuth2 / OIDC configurations.",
            "Server encountered an error while retrieving the issuer usage scope of %s."),
    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_INVALID_SCOPE("65009",
            "Unable to resolve the issuer usage scope value.",
            "Server encountered an error while resolving the issuer usage value for %s.");

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


    OAuth2OIDCConfigMgtErrorMessages(String code, String message, String description) {
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
