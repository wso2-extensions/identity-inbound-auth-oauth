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

package org.wso2.carbon.identity.oauth2.cimd;

/**
 * Thrown when a Client ID Metadata Document cannot be previewed. The error message is safe to return to the
 * caller; the cause is for the log only.
 */
public class ClientIdMetadataDocumentException extends Exception {

    private final ErrorMessage errorMessage;

    public ClientIdMetadataDocumentException(ErrorMessage errorMessage) {

        super(errorMessage.getMessage());
        this.errorMessage = errorMessage;
    }

    public ClientIdMetadataDocumentException(ErrorMessage errorMessage, Throwable cause) {

        super(errorMessage.getMessage(), cause);
        this.errorMessage = errorMessage;
    }

    public ErrorMessage getErrorMessage() {

        return errorMessage;
    }

    /**
     * Preview errors. Every failure before the document's client_id matches the requested URL is
     * {@link #NO_MATCHING_DOCUMENT}, so a preview reveals nothing about what an address serves.
     */
    public enum ErrorMessage {

        INVALID_CLIENT_ID_URL("CIMD-60001", "Invalid Client Identifier URL.",
                "The Client Identifier URL must be an https URL with a DNS host, the default port and a path, " +
                        "and no user information, query, fragment or dot segments."),
        NO_MATCHING_DOCUMENT("CIMD-60002", "Client metadata document not retrieved.",
                "No client metadata document whose client_id matches the URL could be retrieved from it."),
        INVALID_REDIRECT_URI("CIMD-60003", "Invalid redirect URI.",
                "Each redirect URI must be https on the same origin as the Client Identifier URL, or http " +
                        "on 127.0.0.1 or [::1]."),
        INVALID_CLIENT_AUTHENTICATION("CIMD-60004", "Unsupported client authentication.",
                "The token_endpoint_auth_method must be none, or private_key_jwt with an https jwks_uri. " +
                        "Client secrets are not supported."),
        INVALID_GRANT_TYPES("CIMD-60005", "Unsupported grant types.",
                "The grant_types must include authorization_code."),
        VALUE_TOO_LONG("CIMD-60006", "Value too long.",
                "A value in the client metadata document exceeds the length the server can store."),
        CIMD_DISABLED("CIMD-60007", "Client ID Metadata Documents are disabled.",
                "Client ID Metadata Document support is not enabled in this deployment."),
        TOO_MANY_PREVIEWS("CIMD-60008", "Too many previews in progress.",
                "Wait for the other client metadata document previews in this organization to finish.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessage(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }
}
