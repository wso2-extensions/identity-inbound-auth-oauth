/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.util;


/**
 * Constants used in OAuth Endpoint.
 */
public class EndpointConstants {

    private EndpointConstants() {
        // To prevent instantiation.
    }

    /**
     * Constants related to OAuth Endpoint log management.
     */
    public static class LogConstants {

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String RECEIVE_CONSENT_RESPONSE = "receive-consent-response";
            public static final String RECEIVE_TOKEN_REQUEST = "receive-token-request";
            public static final String RECEIVE_AUTHENTICATION_RESPONSE = "receive-authn-response";
            public static final String VALIDATE_AUTHENTICATION_RESPONSE = "validate-authn-status";
            public static final String RECEIVE_AUTHORIZATION_RESPONSE = "receive-authz-request";
            public static final String HANDLE_AUTHORIZATION = "handle-authorization";
            public static final String VALIDATE_SCOPES_BEFORE_CONSENT = "validate-scopes-before-consent";
            public static final String HAND_OVER_TO_FRAMEWORK = "hand-over-to-framework";
            public static final String PERSIST_OAUTH_SCOPE_CONSENT = "persist-oauth-scope-consent";
            public static final String GENERATE_CONSENT_CLAIMS = "generate-consent-claims";
        }

        /**
         * Define common and reusable Input keys for diagnostic logs.
         */
        public static class InputKeys {

            public static final String RESPONSE_TYPE = "response type";
        }
    }
}
