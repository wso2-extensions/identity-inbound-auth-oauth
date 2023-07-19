/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2;

/**
 * This class contains the constants required by the OAuth2 components.
 */
public class OAuth2Constants {

    /**
     * Constants for access token binders.
     */
    public static class TokenBinderType {

        public static final String SSO_SESSION_BASED_TOKEN_BINDER = "sso-session";
        public static final String COOKIE_BASED_TOKEN_BINDER = "cookie";

    }
    public static final String GROUPS = "groups";


    /**
     * Constants for global role based scope issuer.
     */
    public static class RoleBasedScope {

        public static final String GROUPS = "groups";

        public static final String OAUTH2_DEFAULT_SCOPE = "default";

        public static final String CHECK_ROLES_FROM_SAML_ASSERTION = "checkRolesFromSamlAssertion";

        public static final String
                RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION = "retrieveRolesFromUserStoreForScopeValidation";

        public static final String SAML2_ASSERTION = "SAML2Assertion";

        public static final String ROLE_CLAIM = "ROLE_CLAIM";

        public static final String OAUTH_ASSERTION = "assertion";

        public static final String ROLE_ATTRIBUTE_NAME = "http://wso2.org/claims/role";

        public static final String SAML2_SSO_AUTHENTICATOR_NAME = "SAML2SSOAuthenticator";

        public static final String ROLE_CLAIM_ATTRIBUTE = "RoleClaimAttribute";

        public static final String ATTRIBUTE_VALUE_SEPERATER = ",";

        public static final String ATTRIBUTE_VALUE_SEPARATOR = "AttributeValueSeparator";

        public static final String APIM_SCOPE_PREFIX = "apim:";

        public static final String APIM_ANALYTICS_SCOPE_PREFIX = "apim_analytics:";

        public static final String APIM_SERVICE_CATALOG_PREFIX = "service_catalog:";
    }

    /**
     * Constants related to OAuth2 log management.
     */
    public static class LogConstants {

        public static final String OAUTH_INBOUND_SERVICE = "oauth-inbound-service";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String SCOPE_VALIDATION = "scope-validation";
            public static final String ISSUE_ACCESS_TOKEN = "issue-access-token";
            public static final String ISSUE_ID_TOKEN = "issue-id-token";
            public static final String VALIDATE_AUTHORIZATION_CODE = "validate-authz-code";
            public static final String ISSUE_AUTHZ_CODE = "issue-authz-code";

        }

        /**
         * Define common and reusable Input keys for diagnostic logs.
         */
        public static class InputKeys {

            public static final String SCOPE_VALIDATOR = "scope validator";
            public static final String REQUESTED_SCOPES = "requested scopes";
            public static final String AUTHORIZED_SCOPES = "authorized scopes";
            public static final String GRANT_TYPE = "grant type";
            public static final String AUTHORIZATION_CODE = "authorization code";

        }
    }
}
