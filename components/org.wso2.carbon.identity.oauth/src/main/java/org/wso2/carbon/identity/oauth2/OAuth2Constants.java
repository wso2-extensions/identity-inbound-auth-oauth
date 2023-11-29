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
        public static final String CERTIFICATE_BASED_TOKEN_BINDER = "certificate";

    }
    public static final String GROUPS = "groups";
    public static final String ENTITY_ID = "entity_id";
    public static final String IS_CONSENTED = "is_consented";
    public static final String IS_FEDERATED = "is_federated";
    public static final boolean DEFAULT_PERSIST_ENABLED = true;
    public static final String OAUTH_TOKEN_PERSISTENCE_ENABLE = "OAuth.TokenPersistence.Enable";
    public static final String OAUTH_CODE_PERSISTENCE_ENABLE = "OAuth.EnableAuthCodePersistence";
    public static final String OAUTH_ENABLE_REVOKE_TOKEN_HEADERS = "OAuth.EnableRevokeTokenHeadersInResponse";

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
}
