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
        public static final String CLIENT_REQUEST = "client-request";

    }

    /**
     * Constants for token types.
     */
    public static class TokenTypes {

        public static final String OPAQUE = "Opaque";
        public static final String JWT = "jwt";
    }

    public static final String GROUPS = "groups";
    public static final String ENTITY_ID = "entity_id";
    public static final String IS_CONSENTED = "is_consented";
    public static final String IS_FEDERATED = "is_federated";
    public static final boolean DEFAULT_PERSIST_ENABLED = true;
    public static final String OAUTH_TOKEN_PERSISTENCE_ENABLE = "OAuth.TokenPersistence.Enable";
    public static final String OAUTH_CODE_PERSISTENCE_ENABLE = "OAuth.EnableAuthCodePersistence";
    public static final String OAUTH_ENABLE_REVOKE_TOKEN_HEADERS = "OAuth.EnableRevokeTokenHeadersInResponse";
    public static final String IMPERSONATED_REFRESH_TOKEN_ENABLE = "OAuth.ImpersonatedRefreshToken.Enable";
    public static final boolean DEFAULT_IMPERSONATED_REFRESH_TOKEN_ENABLED = true;
    public static final String CONSOLE_CALLBACK_URL_FROM_SERVER_CONFIGS = "Console.CallbackURL";
    public static final String MY_ACCOUNT_CALLBACK_URL_FROM_SERVER_CONFIGS = "MyAccount.CallbackURL";
    public static final String TENANT_DOMAIN_PLACEHOLDER = "{TENANT_DOMAIN}";
    public static final String AGENT_IDENTITY_ENABLE = "AgentIdentity.Enabled";
    public static final String AGENT_IDENTITY_USERSTORE_NAME = "AgentIdentity.Userstore";
    public static final String DEFAULT_AGENT_IDENTITY_USERSTORE_NAME = "AGENT";
    public static final String STORE_OPERATION = "STORE";

    public static final int MAX_ALLOWED_LENGTH = 256;

    public static final boolean DEFAULT_ACCESS_TOKEN_PERSIST_ENABLED = true;
    public static final String OAUTH_ACCESS_TOKEN_PERSISTENCE_ENABLE = "OAuth.TokenPersistence.PersistAccessToken";
    public static final boolean DEFAULT_KEEP_REVOKED_ACCESS_TOKEN_LIST = true;
    public static final String OAUTH_KEEP_REVOKED_ACCESS_TOKEN_LIST = "OAuth.TokenPersistence.KeepRevokedAccessTokens";
    public static final boolean DEFAULT_REFRESH_TOKEN_PERSIST_ENABLED = true;
    public static final String OAUTH_REFRESH_TOKEN_PERSISTENCE_ENABLE = "OAuth.TokenPersistence.PersistRefreshToken";
    public static final String REFRESH_TOKEN_SCOPE_CLAIM_KEY = "rt_scope";
    public static final String TOKEN_ID = "token_id";

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
     * This class define static variables for column names in db.
     */
    public static class OAuthColumnName {

        public static final String ACCESS_TOKEN = "ACCESS_TOKEN";
        public static final String TOKEN_SCOPE = "TOKEN_SCOPE";
        public static final String REFRESH_TOKEN = "REFRESH_TOKEN";
        public static final String TOKEN_ID = "TOKEN_ID";
        public static final String TENANT_ID = "TENANT_ID";
        public static final String AUTHZ_USER = "AUTHZ_USER";
        public static final String SUBJECT_IDENTIFIER = "SUBJECT_IDENTIFIER";
        public static final String USER_DOMAIN = "USER_DOMAIN";
        public static final String AUTHENTICATED_IDP_NAME = "NAME";
        public static final String AUTHORIZED_ORGANIZATION = "AUTHORIZED_ORGANIZATION";
        public static final String TOKEN_BINDING_REF = "TOKEN_BINDING_REF";
        public static final String TIME_CREATED = "TIME_CREATED";
        public static final String REFRESH_TOKEN_TIME_CREATED = "REFRESH_TOKEN_TIME_CREATED";
        public static final String VALIDITY_PERIOD = "VALIDITY_PERIOD";
        public static final String REFRESH_TOKEN_VALIDITY_PERIOD = "REFRESH_TOKEN_VALIDITY_PERIOD";
        public static final String USER_TYPE = "USER_TYPE";
    }
}
