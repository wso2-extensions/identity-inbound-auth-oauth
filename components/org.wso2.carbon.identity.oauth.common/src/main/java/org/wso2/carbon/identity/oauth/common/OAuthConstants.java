/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.common;

public final class OAuthConstants {

    //OAuth2 request headers.
    public static final String HTTP_REQ_HEADER_AUTHZ = "Authorization";

    // OAuth2 response headers
    public static final String HTTP_RESP_HEADER_CACHE_CONTROL = "Cache-Control";
    public static final String HTTP_RESP_HEADER_PRAGMA = "Pragma";
    public static final String HTTP_RESP_HEADER_AUTHENTICATE = "WWW-Authenticate";

    // OAuth2 response header values
    public static final String HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE = "no-store";
    public static final String HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE = "no-cache";

    // OAuth response parameters
    public static final String OAUTH_TOKEN = "oauth_token";
    public static final String OAUTH_TOKEN_SECRET = "oauth_token_secret";
    public static final String OAUTH_CALLBACK_CONFIRMED = "oauth_callback_confirmed";
    public static final String OAUTH_VERIFIER = "oauth_verifier";
    public static final String OAUTHORIZED_USER = "oauthorized_user";
    public static final String APPLICATION_NAME = "application_name";
    public static final String OAUTH_USER_CONSUMER_KEY = "consumer_key";
    public static final String OAUTH_APP_CALLBACK = "callback_url";
    public static final String OAUTH_APP_CONSUMER_KEY = "consumer_key";
    public static final String OAUTH_APP_CONSUMER_SECRET = "consumer_secret";
    public static final String OAUTH_APP_NAME = "oauth_app_name";
    public static final String OAUTH_USER_NAME = "oauth_user_name";
    public static final String OAUTH_ACCESS_TOKEN_ISSUED = "oauth_access_token_issued";

    // Constants to be used by error pages
    public static final String OAUTH_ERROR_CODE = "oauthErrorCode";
    public static final String OAUTH_ERROR_MESSAGE = "oauthErrorMsg";

    // Constants for paging in OAuth UI
    public static final int DEFAULT_ITEMS_PER_PAGE = 10;
    public static final String OAUTH_ADMIN_CLIENT = "OAuthAdminClient";
    public static final String OAUTH_DATA_PAGE_COUNT = "OAuthDataPageCount";

    // Constants that are used with the authentication framework
    public static final String OIDC_LOGGED_IN_USER = "loggedInUser";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String SESSION_DATA_KEY_CONSENT = "sessionDataKeyConsent";
    public static final String OAUTH_CACHE_MANAGER = "OAuthCacheManager";

    // For storing SAML2 assertion in OAuthTokenReqMgtCtx
    public static final String OAUTH_SAML2_ASSERTION = "SAML2Assertion";
    public static final long UNASSIGNED_VALIDITY_PERIOD = -1L;
    public static final String ACCESS_TOKEN_STORE_TABLE = "IDN_OAUTH2_ACCESS_TOKEN";
    public static final int OAUTH_AUTHZ_CB_HANDLER_DEFAULT_PRIORITY = 1;
    public static final String DEFAULT_KEY_ALIAS = "Security.KeyStore.KeyAlias";

    // Custom grant handler profile constants
    public static final String OAUTH_SAML2_BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public static final String OAUTH_SAML1_BEARER_METHOD = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
    public static final String OAUTH_SAML2_BEARER_GRANT_ENUM = "SAML20_BEARER";
    public static final String OAUTH_IWA_NTLM_GRANT_ENUM = "IWA_NTLM";
    public static final String WINDOWS_TOKEN = "windows_token";

    // OAuth client authenticator properties
    public static final String CLIENT_AUTH_CREDENTIAL_VALIDATION = "StrictClientCredentialValidation";
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String ID_TOKEN = "id_token";
    public static final String AUTHZ_CODE = "AuthorizationCode";

    //OAuth PKCE request parameters
    public static final String OAUTH_PKCE_CODE_VERIFIER = "code_verifier";
    public static final String OAUTH_PKCE_CODE_CHALLENGE = "code_challenge";
    public static final String OAUTH_PKCE_CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String OAUTH_PKCE_S256_CHALLENGE = "S256";
    public static final String OAUTH_PKCE_PLAIN_CHALLENGE = "plain";
    //Response types
    public static final String NONE = "none";

    //Constants used for OAuth/OpenID Connect Configuration UI
    public static final String CALLBACK_URL_REGEXP_PREFIX = "regexp=";

    public static final String AUTHORIZATION_CODE_STORE_TABLE = "IDN_OAUTH2_AUTHORIZATION_CODE";

    public static class GrantTypes {
        public static final String IMPLICIT = "implicit";
        public static final String TOKEN = "token";

        private GrantTypes() {
        }
    }

    public static class OAuthVersions {
        public static final String VERSION_1A = "OAuth-1.0a";
        public static final String VERSION_2 = "OAuth-2.0";

        private OAuthVersions(){

        }
    }

    // OAuth1.0a request parameters
    public static class OAuth10AParams {
        public static final String OAUTH_VERSION = "oauth_version";
        public static final String OAUTH_NONCE = "oauth_nonce";
        public static final String OAUTH_TIMESTAMP = "oauth_timestamp";
        public static final String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
        public static final String OAUTH_CALLBACK = "oauth_callback";
        public static final String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
        public static final String OAUTH_SIGNATURE = "oauth_signature";
        public static final String SCOPE = "scope";
        public static final String OAUTH_DISPLAY_NAME = "xoauth_displayname";

        private OAuth10AParams(){

        }
    }

    // OAuth2.0 request parameters
    public static class OAuth20Params {
        public static final String SCOPE = "scope";
        public static final String PROMPT = "prompt";
        public static final String NONCE = "nonce";
        public static final String DISPLAY = "display";
        public static final String ID_TOKEN_HINT = "id_token_hint";
        public static final String LOGIN_HINT = "login_hint";
        private OAuth20Params(){

        }
    }

    // OIDC prompt values
    public static class Prompt {
        public static final String LOGIN = "login";
        public static final String CONSENT = "consent";
        public static final String NONE = "none";
        public static final String SELECT_ACCOUNT = "select_account";
        private Prompt(){

        }
    }

    // OAuth1.0a endpoints
    public static class OAuth10AEndpoints {
        public static final String ACCESS_TOKEN_URL = "/access-token";
        public static final String REQUEST_TOKEN_URL = "/request-token";
        public static final String AUTHORIZE_TOKEN_URL = "/authorize-token";

        private OAuth10AEndpoints(){

        }
    }

    // OAuth2.0 endpoints
    public static class OAuth20Endpoints {
        public static final String OAUTH20_ACCESS_TOKEN_URL = "/token";
        public static final String OAUTH20_AUTHORIZE_TOKEN_URL = "/authorize";

        private OAuth20Endpoints(){

        }
    }

    public static class Consent {
        public static final String DENY = "deny";
        public static final String APPROVE = "approve";
        public static final String APPROVE_ALWAYS = "approveAlways";

        private Consent(){

        }
    }

    public static class TokenStates {
        public static final String TOKEN_STATE_ACTIVE = "ACTIVE";
        public static final String TOKEN_STATE_REVOKED = "REVOKED";
        public static final String TOKEN_STATE_EXPIRED = "EXPIRED";

        private TokenStates(){

        }
    }

    public static class AuthorizationCodeState {
        public static final String ACTIVE = "ACTIVE";
        public static final String REVOKED = "REVOKED";
        public static final String EXPIRED = "EXPIRED";
        public static final String INACTIVE = "INACTIVE";

        private AuthorizationCodeState(){

        }
    }

    public static class OauthAppStates {
        public static final String APP_STATE_ACTIVE = "ACTIVE";
        public static final String APP_STATE_INACTIVE = "INACTIVE";
        public static final String APP_STATE_REVOKED = "REVOKED";

        private OauthAppStates(){

        }
    }

    public static class OAuthError {
        public static class TokenResponse {
            public static final String UNSUPPORTED_CLIENT_AUTHENTICATION_METHOD = "unsupported_client_authentication_method";

            private TokenResponse(){

            }
        }

        private OAuthError(){

        }
    }

    public static class Scope {
        public static final String OPENID = "openid";
        public static final String OAUTH2 = "oauth2";
        public static final String OIDC = "oidc";

        private Scope(){

        }
    }

    public static class UserType {
        public static final String APPLICATION = "APPLICATION";
        public static final String APPLICATION_USER = "APPLICATION_USER";
        private UserType(){

        }
    }

    private OAuthConstants(){

    }
}
