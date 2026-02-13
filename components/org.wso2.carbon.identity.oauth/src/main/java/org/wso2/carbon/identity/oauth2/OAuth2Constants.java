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
    public static final String ENTITY_ID = "entity_id";
    public static final String TOKEN_ID = "token_id";
    public static final String IS_CONSENTED = "is_consented";
    public static final String IS_FEDERATED = "is_federated";
    public static final String USER_SESSION_ID = "usid";
    public static final boolean DEFAULT_PERSIST_ENABLED = true;
    public static final String OAUTH_TOKEN_PERSISTENCE_ENABLE = "OAuth.TokenPersistence.Enable";
    public static final String OAUTH_CODE_PERSISTENCE_ENABLE = "OAuth.EnableAuthCodePersistence";
    public static final String OAUTH_ENABLE_REVOKE_TOKEN_HEADERS = "OAuth.EnableRevokeTokenHeadersInResponse";
}
