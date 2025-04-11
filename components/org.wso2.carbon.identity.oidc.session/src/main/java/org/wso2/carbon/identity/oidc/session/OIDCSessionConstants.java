/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session;

/**
 * Contains the constants related to OIDC session.
 */
public class OIDCSessionConstants {

    public static final String OPBS_COOKIE_ID = "opbs";
    public static final String TENANT_QUALIFIED_OPBS_COOKIE_SUFFIX = "-v2";

    // Request Parameters
    public static final String OIDC_CLIENT_ID_PARAM = "client_id";
    public static final String OIDC_REDIRECT_URI_PARAM = "redirect_uri";
    public static final String OIDC_SESSION_STATE_PARAM = "session_state";
    public static final String OIDC_LOGOUT_CONSENT_PARAM = "consent";
    public static final String OIDC_ID_TOKEN_HINT_PARAM = "id_token_hint";
    public static final String OIDC_TENANT_DOMAIN_PARAM = "tenant_domain";
    public static final String OIDC_POST_LOGOUT_REDIRECT_URI_PARAM = "post_logout_redirect_uri";
    public static final String OIDC_STATE_PARAM = "state";
    public static final String OIDC_SESSION_DATA_KEY_PARAM = "sessionDataKey";
    public static final String OIDC_LOGOUT_CONSENT_DENIAL_REDIRECT_URL = "OAuth.OpenIDConnect" +
            ".RedirectToPostLogoutUriOnConsentDenial";

    public static final String OIDC_CACHE_CLIENT_ID_PARAM = "client_id";
    public static final String OIDC_CACHE_TENANT_DOMAIN_PARAM = "tenant_domain";

    public static final String OIDC_ID_TOKEN_AZP_CLAIM = "azp";

    /**
     * Contains the constants related to OIDC config elements.
     */
    public static class OIDCConfigElements {

        public static final String OIDC_LOGOUT_CONSENT_PAGE_URL = "OIDCLogoutConsentPage";
        public static final String OIDC_LOGOUT_PAGE_URL = "OIDCLogoutPage";
        public static final String V2 = "V2";
        public static final String HANDLE_ALREADY_LOGGED_OUT_SESSIONS_GRACEFULLY =
                "HandleAlreadyLoggedOutSessionsGracefully";
    }

    /**
     * Contains the constants related to OIDC endpoints.
     */
    public static class OIDCEndpoints {

        public static final String OIDC_SESSION_IFRAME_ENDPOINT = "/oidc/checksession";
        public static final String OIDC_LOGOUT_ENDPOINT = "/oidc/logout";
    }

    /**
     * Contains the constants related to OIDC logout request sender.
     */
    public static class OIDCLogoutRequestConstants {

        public static final String POOL_SIZE = "OAuth.OpenIDConnect.LogoutRequestSender.PoolSize";
        public static final String KEEP_ALIVE_TIME = "OAuth.OpenIDConnect.LogoutRequestSender.KeepAliveTime";
        public static final String HTTP_CONNECT_TIMEOUT = "OAuth.OpenIDConnect.LogoutRequestSender.HttpConnectTimeout";
        public static final String HTTP_SOCKET_TIMEOUT = "OAuth.OpenIDConnect.LogoutRequestSender.HttpSocketTimeout";

        public static final String DEFAULT_POOL_SIZE = "2";
        public static final String DEFAULT_KEEP_ALIVE_TIME = "60000";
        public static final String DEFAULT_HTTP_CONNECT_TIMEOUT = "10000";
        public static final String DEFAULT_HTTP_SOCKET_TIMEOUT = "20000";
    }

    private OIDCSessionConstants() {

    }
}
