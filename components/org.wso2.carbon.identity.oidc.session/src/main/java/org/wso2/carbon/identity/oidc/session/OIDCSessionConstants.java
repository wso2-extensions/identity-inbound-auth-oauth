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

public class OIDCSessionConstants {

    public static final String OPBS_COOKIE_ID = "opbs";

    // Request Parameters
    public static final String OIDC_CLIENT_ID_PARAM = "client_id";
    public static final String OIDC_REDIRECT_URI_PARAM = "redirect_uri";
    public static final String OIDC_SESSION_STATE_PARAM = "session_state";
    public static final String OIDC_LOGOUT_CONSENT_PARAM = "consent";
    public static final String OIDC_ID_TOKEN_HINT_PARAM = "id_token_hint";
    public static final String OIDC_POST_LOGOUT_REDIRECT_URI_PARAM = "post_logout_redirect_uri";
    public static final String OIDC_STATE_PARAM = "state";
    public static final String OIDC_SESSION_DATA_KEY_PARAM = "sessionDataKey";

    public static final String OIDC_CACHE_CLIENT_ID_PARAM = "client_id";

    public static final String OIDC_ID_TOKEN_AZP_CLAIM = "azp";

    public static class OIDCConfigElements {
        public static final String OIDC_LOGOUT_CONSENT_PAGE_URL = "OIDCLogoutConsentPage";
        public static final String OIDC_LOGOUT_PAGE_URL = "OIDCLogoutPage";
        public static final String HANDLE_ALREADY_LOGGED_OUT_SESSIONS_GRACEFULLY =
                "HandleAlreadyLoggedOutSessionsGracefully";
    }

    public static class OIDCEndpoints {
        public static final String OIDC_SESSION_IFRAME_ENDPOINT = "/oidc/checksession";
        public static final String OIDC_LOGOUT_ENDPOINT = "/oidc/logout";
    }

    private OIDCSessionConstants() {
    }
}
