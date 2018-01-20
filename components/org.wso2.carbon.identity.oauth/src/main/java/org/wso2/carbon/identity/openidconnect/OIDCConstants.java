/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect;

/**
 * This class is used to define constants related to OIDC specific features.
 */
public class OIDCConstants {

    public static final String USERINFO = "userinfo";
    public static final String ID_TOKEN = "id_token";
    public static final String IDN_OIDC_REQ_OBJECT_REFERENCE = "IDN_OIDC_REQ_OBJECT_REFERENCE";
    public static final String IDN_OIDC_REQ_OBJECT_CLAIMS = "STORE_IDN_OIDC_REQ_OBJECT_CLAIMS";

    public class Event {

        public static final String CODE_ID = "CODE_ID";
        public static final String TOKEN_ID = "TOKEN_ID";
        public static final String SESSION_DATA_KEY = "SESSION_DATA_KEY";
        public static final String POST_ISSUE_CODE = "POST_ISSUE_CODE";
        public static final String POST_ISSUE_ACCESS_TOKEN = "POST_ISSUE_ACCESS_TOKEN";
        public static final String PERSIST_REQUEST_OBJECT = "persistRequestObject";
        public static final String REVOKE_REQUEST_OBJECT = "revokeRequestObject";
        public static final String POST_REVOKE_ACESS_TOKEN = "POST_REVOKE_ACESS_TOKEN";
        public static final String POST_REVOKE_ACESS_TOKEN_BY_ID = "POST_REVOKE_ACESS_TOKEN_BY_ID";
        public static final String POST_REVOKE_CODE_BY_ID = "POST_REVOKE_CODE_BY_ID";
        public static final String POST_REVOKE_CODE = "POST_REVOKE_CODE";
        public static final String ACEESS_TOKENS = "ACEESS_TOKENS";
        public static final String CODES = "CODES";
    }
}

