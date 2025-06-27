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
    public static final String CODE_ID = "code_id";
    public static final String IDN_OIDC_REQ_OBJECT_REFERENCE = "IDN_OIDC_REQ_OBJECT_REFERENCE";
    public static final String IDN_OIDC_REQ_OBJECT_CLAIMS = "STORE_IDN_OIDC_REQ_OBJECT_CLAIMS";
    public static final String HAS_NON_OIDC_CLAIMS = "hasNonOIDCClaims";
    public static final String ID_TOKEN_USER_CLAIMS_PROP_KEY = "IDTokenUserClaims";
    public static final String EXISTING_TOKEN_USED = "existingTokenUsed";

    /**
     * This class is used to define constants related to OIDC event specific features.
     */
    public class Event {

        public static final String CODE_ID = "CODE_ID";
        public static final String TOKEN_ID = "TOKEN_ID";
        public static final String SESSION_DATA_KEY = "SESSION_DATA_KEY";
        public static final String POST_ISSUE_CODE = "POST_ISSUE_CODE";
        public static final String POST_ISSUE_ACCESS_TOKEN = "POST_ISSUE_ACCESS_TOKEN";
        public static final String POST_ISSUE_TOKEN = "POST_ISSUE_TOKEN";
        public static final String HANDLE_REQUEST_OBJECT = "handleRequestObject";
        public static final String POST_REVOKE_ACESS_TOKEN = "POST_REVOKE_ACESS_TOKEN";
        public static final String POST_REVOKE_ACESS_TOKEN_BY_ID = "POST_REVOKE_ACESS_TOKEN_BY_ID";
        public static final String POST_REVOKE_CODE_BY_ID = "POST_REVOKE_CODE_BY_ID";
        public static final String POST_REVOKE_CODE = "POST_REVOKE_CODE";
        public static final String ACEESS_TOKENS = "ACEESS_TOKENS";
        public static final String CODES = "CODES";
        public static final String TOKEN_STATE = "TOKEN_STATE";
        public static final String GRANT_TYPE = "GRANT_TYPE";
        public static final String CLIENT_ID = "CLIENT_ID";
        public static final String TENANT_DOMAIN = "TENANT_DOMAIN";
        public static final String TOKEN_TYPE = "TOKEN_TYPE";
        public static final String NEW_ACCESS_TOKEN = "NEW_ACCESS_TOKEN";
        public static final String OLD_ACCESS_TOKEN = "OLD_ACCESS_TOKEN";
        public static final String POST_REFRESH_TOKEN = "POST_REFRESH_TOKEN";
        public static final String IS_REQUEST_OBJECT_FLOW = "IS_REQUEST_OBJECT_FLOW";
        public static final String TOKEN_CATEGORY = "TOKEN_CATEGORY";
        public static final String APP_RESIDENT_TENANT_ID = "APP_RESIDENT_TENANT_ID";
        public static final String ISSUED_TIME = "ISSUED_TIME";
        public static final String AUTHORIZED_ORGANIZATION_ID = "AUTHORIZED_ORGANIZATION_ID";
    }

    /**
     * This enum is used to define the token types used in OIDC.
     */
    public enum TokenBillingCategory {

        M2M_ACCESS_TOKEN
    }
}

