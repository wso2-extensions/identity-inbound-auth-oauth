/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.validators.scope.constants;

public class Constants {

    public static final String ACTION_CATEGORY = "http://wso2.org/identity/identity-action";
    public static final String SP_CATEGORY = "http://wso2.org/identity/sp";
    public static final String USER_CATEGORY = "http://wso2.org/identity/user";
    public static final String SCOPE_CATEGORY = "http://wso2.org/identity/oauth-scope";

    public static final String AUTH_ACTION_ID = ACTION_CATEGORY + "/action-name";
    public static final String SP_NAME_ID = SP_CATEGORY + "/sp-name";
    public static final String USERNAME_ID = USER_CATEGORY + "/username";
    public static final String USER_STORE_ID = USER_CATEGORY + "/user-store-domain";
    public static final String USER_TENANT_DOMAIN_ID = USER_CATEGORY + "/user-tenant-domain";
    public static final String SCOPE_ID = SCOPE_CATEGORY + "/scope-name";

}
