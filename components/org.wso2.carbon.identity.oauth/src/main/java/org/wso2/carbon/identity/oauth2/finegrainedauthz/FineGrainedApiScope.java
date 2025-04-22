/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.finegrainedauthz;

import java.util.HashMap;
import java.util.Map;

/**
 * This class is used to resolve the fine-grained API scopes for operations.
 */
public class FineGrainedApiScope {

    private static final Map<String, String> SCOPE_MAP = new HashMap<>();

    public static final String USER_ASSIGNMENT_INTO_GROUP = "user_assignment_into_group";
    public static final String USER_ASSIGNMENT_INTO_ROLE = "user_assignment_into_role";
    public static final String GROUP_ASSIGNMENT_INTO_ROLE = "group_assignment_into_role";
    public static final String GROUP_METADATA_UPDATE = "group_metadata_update";
    public static final String ROLE_UPDATE_PERMISSIONS = "role_update_permissions";
    public static final String ROLE_UPDATE_NAME = "role_update_name";
    public static final String USER_CREATION = "create_user";
    public static final String USER_DELETION = "delete_user";
    public static final String FILTER_USERS = "filter_users";
    public static final String SEARCH_USERS = "search_users";
    public static final String GET_USER_BY_ID = "get_user_by_id";

    static {
        SCOPE_MAP.put(GROUP_METADATA_UPDATE, "internal_group_entitlement");
        SCOPE_MAP.put(USER_ASSIGNMENT_INTO_GROUP, "internal_group_entitlement");
        SCOPE_MAP.put(USER_ASSIGNMENT_INTO_ROLE, "internal_role_entitlement");
        SCOPE_MAP.put(GROUP_ASSIGNMENT_INTO_ROLE, "internal_role_entitlement");
        SCOPE_MAP.put(ROLE_UPDATE_PERMISSIONS, "internal_role_mgt_update");
        SCOPE_MAP.put(ROLE_UPDATE_NAME, "internal_role_mgt_update");
        SCOPE_MAP.put(FILTER_USERS, "internal_user_mgt_list");
        SCOPE_MAP.put(USER_CREATION, "internal_user_mgt_create");
        SCOPE_MAP.put(USER_DELETION, "internal_user_mgt_delete");
        SCOPE_MAP.put(SEARCH_USERS, "internal_user_mgt_list");
        SCOPE_MAP.put(GET_USER_BY_ID, "internal_user_mgt_view");
    }

    public String resolve(String operation) {

        return SCOPE_MAP.get(operation);
    }
}
