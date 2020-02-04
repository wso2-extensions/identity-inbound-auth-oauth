/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.device.dao;

/**
 * SQL queries that need to execute database
 */
public class SQLQueries {

    private SQLQueries() {

    }

    /**
     * SQL queries related to device flow.
     */
    public static class DeviceFlowDAOSQLQueries {

        public static final String STORE_DEVICE_CODE = "INSERT INTO IDN_OAUTH2_DEVICE_FLOW (CODE_ID, DEVICE_CODE, " +
                "USER_CODE, CONSUMER_KEY_ID, TIME_CREATED, LAST_POLL_TIME, EXPIRY_TIME, POLL_TIME, STATUS) " +
                "SELECT ?, ?, ?, ID, ?, ?, ?, ?, ? FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = ?";

        public static final String GET_CONSUMER_KEY_FOR_USER_CODE = "SELECT CONSUMER_KEY FROM IDN_OAUTH2_DEVICE_FLOW " +
                "INNER JOIN IDN_OAUTH_CONSUMER_APPS ON CONSUMER_KEY_ID = ID WHERE USER_CODE = ?";

        public static final String REMOVE_DEVICE_CODE = "DELETE FROM IDN_OAUTH2_DEVICE_FLOW WHERE DEVICE_CODE = ?";

        public static final String SET_AUTHENTICATION_STATUS = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET STATUS = ? WHERE " +
                "USER_CODE = ?";

        public static final String GET_CONSUMER_KEY_FOR_DEVICE_CODE = "SELECT CONSUMER_KEY FROM (SELECT * " +
                "FROM IDN_OAUTH_CONSUMER_APPS INNER JOIN IDN_OAUTH2_DEVICE_FLOW ON IDN_OAUTH_CONSUMER_APPS.ID = " +
                "IDN_OAUTH2_DEVICE_FLOW.CONSUMER_KEY_ID) CONSUMER_APPS_WITH_DEVICE_FLOW WHERE DEVICE_CODE = ?";

        public static final String GET_AUTHENTICATION_STATUS = "SELECT IDN_OAUTH2_DEVICE_FLOW.STATUS, " +
                "IDN_OAUTH2_DEVICE_FLOW.LAST_POLL_TIME, IDN_OAUTH2_DEVICE_FLOW.POLL_TIME, " +
                "IDN_OAUTH2_DEVICE_FLOW.EXPIRY_TIME, IDN_OAUTH2_DEVICE_FLOW.AUTHZ_USER, " +
                "IDN_OAUTH2_DEVICE_FLOW.TENANT_ID, IDN_OAUTH2_DEVICE_FLOW.USER_DOMAIN,IDP.NAME FROM " +
                "IDN_OAUTH2_DEVICE_FLOW INNER JOIN IDP ON IDN_OAUTH2_DEVICE_FLOW.IDP_ID = IDP.ID WHERE DEVICE_CODE = ?";

        public static final String CHECK_CLIENT_ID_EXISTS = "SELECT CONSUMER_KEY FROM IDN_OAUTH_CONSUMER_APPS WHERE " +
                "CONSUMER_KEY = ?";

        public static final String GET_SCOPE_FOR_USER_CODE = "SELECT SCOPE FROM IDN_OAUTH2_DEVICE_FLOW WHERE " +
                "USER_CODE = ?";

        public static final String GET_USER_CODE_STATUS = "SELECT STATUS FROM IDN_OAUTH2_DEVICE_FLOW WHERE " +
                "USER_CODE = ?";

        public static final String SET_LAST_POLL_TIME = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET LAST_POLL_TIME = ? WHERE " +
                "DEVICE_CODE = ?";

        public static final String SET_AUTHZ_USER_AND_STATUS = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET AUTHZ_USER = ?, " +
                "STATUS = ?, TENANT_ID = ?, USER_DOMAIN = ?, IDP_ID = (SELECT ID FROM IDP WHERE NAME = ? AND " +
                "TENANT_ID = ?) WHERE USER_CODE = ?";

        public static final String SET_DEVICE_CODE_EXPIRED = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET STATUS = ? WHERE " +
                "DEVICE_CODE = ?";

        public static final String SET_CALLBACK_URL = "UPDATE IDN_OAUTH_CONSUMER_APPS SET CALLBACK_URL = ? WHERE " +
                "CONSUMER_KEY = ?";

        public static final String STORE_DEVICE_FLOW_SCOPES = "INSERT INTO IDN_OAUTH2_DEVICE_FLOW_SCOPES (SCOPE_ID, " +
                "SCOPE) VALUES (?, ?)";

        public static final String GET_SCOPES_FOR_USER_CODE = "SELECT SCOPE FROM (SELECT * FROM " +
                "IDN_OAUTH2_DEVICE_FLOW INNER JOIN IDN_OAUTH2_DEVICE_FLOW_SCOPES ON IDN_OAUTH2_DEVICE_FLOW.CODE_ID" +
                " = IDN_OAUTH2_DEVICE_FLOW_SCOPES.SCOPE_ID) DEVICE_FLOW_WITH_SCOPES WHERE USER_CODE = ?";

        public static final String GET_SCOPES_FOR_DEVICE_CODE = "SELECT SCOPE FROM (SELECT * FROM " +
                "IDN_OAUTH2_DEVICE_FLOW INNER JOIN IDN_OAUTH2_DEVICE_FLOW_SCOPES ON IDN_OAUTH2_DEVICE_FLOW.CODE_ID" +
                " = IDN_OAUTH2_DEVICE_FLOW_SCOPES.SCOPE_ID) DEVICE_FLOW_WITH_SCOPES WHERE DEVICE_CODE = ?";
    }
}
