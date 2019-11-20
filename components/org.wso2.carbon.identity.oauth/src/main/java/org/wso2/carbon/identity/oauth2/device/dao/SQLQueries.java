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

    public static class DeviceFlowDAOSQLQueries {

        public static final String STORE_DEVICE_CODE = "INSERT INTO IDN_OAUTH2_DEVICE_FLOW " +
                "(CODE_ID, DEVICE_CODE, USER_CODE, CONSUMER_KEY_ID, SCOPE, TIME_CREATED, LAST_POLL_TIME, EXPIRY_TIME," +
                " POLL_TIME, STATUS) SELECT ?,?,?,ID,?,?,?,?,?,? FROM IDN_OAUTH_CONSUMER_APPS WHERE " +
                "CONSUMER_KEY=?";

        public static final String GET_CONSUMER_KEY_FOR_USER_CODE = "SELECT CONSUMER_KEY FROM IDN_OAUTH2_DEVICE_FLOW " +
                "INNER JOIN IDN_OAUTH_CONSUMER_APPS ON CONSUMER_KEY_ID = ID WHERE USER_CODE = ?";

        public static final String REMOVE_DEVICE_CODE = "DELETE FROM IDN_OAUTH2_DEVICE_FLOW WHERE DEVICE_CODE=?";

        public static final String SET_USER_HAS_AUTHENTICATED = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET STATUS = ? WHERE " +
                "USER_CODE = ?";

        public static final String GET_CONSUMER_KEY_FOR_DEVICE_CODE = "SELECT CONSUMER_KEY FROM ((SELECT *" +
                " FROM IDN_OAUTH_CONSUMER_APPS INNER JOIN IDN_OAUTH2_DEVICE_FLOW ON IDN_OAUTH_CONSUMER_APPS.ID = " +
                "IDN_OAUTH2_DEVICE_FLOW.CONSUMER_KEY_ID) WHERE DEVICE_CODE=?";

        public static final String GET_AUTHENTICATION_STATUS = "SELECT STATUS, LAST_POLL_TIME, POLL_TIME, EXPIRY_TIME, " +
                "SCOPE, AUTHZ_USER FROM IDN_OAUTH2_DEVICE_FLOW WHERE DEVICE_CODE = ?";

        public static final String CHECK_CLIENT_ID_EXISTS = "SELECT CONSUMER_KEY FROM IDN_OAUTH_CONSUMER_APPS WHERE " +
                "CONSUMER_KEY = ?";

        public static final String GET_SCOPE_FOR_USER_CODE = "SELECT SCOPE FROM IDN_OAUTH2_DEVICE_FLOW WHERE " +
                "USER_CODE = ?";

        public static final String GET_USER_CODE_STATUS = "SELECT STATUS FROM IDN_OAUTH2_DEVICE_FLOW WHERE " +
                "USER_CODE = ?";

        public static final String SET_LAST_POLL_TIME = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET LAST_POLL_TIME = ? WHERE " +
                "DEVICE_CODE = ?";

        public static final String SET_AUTHZ_USER = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET AUTHZ_USER = ? WHERE " +
                "USER_CODE = ?";

        public static final String SET_DEVICE_CODE_EXPIRED = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET STATUS = ? WHERE " +
                "DEVICE_CODE = ?";

        public static final String SET_CALLBACK_URI = "UPDATE IDN_OAUTH_CONSUMER_APPS SET CALLBACK_URL = ? WHERE " +
                "CONSUMER_KEY = ?";

    }

}
