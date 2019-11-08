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

package org.wso2.carbon.identity.oauth.ciba.dao;

/**
 * SQL queries related to data access layer of CIBA.
 */
public class SQLQueries {

    private SQLQueries() {

    }

    public static class CibaSQLQueries {

        public static final String STORE_CIBA_AUTH_REQ_CODE = "INSERT INTO IDN_OAUTH2_CIBA_AUTH_REQ " +
                "(CIBA_AUTH_CODE_DO_KEY, CIBA_AUTH_REQ_ID_HASH,CIBA_AUTHENTICATION_STATUS," +
                "LAST_POLLED_TIME,POLLING_INTERVAL,EXPIRY_TIME,BINDING_MESSAGE,TRANSACTION_CONTEXT,SCOPE) " +
                "VALUES (?,?,?,?,?,?,?,?,?)";

        public static final String UPDATE_CIBA_AUTHENTICATED_USER =
                "UPDATE  IDN_OAUTH2_CIBA_AUTH_REQ SET CIBA_AUTHENTICATED_USER = ?" +
                        "WHERE CIBA_AUTH_CODE_DO_KEY = ? ";

        public static final String RETRIEVE_AUTHENTICATED_USER =
                "SELECT CIBA_AUTHENTICATED_USER FROM IDN_OAUTH2_CIBA_AUTH_REQ " +
                        " WHERE CIBA_AUTH_CODE_DO_KEY = ? ";

        public static final String UPDATE_AUTHENTICATION_STATUS =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_REQ SET CIBA_AUTHENTICATION_STATUS = ?" +
                        " WHERE  CIBA_AUTH_CODE_DO_KEY = ? ";

        public static final String RETRIEVE_AUTHENTICATION_STATUS =
                "SELECT CIBA_AUTHENTICATION_STATUS FROM IDN_OAUTH2_CIBA_AUTH_REQ" +
                        " WHERE  CIBA_AUTH_CODE_DO_KEY = ? ";

        public static final String RETRIEVE_CIBA_AUTH_CODE_DO_KEY_BY_CIBA_AUTH_REQ_ID_HASH =
                "SELECT CIBA_AUTH_CODE_DO_KEY FROM " +
                        " IDN_OAUTH2_CIBA_AUTH_REQ  WHERE CIBA_AUTH_REQ_ID_HASH = ?";

        public static final String RETRIEVE_BINDING_MESSAGE_AND_TRANSACTION_CONTEXT = "SELECT BINDING_MESSAGE," +
                "TRANSACTION_CONTEXT FROM IDN_OAUTH2_CIBA_AUTH_REQ WHERE CIBA_AUTH_CODE_DO_KEY = ? ";

        /**
         * Following are SQL Queries related to polling.
         */

        public static final String RETRIEVE_LAST_POLLED_TIME =
                "SELECT LAST_POLLED_TIME FROM IDN_OAUTH2_CIBA_AUTH_REQ " +
                        " WHERE CIBA_AUTH_CODE_DO_KEY = ?";

        public static final String RETRIEVE_POLLING_INTERVAL = "SELECT POLLING_INTERVAL FROM IDN_OAUTH2_CIBA_AUTH_REQ" +
                " WHERE CIBA_AUTH_CODE_DO_KEY = ?";

        public static final String UPDATE_LAST_POLLED_TIME =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_REQ SET LAST_POLLED_TIME = ? " +
                        " WHERE  CIBA_AUTH_CODE_DO_KEY = ? ";

        public static final String UPDATE_POLLING_INTERVAL =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_REQ SET POLLING_INTERVAL = ? " +
                        " WHERE  CIBA_AUTH_CODE_DO_KEY = ? ";

        public static final String CHECK_IF_AUTH_REQ_ID_HASH_EXISTS = "SELECT COUNT('CIBA_AUTH_CODE_DO_KEY') " +
                "FROM IDN_OAUTH2_CIBA_AUTH_REQ " +
                " WHERE CIBA_AUTH_REQ_ID_HASH = ? ";

        public static final String RETRIEVE_AUTH_CODE_DO_FROM_CIBA_AUTH_CODE_DO_KEY = "SELECT * FROM " +
                "IDN_OAUTH2_CIBA_AUTH_REQ WHERE CIBA_AUTH_CODE_DO_KEY = ?";

    }
}
