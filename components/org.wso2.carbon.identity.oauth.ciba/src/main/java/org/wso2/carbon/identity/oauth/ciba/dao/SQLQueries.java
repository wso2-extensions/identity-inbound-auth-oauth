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

    /**
     * SQL queries.
     */
    public static class CibaSQLQueries {

        public static final String STORE_CIBA_AUTH_CODE = "INSERT INTO IDN_OAUTH2_CIBA_AUTH_CODE " +
                "(AUTH_CODE_KEY, AUTH_REQ_ID, CONSUMER_KEY, ISSUED_TIME, LAST_POLLED_TIME, POLLING_INTERVAL," +
                " EXPIRES_IN, AUTH_REQ_STATUS) VALUES (?,?,?,?,?,?,?,?)";

        public static final String UPDATE_AUTHENTICATED_USER =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_CODE SET AUTHENTICATED_USER_NAME = ? ,USER_STORE_DOMAIN = ? ," +
                        "TENANT_ID = ? WHERE AUTH_CODE_KEY = ? ";

        public static final String UPDATE_AUTHENTICATION_SUCCESS =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_CODE SET AUTHENTICATED_USER_NAME = ? ,USER_STORE_DOMAIN = ? ," +
                        "TENANT_ID = ?, IDP_ID = (SELECT IDP.ID FROM IDP WHERE IDP.NAME = ? AND IDP.TENANT_ID = ?) ," +
                        "AUTH_REQ_STATUS = ? WHERE AUTH_CODE_KEY = ? ";

        public static final String RETRIEVE_AUTHENTICATED_USER =
                "SELECT AUTHENTICATED_USER_NAME,USER_STORE_DOMAIN,TENANT_ID FROM IDN_OAUTH2_CIBA_AUTH_CODE " +
                        " WHERE AUTH_CODE_KEY = ? ";

        public static final String UPDATE_AUTHENTICATION_STATUS =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_CODE SET AUTH_REQ_STATUS = ? WHERE AUTH_CODE_KEY = ? ";

        public static final String RETRIEVE_AUTHENTICATION_STATUS =
                "SELECT AUTH_REQ_STATUS FROM IDN_OAUTH2_CIBA_AUTH_CODE WHERE AUTH_CODE_KEY = ? ";

        public static final String RETRIEVE_CIBA_AUTH_CODE_KEY_BY_CIBA_AUTH_REQ_ID =
                "SELECT AUTH_CODE_KEY FROM IDN_OAUTH2_CIBA_AUTH_CODE WHERE AUTH_REQ_ID = ?";

        public static final String UPDATE_LAST_POLLED_TIME =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_CODE SET LAST_POLLED_TIME = ? WHERE  AUTH_CODE_KEY = ? ";

        public static final String UPDATE_POLLING_INTERVAL =
                "UPDATE IDN_OAUTH2_CIBA_AUTH_CODE SET POLLING_INTERVAL = ? WHERE  AUTH_CODE_KEY = ? ";

        public static final String RETRIEVE_AUTH_CODE = "SELECT AUTH_CODE_KEY, " +
                " AUTH_REQ_ID, CONSUMER_KEY, LAST_POLLED_TIME, POLLING_INTERVAL, EXPIRES_IN, AUTH_REQ_STATUS, " +
                " ISSUED_TIME FROM IDN_OAUTH2_CIBA_AUTH_CODE WHERE AUTH_CODE_KEY = ?";

        public static final String STORE_SCOPES = "INSERT INTO IDN_OAUTH2_CIBA_REQUEST_SCOPES (AUTH_CODE_KEY,SCOPE) " +
                "VALUES (?,?)";

        public static final String RETRIEVE_SCOPE =
                "SELECT SCOPE FROM IDN_OAUTH2_CIBA_AUTH_CODE INNER JOIN IDN_OAUTH2_CIBA_REQUEST_SCOPES ON " +
                        "(IDN_OAUTH2_CIBA_AUTH_CODE.AUTH_CODE_KEY = IDN_OAUTH2_CIBA_REQUEST_SCOPES.AUTH_CODE_KEY) " +
                        " WHERE IDN_OAUTH2_CIBA_AUTH_CODE.AUTH_CODE_KEY= ? ";
    }
}
