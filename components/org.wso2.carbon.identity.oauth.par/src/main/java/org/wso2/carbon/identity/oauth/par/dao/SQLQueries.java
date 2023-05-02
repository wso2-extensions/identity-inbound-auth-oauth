/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.dao;

/**
 * SQL queries related to data access layer of PAR.
 */
public class SQLQueries {

    private SQLQueries() {

    }

    /**
     * SQL queries.
     */

    public static class ParSQLQueries {
        //New Table

        //Storing Data
        public static final String STORE_PAR_REQUEST = "INSERT INTO IDN_OAUTH_PAR_REQUEST " +
                "(REQ_URI_UUID, CLIENT_ID, EXPIRES_IN) VALUES (?, ?, ?);";

        public static final String STORE_PAR_REQUEST_PARAMS = "INSERT INTO IDN_OAUTH_PAR_REQUEST_PARAMS " +
                "(REQ_URI_UUID, PARAM_KEY, PARAM_VALUE) VALUES (?, ?, ?);";

        public static final String STORE_PAR_REQUEST_OBJECT = "INSERT INTO IDN_OAUTH_PAR_REQUEST_OBJ " +
                "(REQ_URI_UUID, REQUEST_OBJ) VALUES (?, ?);";


        //Retrieve data
        public static final String RETRIEVE_PAR_CLIENT_ID =
                "SELECT CLIENT_ID FROM IDN_OAUTH_PAR_REQUEST " +
                        " WHERE REQ_URI_UUID = ? ";

        public static final String RETRIEVE_PAR_PARAMS =
                "SELECT PARAM_KEY, PARAM_VALUE FROM IDN_OAUTH_PAR_REQUEST_PARAMS WHERE REQ_URI_UUID = ?";

        public static final String RETRIEVE_REQUEST_EXPIRES_IN =
                "SELECT EXPIRES_IN FROM IDN_OAUTH_PAR_REQUEST WHERE REQ_URI_UUID = ?";
    }
}
