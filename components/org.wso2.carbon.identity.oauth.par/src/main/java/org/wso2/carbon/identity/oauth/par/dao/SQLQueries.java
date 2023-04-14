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
 * KIND, either express or implied.  See the License for the
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
        public static final String STORE_PAR_REQUEST = "INSERT INTO IDN_OAUTH_PAR " +
                "(REQ_URI_UUID, PARAM_MAP, REQ_TIME) VALUES (?,?,?)";

        public static final String RETRIEVE_PAR_REQUEST_DATA =
                "SELECT PARAM_MAP, REQ_TIME FROM IDN_OAUTH_PAR " +
                        " WHERE REQ_URI_UUID = ? ";
    }
}
