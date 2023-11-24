/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.par.common;

/**
 * SQL queries related to data access layer of PAR.
 */
public class SQLQueries {

    private SQLQueries() {

    }

    /**
     * PAR related SQL queries.
     */
    public static class ParSQLQueries {

        public static final String STORE_PAR_REQUEST = "INSERT INTO IDN_OAUTH_PAR " +
                "(REQ_URI_REF, CLIENT_ID, SCHEDULED_EXPIRY, PARAMETERS) VALUES (?, ?, ?, ?);";

        public static final String RETRIEVE_PAR_REQUEST = "SELECT CLIENT_ID, SCHEDULED_EXPIRY, PARAMETERS " +
                "FROM IDN_OAUTH_PAR WHERE REQ_URI_REF = ?";

        public static final String REMOVE_PAR_REQUEST = "DELETE FROM IDN_OAUTH_PAR WHERE REQ_URI_REF = ?";
    }
}
