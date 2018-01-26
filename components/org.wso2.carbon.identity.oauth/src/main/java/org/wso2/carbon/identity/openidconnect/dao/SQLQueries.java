/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect.dao;

public class SQLQueries {

    private SQLQueries() {

    }

    /**
     * OIDC Request Object related queries
     */
    public static final String STORE_IDN_OIDC_REQ_OBJECT_REFERENCE = "INSERT INTO IDN_OIDC_REQ_OBJECT_REFERENCE " +
            "(CONSUMER_KEY_ID, CODE_ID, TOKEN_ID, SESSION_DATA_KEY) SELECT ID,?,?,? FROM " +
            "IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

    public static final String STORE_IDN_OIDC_REQ_OBJECT_CLAIMS = "INSERT INTO IDN_OIDC_REQ_OBJECT_CLAIMS " +
            "(REQ_OBJECT_ID,CLAIM_ATTRIBUTE, ESSENTIAL, VALUE, IS_USERINFO) VALUES (?, ?, ?, ?, ?)";

    public static final String STORE_IDN_OIDC_REQ_OBJECT_CLAIM_VALUES = "INSERT INTO IDN_OIDC_REQ_OBJECT_CLAIM_VALUES " +
            "(REQ_OBJECT_CLAIMS_ID,VALUES) VALUES (?, ?)";

    public static final String UPDATE_REQUEST_OBJECT = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE SET " +
            "CODE_ID=?,TOKEN_ID=? WHERE SESSION_DATA_KEY=?";

    public static final String REFRESH_REQUEST_OBJECT = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE SET " +
            "TOKEN_ID=? WHERE TOKEN_ID=?";

    public static final String DELETE_REQ_OBJECT_TOKEN_FOR_CODE = "DELETE FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE TOKEN_ID =" +
            " ?";

    public static final String UPDATE_REQUEST_OBJECT_TOKEN_FOR_CODE = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE SET " +
            "TOKEN_ID=? WHERE CODE_ID=?";

    public static final String DELETE_REQ_OBJECT_BY_CODE_ID = "DELETE FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE CODE_ID =" +
            " ?";

    public static final String DELETE_REQ_OBJECT_BY_TOKEN_ID = "DELETE FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE TOKEN_ID" +
            " = ?";

    public static final String RETRIEVE_ESSENTIAL_CLAIMS_BY_TOKEN = "SELECT CLAIM_ATTRIBUTE" +
            " FROM IDN_OIDC_REQ_OBJECT_CLAIMS" +
            " LEFT JOIN IDN_OIDC_REQ_OBJECT_REFERENCE" +
            " ON IDN_OIDC_REQ_OBJECT_CLAIMS.REQ_OBJECT_ID = IDN_OIDC_REQ_OBJECT_REFERENCE.ID" +
            " WHERE TOKEN_ID=? AND ESSENTIAL=? AND IS_USERINFO=? ";

    public static final String RETRIEVE_REQUESTED_CLAIMS_BY_TOKEN = "SELECT CLAIM_ATTRIBUTE, ESSENTIAL, VALUE " +
            " FROM IDN_OIDC_REQ_OBJECT_CLAIMS" +
            " LEFT JOIN IDN_OIDC_REQ_OBJECT_REFERENCE" +
            " ON IDN_OIDC_REQ_OBJECT_CLAIMS.REQ_OBJECT_ID = IDN_OIDC_REQ_OBJECT_REFERENCE.ID" +
            " WHERE TOKEN_ID=? AND IS_USERINFO=? ";

}
