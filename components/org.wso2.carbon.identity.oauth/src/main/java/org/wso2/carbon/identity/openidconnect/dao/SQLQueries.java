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
            "(CONSUMER_KEY_ID, SESSION_DATA_KEY) VALUES ((SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?),?)";

    public static final String STORE_IDN_OIDC_REQ_OBJECT_CLAIMS = "INSERT INTO IDN_OIDC_REQ_OBJECT_CLAIMS " +
            "(REQ_OBJECT_ID,CLAIM_ATTRIBUTE, ESSENTIAL, VALUE, IS_USERINFO) VALUES (?, ?, ?, ?, ?)";

    public static final String STORE_IDN_OIDC_REQ_OBJECT_CLAIM_VALUES = "INSERT INTO IDN_OIDC_REQ_OBJ_CLAIM_VALUES " +
            "(REQ_OBJECT_CLAIMS_ID,CLAIM_VALUES) VALUES (?, ?)";

    public static final String UPDATE_REQUEST_OBJECT = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE SET " +
            "CODE_ID=?,TOKEN_ID=? WHERE SESSION_DATA_KEY=?";

    public static final String RETRIEVE_REQUEST_OBJECT_REF_ID_BY_TOKEN_ID = "SELECT ID FROM " +
            "IDN_OIDC_REQ_OBJECT_REFERENCE WHERE TOKEN_ID=?";

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

    public static final String RETRIEVE_REQUESTED_CLAIMS_BY_TOKEN = "SELECT CLAIM_ATTRIBUTE, ESSENTIAL, VALUE " +
            " FROM IDN_OIDC_REQ_OBJECT_CLAIMS" +
            " LEFT JOIN IDN_OIDC_REQ_OBJECT_REFERENCE" +
            " ON IDN_OIDC_REQ_OBJECT_CLAIMS.REQ_OBJECT_ID = IDN_OIDC_REQ_OBJECT_REFERENCE.ID" +
            " WHERE TOKEN_ID=? AND IS_USERINFO=? ";

    public static final String RETRIEVE_REQUESTED_CLAIMS_BY_SESSION_DATA_KEY = "SELECT CLAIM_ATTRIBUTE, ESSENTIAL," +
            " VALUE FROM IDN_OIDC_REQ_OBJECT_CLAIMS" +
            " LEFT JOIN IDN_OIDC_REQ_OBJECT_REFERENCE" +
            " ON IDN_OIDC_REQ_OBJECT_CLAIMS.REQ_OBJECT_ID = IDN_OIDC_REQ_OBJECT_REFERENCE.ID" +
            " WHERE SESSION_DATA_KEY=? AND IS_USERINFO=?";

    public static final String RETRIEVE_REQUESTED_CLAIMS_ID = "SELECT ID, CLAIM_ATTRIBUTE FROM IDN_OIDC_REQ_OBJECT_CLAIMS" +
            " WHERE REQ_OBJECT_ID=? ";

    /**
     * OIDC Scope claims mapping related queries.
     */

    public static final String STORE_IDN_OIDC_SCOPES = "INSERT INTO IDN_OIDC_SCOPE (NAME,TENANT_ID) VALUES (?, ?)";

    public static final String STORE_IDN_OIDC_CLAIMS = "INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING " +
            "(SCOPE_ID, EXTERNAL_CLAIM_ID) SELECT ?,IDN_CLAIM.ID FROM IDN_CLAIM LEFT JOIN " +
            "IDN_CLAIM_DIALECT ON IDN_CLAIM_DIALECT.ID = IDN_CLAIM.DIALECT_ID WHERE CLAIM_URI=? AND IDN_CLAIM_DIALECT." +
            "DIALECT_URI='http://wso2.org/oidc/claim' AND IDN_CLAIM_DIALECT.TENANT_ID=?";

    public static final String GET_ALL_IDN_OIDC_SCOPES = "SELECT COUNT(ID) FROM IDN_OIDC_SCOPE WHERE TENANT_ID=?";

    public static final String GET_IDN_OIDC_SCOPES_CLAIMS = "SELECT NAME,CLAIM_URI FROM IDN_OIDC_SCOPE LEFT JOIN" +
            " IDN_OIDC_SCOPE_CLAIM_MAPPING  ON IDN_OIDC_SCOPE_CLAIM_MAPPING.SCOPE_ID = IDN_OIDC_SCOPE.ID LEFT JOIN" +
            " IDN_CLAIM ON IDN_CLAIM.ID =IDN_OIDC_SCOPE_CLAIM_MAPPING.EXTERNAL_CLAIM_ID LEFT JOIN" +
            " IDN_CLAIM_DIALECT ON IDN_CLAIM_DIALECT.ID = IDN_CLAIM.DIALECT_ID WHERE IDN_OIDC_SCOPE.TENANT_ID=?" +
            " AND IDN_CLAIM_DIALECT.DIALECT_URI='http://wso2.org/oidc/claim' AND IDN_CLAIM_DIALECT.TENANT_ID=?";

    public static final String GET_IDN_OIDC_SCOPES = "SELECT NAME FROM IDN_OIDC_SCOPE WHERE TENANT_ID=?";

    public static final String GET_IDN_OIDC_CLAIMS = "SELECT CLAIM_URI  FROM IDN_OIDC_SCOPE LEFT JOIN " +
            "IDN_OIDC_SCOPE_CLAIM_MAPPING  ON IDN_OIDC_SCOPE_CLAIM_MAPPING.SCOPE_ID = IDN_OIDC_SCOPE.ID LEFT JOIN " +
            "IDN_CLAIM ON IDN_CLAIM.ID =IDN_OIDC_SCOPE_CLAIM_MAPPING.EXTERNAL_CLAIM_ID WHERE IDN_OIDC_SCOPE.NAME=? " +
            "AND IDN_OIDC_SCOPE.TENANT_ID=?";

    public static final String GET_IDN_OIDC_SCOPE_ID = "SELECT ID FROM IDN_OIDC_SCOPE WHERE NAME=? AND TENANT_ID=?";

    public static final String GET_OIDC_CLAIM_ID = "SELECT ID FROM IDN_CLAIM WHERE CLAIM_URI=? AND TENANT_ID =?";

    public static final String DELETE_SCOPE_CLAIM_MAPPING = "DELETE FROM IDN_OIDC_SCOPE WHERE NAME=? AND TENANT_ID=?";

    public static final String DELETE_CLAIMS_FROM_SCOPE = "DELETE FROM IDN_OIDC_SCOPE_CLAIM_MAPPING WHERE " +
            "EXTERNAL_CLAIM_ID IN (SELECT IDN_SCM.EXTERNAL_CLAIM_ID FROM " +
            "(SELECT * FROM IDN_OIDC_SCOPE_CLAIM_MAPPING) AS IDN_SCM LEFT JOIN IDN_OIDC_SCOPE " +
            "ON IDN_SCM.SCOPE_ID = IDN_OIDC_SCOPE.ID LEFT JOIN IDN_CLAIM " +
            "ON IDN_CLAIM.ID = IDN_SCM.EXTERNAL_CLAIM_ID LEFT JOIN IDN_CLAIM_DIALECT " +
            "ON IDN_CLAIM_DIALECT.ID = IDN_CLAIM.DIALECT_ID " +
            "WHERE IDN_OIDC_SCOPE.NAME =? AND IDN_CLAIM.CLAIM_URI =? AND " +
            "IDN_OIDC_SCOPE.TENANT_ID =? AND DIALECT_URI = 'http://wso2.org/oidc/claim') " +
            "AND SCOPE_ID IN (SELECT IDN_OIDC_SCOPE.ID FROM IDN_OIDC_SCOPE WHERE NAME =?)";

    public static final String INSERT_NEW_CLAIMS_FOR_SCOPE = "INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING " +
            "(SCOPE_ID,EXTERNAL_CLAIM_ID) VALUES (?, ?)";

}
