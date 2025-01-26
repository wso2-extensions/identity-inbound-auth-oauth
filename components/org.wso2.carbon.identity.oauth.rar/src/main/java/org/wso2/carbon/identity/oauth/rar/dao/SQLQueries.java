/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.rar.dao;

/**
 * The {@code SQLQueries} class contains SQL query constants used for performing
 * database operations related to OAuth2 Rich Authorization Requests.
 */
public class SQLQueries {

    private SQLQueries() {
        // Private constructor to prevent instantiation
    }

    private static final String SELECT_AUTHORIZATION_DETAILS_ID_BY_TYPE =
            "SELECT ID FROM AUTHORIZATION_DETAILS_TYPES WHERE TYPE = ? AND TENANT_ID = ?";

    public static final String ADD_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS =
            "INSERT INTO IDN_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS " +
                    "(CONSENT_ID, AUTHORIZATION_DETAILS, CONSENT, TYPE_ID, TENANT_ID) " +
                    "VALUES (?, ?, ?, (" + SELECT_AUTHORIZATION_DETAILS_ID_BY_TYPE + "), ?)";

    public static final String UPDATE_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS =
            "UPDATE IDN_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS " +
                    "SET AUTHORIZATION_DETAILS=?, CONSENT=? " +
                    "WHERE CONSENT_ID=? AND TYPE_ID=(" + SELECT_AUTHORIZATION_DETAILS_ID_BY_TYPE + ") AND TENANT_ID=?";

    public static final String GET_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS =
            "SELECT ID, TYPE_ID, AUTHORIZATION_DETAILS, CONSENT FROM IDN_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS " +
                    "WHERE CONSENT_ID=? AND TENANT_ID=?";

    public static final String DELETE_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS =
            "DELETE FROM IDN_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS WHERE CONSENT_ID=? AND TENANT_ID=?";

    public static final String ADD_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS =
            "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS " +
                    "(TOKEN_ID, AUTHORIZATION_DETAILS, TYPE_ID, TENANT_ID) " +
                    "VALUES (?, ?, (" + SELECT_AUTHORIZATION_DETAILS_ID_BY_TYPE + "), ?)";

    public static final String DELETE_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS =
            "DELETE FROM IDN_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS WHERE TOKEN_ID=? AND TENANT_ID=?";

    public static final String GET_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS =
            "SELECT ID, TYPE_ID, AUTHORIZATION_DETAILS FROM IDN_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS " +
                    "WHERE TOKEN_ID=? AND TENANT_ID=?";

    public static final String ADD_OAUTH2_CODE_AUTHORIZATION_DETAILS =
            "INSERT INTO IDN_OAUTH2_AUTHZ_CODE_AUTHORIZATION_DETAILS" +
                    "(CODE_ID, AUTHORIZATION_DETAILS, TYPE_ID, TENANT_ID) " +
                    "VALUES (?, ?, (" + SELECT_AUTHORIZATION_DETAILS_ID_BY_TYPE + "), ?)";

    public static final String GET_OAUTH2_CODE_AUTHORIZATION_DETAILS_BY_CODE =
            "SELECT IOAC.CODE_ID, IOACAD.TYPE_ID, IOACAD.AUTHORIZATION_DETAILS " +
                    "FROM IDN_OAUTH2_AUTHZ_CODE_AUTHORIZATION_DETAILS IOACAD " +
                    "INNER JOIN IDN_OAUTH2_AUTHORIZATION_CODE IOAC ON IOACAD.CODE_ID = IOAC.CODE_ID " +
                    "WHERE IOAC.AUTHORIZATION_CODE=? AND IOACAD.TENANT_ID=?";

    public static final String GET_IDN_OAUTH2_USER_CONSENT_CONSENT_ID =
            "SELECT CONSENT_ID FROM IDN_OAUTH2_USER_CONSENT WHERE USER_ID=? AND APP_ID=? AND TENANT_ID=?";
}
