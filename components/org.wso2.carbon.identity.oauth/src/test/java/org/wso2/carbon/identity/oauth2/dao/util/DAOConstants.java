/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.dao.util;

/**
 * DAO Constants.
 */
public final class DAOConstants {

    private DAOConstants() {
    }

    public static final String AUTHZ_CODE_STATUS_BY_CODE = "SELECT STATE FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE " +
            "AUTHORIZATION_CODE= ?";

    public static final String TOKEN_STATUS_BY_TOKE = "SELECT TOKEN_STATE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE " +
            "TOKEN_ID=?";

}
