/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.introspection;

/**
 * This class represents the format of the introspection response.
 */
public final class IntrospectionResponse {

    // whether or not the presented token is currently active
    public static final String ACTIVE = "active";

    // OPTIONAL
    // list of scopes associated with the token
    public static final String SCOPE = "scope";

    // OPTIONAL
    // client identifier for the OAuth 2.0 client that requested this token
    public static final String CLIENT_ID = "client_id";

    // OPTIONAL
    // resource owner who authorized the token
    public static final String USERNAME = "username";

    // OPTIONAL
    // token type
    public static final String TOKEN_TYPE = "token_type";

    // OPTIONAL
    // time-stamp to indicate when this token is not to be used before
    public static final String NBF = "nbf";

    // OPTIONAL
    // intended audience for the token
    public static final String AUD = "aud";

    // OPTIONAL
    // issuer of the token
    public static final String ISS = "iss";

    // OPTIONAL
    public static final String JTI = "jti";

    // OPTIONAL
    // subject of the token
    public static final String SUB = "sub";

    // OPTIONAL
    // time-stamp to indicate when this token will expire
    public static final String EXP = "exp";

    // OPTIONAL
    // time-stamp to indicate when this token was originally issued
    public static final String IAT = "iat";

    // OPTIONAL
    // hash of token binding id
    public static final String TBH = "tbh";

    // OPTIONAL
    // confirmation used to contain tbh
    public static final String CNF = "cnf";

    class Error {

        public static final String INVALID_REQUEST = "invalid_request";

        public static final String ERROR = "error";

        public static final String ERROR_DESCRIPTION = "error_description";

    }

}
