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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.openidconnect.model;

public class Constants {

    public static final String REQUEST = "request";
    public static final String REQUEST_URI = "request_uri";
    public static final String CLIENT_ID = "client_id";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String SCOPE = "scope";
    public static final String STATE = "state";
    public static final String NONCE = "nonce";
    public static final String ISS = "iss";
    public static final String AUD = "aud";
    public static final String MAX_AGE = "max_age";
    public static final String DISPLAY = "display";
    public static final String AUTH_TIME = "auth_time";
    public static final String RESPONSE_MODE = "response_mode";
    public static final String ACR_VALUES = "acr_values";
    public static final String LOGIN_HINT = "login_hint";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String PROMPT = "prompt";
    public static String CLAIMS = "claims";
    public static final String JWKS_URI = "jwksURI";


    //JWS is consists of three parts seperated by 2 '.'s as JOSE header, JWS payload, JWS signature
    public static final int NUMBER_OF_PARTS_IN_JWS = 3;
    public static final int NUMBER_OF_PARTS_IN_JWE = 5;
    public static final String RS = "RS";
    public static final String PS = "PS";
    public static final String JWT_PART_DELIMITER = "\\.";

    public static final String FULL_STOP_DELIMITER = ".";
    public static final String DASH_DELIMITER = "-";
    public static final String KEYSTORE_FILE_EXTENSION = ".jks";
}
