/*
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
 * Contains the required constants for PAR feature.
 */
public class ParConstants {

    public static final int EXPIRES_IN_DEFAULT_VALUE = 60;
    public static final long SEC_TO_MILLISEC_FACTOR = 1000;
    public static final String UTC = "UTC";
    public static final String EXPIRES_IN = "expires_in";
    public static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:par:request_uri:";
    public static final String CACHE_NAME = "ParCache";
    public static final String COL_LBL_PARAMETERS = "PARAMETERS";
    public static final String COL_LBL_SCHEDULED_EXPIRY = "SCHEDULED_EXPIRY";
    public static final String COL_LBL_CLIENT_ID = "CLIENT_ID";
    public static final String PAR = "PAR";
    public static final String REQUEST_URI_IN_REQUEST_BODY_ERROR = "Request with request_uri not allowed.";
    public static final String REPEATED_PARAMS_IN_REQUEST_ERROR = "Invalid request with repeated parameters.";
    public static final String INVALID_CONSUMER_KEY_ERROR =
            "Cannot find an application associated with the given consumer key.";
    public static final String PAR_CLIENT_AUTH_ERROR = "Client Authentication Failed.";
    public static final String CLIENT_AUTH_REQUIRED_ERROR = "Client authentication required.";
    public static final String INTERNAL_SERVER_ERROR = "Internal Server Error.";
    public static final String INVALID_CLIENT_ERROR = "A valid OAuth client could not be found for client_id: ";
    public static final String INVALID_REQUEST_OBJECT = "Unable to build a valid Request Object from the" +
            " pushed authorization request.";

    private ParConstants() {

    }
}
