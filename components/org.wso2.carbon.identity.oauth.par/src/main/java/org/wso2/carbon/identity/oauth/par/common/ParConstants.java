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

package org.wso2.carbon.identity.oauth.par.common;

/**
 * Contains the required constants for PAR feature.
 */
public class ParConstants {
    public static final long EXPIRES_IN_DEFAULT_VALUE_IN_SEC = 60; //according to PAR spec (60 seconds)
    public static final long MAXIMUM_REQUESTED_EXPIRY_IN_SEC = 600; //according to PSR spec
    public static final long SEC_TO_MILLISEC_FACTOR = 1000;
    public static final String REQUEST = "request";
    public static final String UTC = "UTC";
    public static final String REQUEST_URI = "request_uri";
    public static final String EXPIRES_IN = "expires_in";
    public static final String IS_PAR_REQUEST = "isParRequest";
    public static final String REQUEST_URI_HEAD = "urn:ietf:params:wso2is:request_uri:";


    private ParConstants() {

    }
}
