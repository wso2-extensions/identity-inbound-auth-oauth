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

package org.wso2.carbon.identity.oauth.ciba.common;

/**
 * Represents possible authentication status.
 */
public enum AuthReqStatus {

    REQUESTED, // Authentication request is awaiting authentication & authorization.
    AUTHENTICATED,
    TOKEN_ISSUED, // Token issued for the authentication request after successful completion of authentication process.
    EXPIRED,

   // Possible failures in authentication requests.
    FAILED ,
    CONSENT_DENIED
}
