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

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * This exception is used to communicate error messages, descriptions and status codes from authenticator to oauth
 * side so that respective responses can be built and send out.
 */
public class OAuthClientAuthnException extends IdentityOAuth2Exception {

    private String errorCode;

    public OAuthClientAuthnException(String message, String errorCode, Throwable e) {

        super(message, e);
        this.errorCode = errorCode;
    }

    public OAuthClientAuthnException(String message, String errorCode) {

        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {

        return this.errorCode;
    }
}
