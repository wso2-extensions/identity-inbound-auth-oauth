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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.exception;

/**
 * This exception should be thrown when client authentication fails in the revoke endpoint.
 * callback is a qualified name of a JavaScript function which is defined in the
 * @see <a href="https://tools.ietf.org/html/rfc7009#page-3">Oauth Token Revocation specification</a>
 */
public class RevokeEndpointAccessDeniedException extends InvalidRequestParentException {

    private String callback;
    public RevokeEndpointAccessDeniedException(String message) {
        super(message);
    }

    public RevokeEndpointAccessDeniedException(String message, String errorCode, String callback) {
        super(message);
        this.errorCode = errorCode;
        this.callback = callback;
    }

    public RevokeEndpointAccessDeniedException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }

    public String getCallback() {
        return callback;
    }
}
