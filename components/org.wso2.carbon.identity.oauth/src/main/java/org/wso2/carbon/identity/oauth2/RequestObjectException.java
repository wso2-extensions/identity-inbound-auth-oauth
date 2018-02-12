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
package org.wso2.carbon.identity.oauth2;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

/**
 * Custom exception to be thrown inside DynamicClientRegistration related functionality.
 */
public class RequestObjectException extends FrameworkException {

    public static final String ERROR_CODE_INVALID_REQUEST = "invalid_request";
    private static final long serialVersionUID = -4449780649560053452L;
    private String errorMessage;

    public RequestObjectException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
        this.errorMessage = errorMessage;
    }

    public RequestObjectException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);
        this.errorMessage = errorMessage;
    }

    public RequestObjectException(String errorMessage) {
        // By default we set the invalid_request error code.
        super(ERROR_CODE_INVALID_REQUEST, errorMessage);
        this.errorMessage = errorMessage;
    }

    public RequestObjectException(String errorMessage, Throwable cause) {
        // By default we set the invalid_request error code.
        super(ERROR_CODE_INVALID_REQUEST, errorMessage, cause);
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
