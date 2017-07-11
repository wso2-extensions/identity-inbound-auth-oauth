/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;

/**
 * Used for creating checked exceptions that can be handled.
 */
public class IdentityOAuth2ScopeException extends IdentityException {

    private static final long serialVersionUID = 5697663399373749593L;

    public IdentityOAuth2ScopeException(String message) {
        super(message);
        this.setErrorCode(getDefaultErrorCode());
    }

    public IdentityOAuth2ScopeException(String message, Throwable cause) {
        super(message, cause);
        this.setErrorCode(getDefaultErrorCode());
    }

    public IdentityOAuth2ScopeException(String errorCode, String message) {
        super(errorCode, message);
        this.setErrorCode(errorCode);
    }

    public IdentityOAuth2ScopeException(String errorCode, String message, Throwable throwable) {
        super(errorCode, message, throwable);
        this.setErrorCode(errorCode);
    }

    public String getErrorDescription() {

        String errorDescription = this.getMessage();
        if (StringUtils.isEmpty(errorDescription)) {
            errorDescription = Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getMessage();
        }
        return errorDescription;
    }

    private String getDefaultErrorCode() {

        String errorCode = super.getErrorCode();
        if (StringUtils.isEmpty(errorCode)) {
            errorCode = Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getCode();
        }
        return errorCode;
    }

}
