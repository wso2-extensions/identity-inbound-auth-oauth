/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;

/**
 * OAuth invalid scope exception.
 */

public class IdentityOAuth2InvalidScopeException extends IdentityException {

    private static final long serialVersionUID = 6685265285500081950L;

    public IdentityOAuth2InvalidScopeException(String message) {
        super(message);
        this.setErrorCode(getDefaultErrorCode());
    }

    public IdentityOAuth2InvalidScopeException(String errorCode, String message) {
        super(errorCode, message);
    }

    public IdentityOAuth2InvalidScopeException(String message, Throwable cause) {
        super(message, cause);
        this.setErrorCode(getDefaultErrorCode());
    }

    public IdentityOAuth2InvalidScopeException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    private String getDefaultErrorCode() {

        String errorCode = super.getErrorCode();
        if (StringUtils.isEmpty(errorCode)) {
            errorCode = Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getCode();
        }
        return errorCode;
    }
}
