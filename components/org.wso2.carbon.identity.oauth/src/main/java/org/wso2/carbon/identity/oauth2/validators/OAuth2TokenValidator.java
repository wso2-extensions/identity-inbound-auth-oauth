/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.validators;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * OAuth2 access token Validators should implement this interface.
 * OAuth2 access token validator implementations can be plugged
 * to the system using identity.xml
 */
public interface OAuth2TokenValidator {

    boolean validateAccessDelegation(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception;

    boolean validateScope(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception;

    // For validation of token profile specific items.
    // E.g. validation of HMAC signature in HMAC token profile
    boolean validateAccessToken(OAuth2TokenValidationMessageContext validationReqDTO)
            throws IdentityOAuth2Exception;

    default String getTokenType() {

        return "Bearer";
    }

}
