/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.validators.grant;

import org.apache.oltu.oauth2.as.validator.RefreshTokenValidator;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthCommonUtil.validateContentTypes;

/**
 * Grant validator for Refresh Token Grant Type
 */
public class RefreshTokenGrantValidator extends RefreshTokenValidator {

    public RefreshTokenGrantValidator() {
        super();
        // Client Authentication is handled by
        // org.wso2.carbon.identity.oauth2.token.handlers.clientauth.ClientAuthenticationHandler extensions point.
        // Therefore client_id and client_secret are not mandatory since client can authenticate with other means.
        enforceClientAuthentication = false;
    }

    @Override
    public void validateContentType(HttpServletRequest request) throws OAuthProblemException {

        validateContentTypes(request);
    }
}
