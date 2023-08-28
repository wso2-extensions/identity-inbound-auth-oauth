/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.common;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.as.validator.CodeValidator;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.json.JSONObject;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.RESPONSE_MODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ResponseModes.JWT;

/**
 * Validator for code flow requests.
 */
public class CodeResponseValidator extends CodeValidator {

    public CodeResponseValidator() {

    }

    @Override
    public void validateRequiredParameters(HttpServletRequest request) throws OAuthProblemException {

        super.validateRequiredParameters(request);
        // FAPI requests require the response_mode to be jwt when the response_type is code.
        if (OAuthCommonUtil.isFapiEnabled()) {
            String responseMode = request.getParameter(RESPONSE_MODE);
            if (StringUtils.isNotBlank(request.getParameter(OAuthConstants.OAuth20Params.REQUEST))) {
                JSONObject requestObjectJson =
                        OAuthCommonUtil.decodeRequestObject(request.getParameter(OAuthConstants.OAuth20Params.REQUEST));
                responseMode = requestObjectJson.getString(RESPONSE_MODE);
            }
            if (!JWT.equals(responseMode)) {
                throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST)
                        .description("Invalid response_mode for the given response_type");
            }
        }
    }
}
