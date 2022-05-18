/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.authz.validators;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REDIRECT_URI;

/**
 * The default implementation of the ResponseTypeRequestValidator. If there is no ResponseTypeRequestValidator
 * registered for the response type, then this will be used for the validation.
 */
public class DefaultResponseTypeRequestValidator extends AbstractResponseTypeRequestValidator {

    public DefaultResponseTypeRequestValidator() {

        parametersToValidate.add(REDIRECT_URI);
    }

    @Override
    public String getResponseType() {

        return "";
    }
}
