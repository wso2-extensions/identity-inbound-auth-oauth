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

import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.Set;

/**
 * Default OAuth2 access token validator that supports "bearer" token type.
 * However this validator does not validate scopes or access delegation.
 */
public class DefaultOAuth2TokenValidator implements OAuth2TokenValidator {

    public static final String TOKEN_TYPE = "bearer";
    private static final String ACCESS_TOKEN_DO = "AccessTokenDO";

    @Override
    public boolean validateAccessDelegation(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception {

        // By default we don't validate access delegation
        return true;
    }

    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception {

        Set<OAuth2ScopeValidator> oAuth2ScopeValidators = OAuthServerConfiguration.getInstance()
                .getOAuth2ScopeValidators();
        for (OAuth2ScopeValidator validator: oAuth2ScopeValidators) {

            if (validator != null && validator.canHandle(messageContext)) {
                String resource = null;
                if (messageContext.getRequestDTO().getContext() != null) {
                    //Iterate the array of context params to find the 'resource' context param.
                    for (OAuth2TokenValidationRequestDTO.TokenValidationContextParam resourceParam :
                            messageContext.getRequestDTO().getContext()) {
                        //If the context param is the resource that is being accessed
                        if (resourceParam != null && "resource".equals(resourceParam.getKey())) {
                            resource = resourceParam.getValue();
                            break;
                        }
                    }
                }
                boolean isValid = validator.validateScope((AccessTokenDO) messageContext.getProperty
                        (ACCESS_TOKEN_DO), resource);

                if (!isValid) {
                    return false;
                }
            }
        }
        return true;
    }

    // For validation of token profile specific items.
    // E.g. validation of HMAC signature in HMAC token profile
    @Override
    public boolean validateAccessToken(OAuth2TokenValidationMessageContext validationReqDTO)
            throws IdentityOAuth2Exception {

        // With bearer token we don't validate anything apart from access delegation and scopes
        return true;
    }

}
