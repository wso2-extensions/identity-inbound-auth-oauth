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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Default OAuth2 access token validator that supports "bearer" token type.
 * However this validator does not validate scopes or access delegation.
 */
public class DefaultOAuth2TokenValidator implements OAuth2TokenValidator {

    public static final String TOKEN_TYPE = "bearer";
    private static final String ACCESS_TOKEN_DO = "AccessTokenDO";
    private static final String OIDC_SCOPE_VALIDATOR_CLASS = "org.wso2.carbon.identity.oauth2.validators.OIDCScopeValidator";

    @Override
    public boolean validateAccessDelegation(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception {

        // By default we don't validate access delegation
        return true;
    }

    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception {

        OAuth2ScopeValidator scopeValidator = OAuthServerConfiguration.getInstance().getoAuth2ScopeValidator();
        if (scopeValidator != null && scopeValidator.getClass() != null && messageContext.getRequestDTO() != null) {
            //if OIDC scope validator is engaged through the configuration
            if (scopeValidator.getClass().getName().equals(OIDC_SCOPE_VALIDATOR_CLASS)) {
                List<String> idTokenAllowedGrantTypesList = new ArrayList();
                Map<String, String> idTokenAllowedGrantTypesMap = OAuthServerConfiguration.getInstance().
                        getIdTokenAllowedForGrantTypesMap();
                if (!idTokenAllowedGrantTypesMap.isEmpty()) {
                    for (Map.Entry<String, String> entry : idTokenAllowedGrantTypesMap.entrySet()) {
                        if (Boolean.parseBoolean(entry.getValue())) {
                            idTokenAllowedGrantTypesList.add(entry.getKey());
                        }
                    }
                }
                if (!idTokenAllowedGrantTypesList.isEmpty()) {
                    return scopeValidator.validateScope((AccessTokenDO) messageContext.getProperty(ACCESS_TOKEN_DO),
                            idTokenAllowedGrantTypesList.toString());
                } else {
                    return scopeValidator.validateScope((AccessTokenDO) messageContext.getProperty(ACCESS_TOKEN_DO),
                            null);
                }
            }
            //If any other scope validator is engaged through the configuration
            else {
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

                //Return True if there is no resource to validate the token against
                //OR if the token has a valid scope to access the resource. False otherwise.
                return resource == null ||
                        scopeValidator.validateScope((AccessTokenDO) messageContext.getProperty(ACCESS_TOKEN_DO),
                                resource);
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
