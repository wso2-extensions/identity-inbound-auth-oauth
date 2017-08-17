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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * The OIDC Scope Validation implementation. This validates "openid" scope with authorization_code, password and
 * client_credential grant types.
 */
public class OIDCScopeValidator extends OAuth2ScopeValidator {

    private static Log log = LogFactory.getLog(OIDCScopeValidator.class);

    /**
     * Returns whether the grant types are validated with "openid" scope.
     *
     * @param accessTokenDO The access token data object.
     * @param resource The resource that is being accessed.
     * @return true if the grant type is valid.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {

        List<String> idTokenAllowedGrantList = new ArrayList<>();
        Map<String, String> idTokenAllowedGrantTypesMap = OAuthServerConfiguration.getInstance().
                getIdTokenAllowedForGrantTypesMap();

        if (!idTokenAllowedGrantTypesMap.isEmpty()) {
            for (Map.Entry<String, String> entry : idTokenAllowedGrantTypesMap.entrySet()) {
                if (Boolean.parseBoolean(entry.getValue())) {
                    idTokenAllowedGrantList.add(entry.getKey());
                }
            }
        }

        String grantTypeValue = accessTokenDO.getGrantType();

        // validating the authorization_code grant type with open id scope ignoring the IdTokenAllowed element defined
        // in the identity.xml
        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantTypeValue)) {
            return true;
        } else if (idTokenAllowedGrantList.contains(grantTypeValue)) {
            // if id_token is allowed for requested grant type.
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("id_token is not allowed for requested grant type: " + grantTypeValue);
            }
            return false;
        }
    }

    @Override
    public boolean canHandle(OAuth2TokenValidationMessageContext messageContext) {

        AccessTokenDO accessTokenDO = (AccessTokenDO) messageContext.getProperty("AccessTokenDO");
        if (accessTokenDO != null) {
            //Get the list of scopes associated with the access token
            String[] scopes = accessTokenDO.getScope();

            if (scopes != null && scopes.length > 0) {
                for (String scope : scopes) {
                    if (scope.trim().equals(OAuthConstants.Scope.OPENID)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
