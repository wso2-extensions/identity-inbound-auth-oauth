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
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This class should be extended by all OAuth2 Scope Validators.
 */
public abstract class OAuth2ScopeValidator {

    protected Set<String> scopesToSkip;
    protected Map<String, String> properties = new HashMap<>();

    /**
     * Method to validate the scopes associated with the access token against the resource that is being accessed.
     *
     * @param accessTokenDO - The access token data object
     * @param resource      - The resource that is being accessed.
     * @return - true if scope is valid, false otherwise
     * @throws IdentityOAuth2Exception
     */
    public abstract boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception;

    /**
     * Method to validate scopes in the token request against the roles of user
     *
     * @param tokReqMsgCtx
     * @return - true if the user has enough permission to generate tokens with requested scopes or
     * no scopes are requested, otherwise false
     * @throws IdentityOAuth2Exception
     */
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws
            IdentityOAuth2Exception, UserStoreException {
        return true;
    }

    public Set<String> getScopesToSkip() {
        return scopesToSkip;
    }

    public void setScopesToSkip(Set<String> scopesToSkip) {
        this.scopesToSkip = scopesToSkip;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    /**
     * Checks whether a given scopes can be handled by the validator.
     *
     * @param messageContext OAuth2TokenValidationMessageContext for the request.
     * @return true if the given scopes can be validated, otherwise false.
     */
    public boolean canHandle(OAuth2TokenValidationMessageContext messageContext) {
        return true;
    }

    /**
     * Method to get the name of the implemented scope validator name to display in the UI and save in the database.
     * As default the class name is used.
     *
     * @return Name of the scope validator
     */
    public String getValidatorName() {
        return this.getClass().getCanonicalName();
    }
}
