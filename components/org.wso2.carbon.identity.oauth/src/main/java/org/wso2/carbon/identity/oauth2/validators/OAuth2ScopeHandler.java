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

package org.wso2.carbon.identity.oauth2.validators;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.HashMap;
import java.util.Map;

/**
 * Scope handling extension during token issue.
 */
public abstract class OAuth2ScopeHandler {

    protected Map<String, String> properties = new HashMap<>();

    /**
     * Method to validate the scopes associated with the access token against the resource that is being accessed.
     *
     * @param tokReqMsgCtx message context of the token request.
     * @return true if scope is valid, false otherwise
     * @throws IdentityOAuth2Exception if error occurs while scope validation.
     */
    public abstract boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception;

    /**
     * Checks whether a given scopes can be handled by the scope handler.
     *
     * @param tokReqMsgCtx message context of the token request.
     * @return true if the given scopes can be validated, otherwise false.
     */
    public abstract boolean canHandle(OAuthTokenReqMessageContext tokReqMsgCtx);

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }
}
