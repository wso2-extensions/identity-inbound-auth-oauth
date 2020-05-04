/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.validators.scope;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

/**
 * This is a global level interface for scope validation. This needs to be engaged after application level validators.
 */
public interface ScopeValidator {

    /**
     * Checks whether the validator can be engaged.
     *
     * @return True if it can handle, otherwise false.
     */
    boolean canHandle();

    /**
     * Validates scopes in the authorization request and manipulate the permitted scopes within the request. Engage
     * it after application-level validators at ResponseTypeHandler level.
     *
     * @param authzReqMessageContext Authorization request.
     * @return True if the user has enough permission to generate tokens or authorization codes with requested
     * scopes or no scopes are requested, otherwise false.
     * @throws IdentityOAuth2Exception
     */
    boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception;

    /**
     * Validates scopes in the token request and manipulate the permitted scopes within the request. Engage it after
     * application-level validators at GrantHandler level.
     *
     * @param tokenReqMessageContext OAuthTokenReqMessageContext.
     * @return True if the user has enough permission to generate tokens with requested scopes or
     * no scopes are requested, otherwise false.
     * @throws IdentityOAuth2Exception
     */
    boolean validateScope(OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception;

    /**
     * Validates scopes in the token request and manipulate the permitted scopes within the request. Engage it after
     * application-level validators at TokenValidator level.
     *
     * @param tokenValidationMessageContext OAuth2TokenValidationMessageContext.
     * @return True if the user has enough permission to generate tokens with requested scopes or
     * no scopes are requested, otherwise false.
     * @throws IdentityOAuth2Exception
     */
    boolean validateScope(OAuth2TokenValidationMessageContext tokenValidationMessageContext)
            throws IdentityOAuth2Exception;

    /**
     * Get the friendly name of the implemented scope validator.
     *
     * @return Name of the scope validator.
     */
    String getName();
}
