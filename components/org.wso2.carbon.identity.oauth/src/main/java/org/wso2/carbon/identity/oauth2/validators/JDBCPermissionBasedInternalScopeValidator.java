/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;

/**
 * The JDBC Scope Validation implementation. This validates the Resource's scope (stored in IDN_OAUTH2_RESOURCE_SCOPE)
 * against the Access Token's scopes.
 */
public class JDBCPermissionBasedInternalScopeValidator {

    public String[] validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) {

        // filter internal scopes
        String[] requestedScopes = Oauth2ScopeUtils.getRequestedScopes(tokReqMsgCtx.getScope());
        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }
        List<Scope> userAllowedScopes = Oauth2ScopeUtils.getUserAllowedScopes(tokReqMsgCtx.getAuthorizedUser(),
                requestedScopes, tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
        String[] userAllowedScopesAsArray = Oauth2ScopeUtils.getScopes(userAllowedScopes);
        if (ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
            return userAllowedScopesAsArray;
        }

        List<String> scopesToRespond = new ArrayList<>();
        for (String scope : requestedScopes) {
            if (ArrayUtils.contains(userAllowedScopesAsArray, scope)) {
                scopesToRespond.add(scope);
            }
        }
        return scopesToRespond.toArray(new String[0]);
    }

    public String[] validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) {

        // Remove openid scope from the list if available
        String[] requestedScopes = Oauth2ScopeUtils.getRequestedScopes(authzReqMessageContext.getAuthorizationReqDTO
                ().getScopes());
        //If the token is not requested for specific scopes, return true
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return requestedScopes;
        }
        List<Scope> userAllowedScopes =
                Oauth2ScopeUtils.getUserAllowedScopes(authzReqMessageContext.getAuthorizationReqDTO().getUser(),
                        requestedScopes, authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());

        String[] userAllowedScopesAsArray = Oauth2ScopeUtils.getScopes(userAllowedScopes);
        if (ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
            return userAllowedScopesAsArray;
        }

        List<String> scopesToRespond = new ArrayList<>();
        for (String scope : requestedScopes) {
            if (ArrayUtils.contains(userAllowedScopesAsArray, scope)) {
                scopesToRespond.add(scope);
            }
        }
        return scopesToRespond.toArray(new String[0]);
    }

}














