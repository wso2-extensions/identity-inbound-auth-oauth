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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Scope handler for token requests with openid scope.
 */
public class OIDCScopeHandler extends OAuth2ScopeHandler {

    private static final Log log = LogFactory.getLog(OIDCScopeHandler.class);

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        Set<String> idTokenNotAllowedGrantTypesSet = OAuthServerConfiguration.getInstance()
                .getIdTokenNotAllowedGrantTypesSet();
        String grantType = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();
        // validating the authorization_code grant type with openid scope ignoring the IdTokenAllowed element defined
        // in the identity.xml
        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            return true;
        } else if (!idTokenNotAllowedGrantTypesSet.contains(grantType)) {
            // if id_token is allowed for requested grant type.
            return true;
        } else {
            // Remove OIDC scopes from the token message context.
            String[] scopes = tokReqMsgCtx.getScope();
            List<String> oidcScopes = OAuth2Util.getOIDCScopes(tokReqMsgCtx.getOauth2AccessTokenReqDTO()
                    .getTenantDomain());

            List<String> filteredScopes = Arrays.stream(scopes)
                    .filter(scope -> !OAuthConstants.Scope.OPENID.equals(scope))
                    .filter(scope -> !oidcScopes.contains(scope))
                    .collect(Collectors.toList());

            tokReqMsgCtx.setScope(filteredScopes.toArray(new String[0]));

            if (log.isDebugEnabled()) {
                log.debug("id_token is not allowed for requested grant type: " +
                        grantType + ". Removing all OIDC scopes registered in the tenant " +
                         "from requested scopes.");
            }
            // Returning 'true' since we are dropping openid scope and don't need to prevent issuing the token for
            // remaining scopes.

            return true;
        }
    }

    @Override
    public boolean canHandle(OAuthTokenReqMessageContext tokReqMsgCtx) {
        String[] scopes = tokReqMsgCtx.getScope();
        return scopes != null && Arrays.asList(scopes).contains(OAuthConstants.Scope.OPENID);
    }
}
