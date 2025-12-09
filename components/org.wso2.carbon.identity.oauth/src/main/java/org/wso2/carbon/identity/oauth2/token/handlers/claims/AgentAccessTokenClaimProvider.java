/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.HashMap;
import java.util.Map;

/**
 * A class that provides additional claims for JWT access tokens when the AI agent is used.
 */
public class AgentAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

    private static final String ACT = "act";
    private static final String SUB = "sub";
    private static final String AGENT = "AGENT";
    private static final String AUT = "aut";

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context) throws IdentityOAuth2Exception {

        String agentIdentityUserStoreName = IdentityUtil.getAgentIdentityUserstoreName();
        if (StringUtils.isNotEmpty(agentIdentityUserStoreName) && agentIdentityUserStoreName
                .equalsIgnoreCase(context.getAuthorizedUser().getUserStoreDomain())) {
            Map<String, Object> agentMap = new HashMap<>();
            agentMap.put(AUT, AGENT);
            return agentMap;
        } else if (GrantType.AUTHORIZATION_CODE.toString().equals(context.getOauth2AccessTokenReqDTO().getGrantType())
            && context.getRequestedActor() != null) {
            Map<String, Object> agentMap = new HashMap<>();
            Map<String, Object> actMap = new HashMap<>();
            actMap.put(SUB, context.getRequestedActor());
            actMap.put(AUT, AGENT);
            agentMap.put(ACT, actMap);
            return agentMap;
        }
        return null;
    }
}
