package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Collections;
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

        if (OAuth2Util.getAgentIdentityUserstoreName().equalsIgnoreCase(context.getAuthorizedUser()
                .getUserStoreDomain())) {
            Map<String, Object> agentMap = new HashMap<>();
            agentMap.put(AUT, AGENT);
            return agentMap;
        } else if (GrantType.AUTHORIZATION_CODE.toString().equals(context.getOauth2AccessTokenReqDTO().getGrantType())
            && context.getRequestedActor() != null) {
            Map<String, Object> agentMap = new HashMap<>();
            agentMap.put(ACT, Collections.singletonMap(SUB, context.getRequestedActor()));
            return agentMap;
        }
        return null;
    }
}
