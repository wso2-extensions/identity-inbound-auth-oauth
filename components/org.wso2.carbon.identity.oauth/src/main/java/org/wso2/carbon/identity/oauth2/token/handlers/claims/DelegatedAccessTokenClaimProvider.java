package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.DELEGATING_ACTOR;

/**
 * Provides additional claims for JWT access tokens when token exchange
 * delegation is requested (RFC 8693 delegation flow).
 */
public class DelegatedAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

    private static final String ACT = "act";
    private static final String SUB = "sub";

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context)
            throws IdentityOAuth2Exception {

        // Authz context doesn't apply to token exchange delegation
        return null;
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context)
            throws IdentityOAuth2Exception {

        if (context.isDelegationRequest()
                && context.getProperty(DELEGATING_ACTOR) != null
                && StringUtils.isNotBlank(context.getProperty(DELEGATING_ACTOR).toString())) {

            Map<String, Object> actorMap = new HashMap<>();
            actorMap.put(ACT, Collections.singletonMap(SUB, context.getProperty(DELEGATING_ACTOR).toString()));
            return actorMap;
        }
        return null;
    }
}
