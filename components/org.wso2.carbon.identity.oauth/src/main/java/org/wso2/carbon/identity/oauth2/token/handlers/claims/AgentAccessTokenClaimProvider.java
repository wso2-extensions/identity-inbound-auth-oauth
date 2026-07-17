package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACTOR_SUBJECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.EXISTING_ACT_CLAIM;

/**
 * A class that provides additional claims for JWT access tokens when the AI agent is used.
 */
public class AgentAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

    private static final String ACT = "act";
    private static final String SUB = "sub";
    private static final String AGENT = "AGENT";
    private static final String AUT = "aut";
    private static final String CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";

    private static final Log log = LogFactory.getLog(AgentAccessTokenClaimProvider.class);

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context) throws IdentityOAuth2Exception {

        Map<String, Object> additionalClaims = new HashMap<>();

        String agentIdentityUserStoreName = IdentityUtil.getAgentIdentityUserstoreName();
        if (StringUtils.isNotEmpty(agentIdentityUserStoreName) && agentIdentityUserStoreName
                .equalsIgnoreCase(context.getAuthorizedUser().getUserStoreDomain())) {
            additionalClaims.put(AUT, AGENT);
        } else if ((GrantType.AUTHORIZATION_CODE.toString().equals(context.getOauth2AccessTokenReqDTO().getGrantType())
                || CIBA_GRANT_TYPE.equals(context.getOauth2AccessTokenReqDTO().getGrantType()))
                && context.getRequestedActor() != null) {

            additionalClaims.put(ACT, Collections.singletonMap(SUB, context.getRequestedActor()));
        }

        if (context.isDelegationRequest()) {
            Object delegationActClaim = buildDelegationActClaim(context);
            if (delegationActClaim != null) {
                additionalClaims.put(ACT, delegationActClaim);
            }
        }

        return additionalClaims.isEmpty() ? null : additionalClaims;
    }

    /**
     * Builds the {@code act} claim for a delegation request.
     *
     * <p>If a new actor subject is present, it becomes the current actor and any existing act
     * claim is nested underneath it. If there is no new actor, the existing act claim (if any)
     * is carried forward unchanged.</p>
     *
     * @param context Token request message context.
     * @return The act claim value, or {@code null} if there is neither a new actor nor an
     *         existing act claim.
     */
    private Object buildDelegationActClaim(OAuthTokenReqMessageContext context) {

        Object actorSubject = context.getProperty(ACTOR_SUBJECT);
        Object existingActClaim = context.getProperty(EXISTING_ACT_CLAIM);

        if (actorSubject != null) {
            // A new actor becomes the current actor, nesting any existing chain underneath.
            Map<String, Object> actClaim = new HashMap<>();
            actClaim.put(SUB, actorSubject.toString());
            if (existingActClaim instanceof Map) {
                actClaim.put(ACT, existingActClaim);
            }
            if (log.isDebugEnabled()) {
                log.debug("Delegation: added actor '" + actorSubject + "', nested existing act: "
                        + (existingActClaim instanceof Map));
            }
            return actClaim;
        }

        // No new actor: carry the existing act claim forward unchanged.
        if (existingActClaim instanceof Map) {
            if (log.isDebugEnabled()) {
                log.debug("Delegation: no new actor. Carrying existing act claim forward unchanged.");
            }
            return existingActClaim;
        }
        return null;
    }
}
