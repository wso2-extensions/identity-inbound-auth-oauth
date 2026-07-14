package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACTOR_AZP;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACTOR_SUBJECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.DELEGATING_ACTOR;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.EXISTING_ACT_CLAIM;

/**
 * A class that provides additional claims for JWT access tokens when the AI agent is used.
 */
public class AgentAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

    private static final String ACT = "act";
    private static final String SUB = "sub";
    private static final String AGENT = "AGENT";
    private static final String AUT = "aut";
    private static final String AZP = "azp";
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

            Map<String, Object> actClaimMap = new HashMap<>();
            actClaimMap.put(SUB, context.getRequestedActor());
            // Include azp in act claim from context property
            Object actorAzp = context.getProperty(ACTOR_AZP);
            if (actorAzp != null) {
                actClaimMap.put(AZP, actorAzp.toString());
            } else {
                // Fallback: use the client_id of the requesting application
                String clientId = context.getOauth2AccessTokenReqDTO().getClientId();
                if (StringUtils.isNotEmpty(clientId)) {
                    actClaimMap.put(AZP, clientId);
                }
            }
            additionalClaims.put(ACT, actClaimMap);
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
     * Preserves any existing act claim as a nested chain.
     *
     * @param context Token request message context.
     * @return The act claim value, or {@code null} if no actor subject is available.
     */
    private Object buildDelegationActClaim(OAuthTokenReqMessageContext context) {

        Object actorSubject = context.getProperty(ACTOR_SUBJECT);
        if (actorSubject == null) {
            return null;
        }
        Object existingActClaim = context.getProperty(EXISTING_ACT_CLAIM);
        String consumerKey = context.getOauth2AccessTokenReqDTO().getClientId();

        if (existingActClaim instanceof Map && consumerKey != null
                && consumerKey.equals(context.getProperty(DELEGATING_ACTOR))) {
            /*
             * No new actor. Carry the existing act claim forward unchanged so
             * the delegation chain is neither altered nor duplicated.
             */
            if (log.isDebugEnabled()) {
                log.debug("Delegation re-exchange with no new actor. Carrying forward existing act claim unchanged.");
            }
            return existingActClaim;
        }

        Map<String, Object> actClaim = new HashMap<>();
        actClaim.put(SUB, actorSubject.toString());

        Object actorAzp = context.getProperty(ACTOR_AZP);
        if (actorAzp != null) {
            actClaim.put(AZP, actorAzp.toString());
        }

        // Support nested act claims for chained delegation.
        if (existingActClaim instanceof Map) {
            actClaim.put(ACT, existingActClaim);
            if (log.isDebugEnabled()) {
                log.debug("Delegation: nesting existing act claim.");
            }
        } else if (existingActClaim != null && log.isDebugEnabled()) {
            log.debug("Delegation: existing act claim is not in expected Map format. Type: "
                    + existingActClaim.getClass().getName());
        }

        if (log.isDebugEnabled()) {
            log.debug("Added act claim for delegation. Actor: " + actorSubject
                    + ", AZP: " + actorAzp + ", Has nested act: " + (existingActClaim instanceof Map));
        }
        return actClaim;
    }
}
