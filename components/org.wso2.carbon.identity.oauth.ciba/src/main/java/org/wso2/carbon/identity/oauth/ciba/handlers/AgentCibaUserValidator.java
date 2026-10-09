/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;

import java.util.Map;

/**
 * {@link CibaUserValidator} that is executed only for the agent CIBA (on-behalf-of) flow.
 * <p>
 * When an agent runs CIBA with its own token as the {@code actor_token}, this validator enforces
 * owner binding: the user resolved from the {@code login_hint} must be the owner of the acting
 * agent. The agent owner is read from the {@code agent_owner} claim carried in the actor token.
 * The claim name under which that value appears in the token is resolved via the OIDC dialect
 * ({@value CibaConstants#OIDC_DIALECT}): the external OIDC claim URI mapped to the local claim
 * {@value CibaConstants#AGENT_OWNER_CLAIM_URI}.
 */
public class AgentCibaUserValidator implements CibaUserValidator {

    private static final Log log = LogFactory.getLog(AgentCibaUserValidator.class);

    @Override
    public boolean isApplicable(CibaAuthCodeRequest cibaAuthCodeRequest) {

        // Applies only to the agent CIBA flow: agent identity enabled and an actor is present.
        return IdentityUtil.isAgentIdentityEnabled() && cibaAuthCodeRequest != null
                && StringUtils.isNotBlank(cibaAuthCodeRequest.getRequestedActor());
    }

    @Override
    public void validate(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeRequest cibaAuthCodeRequest,
                         String tenantDomain) throws CibaClientException, CibaCoreException {

        if (resolvedUser == null) {
            throw new CibaClientException("Cannot validate agent owner binding: resolved user is null.");
        }

        Map<String, String> actorTokenClaims = cibaAuthCodeRequest.getActorTokenClaims();
        if (actorTokenClaims == null || actorTokenClaims.isEmpty()) {
            throw new CibaClientException("Actor token claims are not available to validate agent owner binding.");
        }

        // Resolve the token claim name that carries the agent owner value via the OIDC dialect.
        String ownerClaimName = resolveAgentOwnerClaimName(tenantDomain);
        if (StringUtils.isBlank(ownerClaimName)) {
            if (log.isDebugEnabled()) {
                log.debug("The agent owner claim (" + CibaConstants.AGENT_OWNER_CLAIM_URI +
                        ") is not mapped in the OIDC dialect. Skipping agent owner binding validation.");
            }
            return;
        }

        String agentOwner = actorTokenClaims.get(ownerClaimName);
        if (StringUtils.isBlank(agentOwner)) {
            if (log.isDebugEnabled()) {
                log.debug("The agent owner claim is missing in the actor token. " +
                        "Skipping agent owner binding validation.");
            }
            return;
        }

        if (!matchesResolvedUser(agentOwner, resolvedUser)) {
            if (log.isDebugEnabled()) {
                log.debug("Agent owner binding failed for CIBA request from client: " +
                        cibaAuthCodeRequest.getIssuer() + ". Resolved user does not match the agent owner.");
            }
            throw new CibaClientException("The CIBA user does not match the owner of the acting agent.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Agent owner binding validated for CIBA request from client: " +
                    cibaAuthCodeRequest.getIssuer());
        }
    }

    /**
     * Resolves the token claim name that carries the agent owner value, by looking up the OIDC
     * dialect ({@value CibaConstants#OIDC_DIALECT}) external claim mapped to the local agent owner
     * claim ({@value CibaConstants#AGENT_OWNER_CLAIM_URI}).
     *
     * @param tenantDomain The tenant domain.
     * @return The OIDC (token) claim name for the agent owner, or {@code null} if not mapped.
     * @throws CibaCoreException If the OIDC claim mapping could not be retrieved.
     */
    private String resolveAgentOwnerClaimName(String tenantDomain) throws CibaCoreException {

        try {
            Map<String, String> localToOidcClaimMap = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(CibaConstants.OIDC_DIALECT, null, tenantDomain, true);
            return localToOidcClaimMap.get(CibaConstants.AGENT_OWNER_CLAIM_URI);
        } catch (ClaimMetadataException e) {
            throw new CibaCoreException("Error resolving the OIDC claim mapping for the agent owner claim: "
                    + CibaConstants.AGENT_OWNER_CLAIM_URI, e);
        }
    }

    /**
     * Checks whether the agent owner value refers to the resolved user. The owner is expected in the
     * form {@code <userId>@<tenantDomain>}, but a bare user ID is also accepted.
     *
     * @param agentOwner   The agent owner value from the actor token.
     * @param resolvedUser The user resolved from the CIBA request.
     * @return {@code true} if the owner refers to the resolved user.
     */
    private boolean matchesResolvedUser(String agentOwner, CibaUserResolver.ResolvedUser resolvedUser) {

        String userId = resolvedUser.getUserId();
        if (StringUtils.isBlank(userId)) {
            return false;
        }
        String expectedWithTenant = userId + "@" + resolvedUser.getTenantDomain();
        if (agentOwner.equalsIgnoreCase(expectedWithTenant) || agentOwner.equalsIgnoreCase(userId)) {
            return true;
        }
        // Fall back to comparing the user ID portion before the tenant suffix.
        int atIndex = agentOwner.lastIndexOf('@');
        if (atIndex > 0) {
            return agentOwner.substring(0, atIndex).equalsIgnoreCase(userId);
        }
        return false;
    }
}
