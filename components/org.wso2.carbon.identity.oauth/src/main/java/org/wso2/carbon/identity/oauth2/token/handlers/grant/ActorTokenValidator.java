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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.util.Optional;

/**
 * Utility class to validate an actor token JWT and extract the actor subject.
 * Used by both the authorization code grant flow (at /token time) and the
 * CIBA grant flow (at /ciba backchannel authentication request time).
 */
public class ActorTokenValidator {

    private static final Log log = LogFactory.getLog(ActorTokenValidator.class);

    private ActorTokenValidator() {
    }

    /**
     * Holds the extracted claims from a validated actor token.
     */
    public static class ActorTokenClaims {

        private final String subject;
        private final String azp;
        private final Object existingActClaim;

        ActorTokenClaims(String subject, String azp, Object existingActClaim) {
            this.subject = subject;
            this.azp = azp;
            this.existingActClaim = existingActClaim;
        }

        public String getSubject() {
            return subject;
        }

        public String getAzp() {
            return azp;
        }

        public Object getExistingActClaim() {
            return existingActClaim;
        }
    }

    /**
     * Validates the actor token JWT and returns the actor's subject claim.
     *
     * @param actorToken   Raw JWT string representing the actor token.
     * @param tenantDomain Tenant domain used for IDP lookup and issuer validation.
     * @return The actor's {@code sub} claim value.
     * @throws IdentityOAuth2Exception If the JWT is invalid, the signature fails,
     *                                 the token is expired, or the issuer is unexpected.
     */
    public static String validateAndGetSubject(String actorToken, String tenantDomain)
            throws IdentityOAuth2Exception {

        return validateAndExtractClaims(actorToken, tenantDomain).getSubject();
    }

    /**
     * Validates the actor token JWT and returns the extracted actor claims including
     * the subject, {@code azp}/{@code client_id}, and existing {@code act} claim.
     *
     * @param actorToken   Raw JWT string representing the actor token.
     * @param tenantDomain Tenant domain used for IDP lookup and issuer validation.
     * @return {@link ActorTokenClaims} containing the subject, azp, and existing act claim.
     * @throws IdentityOAuth2Exception If the JWT is invalid, the signature fails,
     *                                 the token is expired, or the issuer is unexpected.
     */
    public static ActorTokenClaims validateAndExtractClaims(String actorToken, String tenantDomain)
            throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        try {
            signedJWT = JWTUtils.parseJWT(actorToken);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while parsing the actor token JWT.", e);
        }

        Optional<JWTClaimsSet> claimsSetOptional = JWTUtils.getJWTClaimSet(signedJWT);
        JWTClaimsSet claimsSet = claimsSetOptional.orElseThrow(() ->
                new IdentityOAuth2Exception("Claim values are empty in the given actor token."));

        JWTUtils.validateMandatoryClaims(claimsSet);

        String jwtIssuer = claimsSet.getIssuer();
        IdentityProvider identityProvider = OAuth2Util.getIdentityProviderWithJWTIssuer(jwtIssuer, tenantDomain);

        if (!JWTSignatureValidationUtils.validateSignature(signedJWT, identityProvider, tenantDomain)) {
            throw new IdentityOAuth2Exception("Signature or message authentication invalid for actor token.");
        }
        if (log.isDebugEnabled()) {
            log.debug("Signature/MAC validated successfully for actor token.");
        }

        if (!JWTUtils.checkExpirationTime(claimsSet.getExpirationTime())) {
            throw new IdentityOAuth2ClientException("Actor token has expired.");
        }
        JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());

        String expectedIssuer = OAuth2Util.getIdTokenIssuer(tenantDomain);
        if (!StringUtils.equals(expectedIssuer, jwtIssuer)) {
            throw new IdentityOAuth2Exception("Invalid issuer in the actor token. Expected: " + expectedIssuer
                    + ", Received: " + jwtIssuer);
        }

        // Extract azp/client_id and existing act claim for delegation chain processing.
        Object azpClaim = claimsSet.getClaim("azp");
        if (azpClaim == null) {
            // Fallback to client_id if azp not present.
            azpClaim = claimsSet.getClaim("client_id");
        }
        Object existingActClaim = claimsSet.getClaim("act");

        return new ActorTokenClaims(
                claimsSet.getSubject(),
                azpClaim != null ? azpClaim.toString() : null,
                existingActClaim
        );
    }
}
