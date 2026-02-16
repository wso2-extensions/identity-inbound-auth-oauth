/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.util.Date;

/**
 * Interface to access and manage revoked token information.
 */
public interface RevokedTokenPersistenceDAO {

    /**
     * Check if a token is marked as revoked due to direct token revocations.
     *
     * @param token       The token to check.
     * @param consumerKey The consumer key associated with the token.
     * @return {@code true} if the token is marked as revoked, {@code false} otherwise.
     * @throws IdentityOAuth2Exception If an error occurs during the check.
     */
    boolean isRevokedToken(String token, String consumerKey) throws IdentityOAuth2Exception;

    /**
     * Mark a token as revoked with its expiry time during generation.
     *
     * @param token       The token to mark as revoked.
     * @param consumerKey The consumer key associated with the token.
     * @param expiryTime  The expiry time set for the token during generation.
     * @throws IdentityOAuth2Exception If an error occurs while marking the token as revoked.
     */
    void addRevokedToken(String token, String consumerKey, Long expiryTime) throws IdentityOAuth2Exception;

    /**
     * Check if a token has been revoked as a result of any changes in the subject principal/entity associated with
     * the token after the token's issuance timestamp.
     *
     * @param entityId        The entity/subject principal ID for which the token was issued for.
     * @param tokenIssuedTime The timestamp at which token was issued.
     * @return {@code true} if the token has been revoked for the specified entity after the given timestamp,
     * {@code false} otherwise.
     * @throws IdentityOAuth2Exception If an error occurs during the token revocation check.
     */
    boolean isTokenRevokedForSubjectEntity(String entityId, Date tokenIssuedTime) throws IdentityOAuth2Exception;

    /**
     * Revoke access tokens based on a user or app event.
     *
     * @param subjectId           The subject identifier for the user.
     * @param subjectIdType       The type of subject identifier.
     * @param revocationTime      The time of the revocation event.
     * @param tenantId              The tenant associated with the revocation.
     * @throws IdentityOAuth2Exception If an error occurs during access token revocation.
     */
    void revokeTokensBySubjectEvent(String subjectId, String subjectIdType, long revocationTime, int tenantId)
            throws IdentityOAuth2Exception;
}
