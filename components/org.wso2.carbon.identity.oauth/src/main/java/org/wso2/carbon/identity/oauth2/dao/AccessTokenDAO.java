/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Access token related data access interface.
 */
public interface AccessTokenDAO {

    void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                           String userStoreDomain) throws IdentityOAuth2Exception;

    boolean insertAccessToken(String accessToken, String consumerKey,
                              AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO,
                              String rawUserStoreDomain) throws IdentityOAuth2Exception;

    AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                       String scope, boolean includeExpiredTokens) throws IdentityOAuth2Exception;

    /**
     * Get latest access token.
     *
     * @param consumerKey consumer key.
     * @param authzUser authorized user.
     * @param userStoreDomain user store domain.
     * @param scope scope.
     * @param tokenBindingReference token binding reference.
     * @param includeExpiredTokens include expired tokens.
     * @return latest access token.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    default AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
            String scope, String tokenBindingReference, boolean includeExpiredTokens) throws IdentityOAuth2Exception {

        return getLatestAccessToken(consumerKey, authzUser, userStoreDomain, scope, includeExpiredTokens);
    }

    /**
     * Get latest access token.
     *
     * @param consumerKey Consumer key.
     * @param appTenantDomain Application tenant domain.
     * @param authzUser Authorized user.
     * @param userStoreDomain User store domain
     * @param scope Scope.
     * @param tokenBindingReference Token binding reference
     * @param includeExpiredTokens Include expired tokens.
     * @return Latest access token.
     * @throws IdentityOAuth2Exception If any error occurred while getting latest access token.
     */
    default AccessTokenDO getLatestAccessToken(String consumerKey, String appTenantDomain, AuthenticatedUser authzUser,
            String userStoreDomain, String scope, String tokenBindingReference, boolean includeExpiredTokens)
        throws IdentityOAuth2Exception {

        return getLatestAccessToken(consumerKey, authzUser, userStoreDomain, scope, tokenBindingReference,
                includeExpiredTokens);
    }

    /**
     * Get tokenId by binding reference.
     * @param bindingRef BindingRef.
     * @return TokenId.
     * @throws IdentityOAuth2Exception
     */
    default Set<String> getTokenIdBySessionIdentifier(String bindingRef) throws IdentityOAuth2Exception {

        return null;
    }

    /**
     * Store tokenId to sessioncontext identifier mapping.
     * @param sessionIdentifier SessionIdentifier.
     * @param tokenId TokenId.
     * @param tenantId TenantId.
     * @throws IdentityOAuth2Exception
     */
    default void storeTokenToSessionMapping(String sessionIdentifier, String tokenId, int tenantId)
            throws IdentityOAuth2Exception {

    }

    /**
     * Get session identifier by token identifier.
     *
     * @param tokenId Token identifier.
     * @return Session identifier.
     * @throws IdentityOAuth2Exception
     */
    default String getSessionIdentifierByTokenId(String tokenId) throws IdentityOAuth2Exception {

        return null;
    }

    Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName,
                                       String userStoreDomain, boolean includeExpired) throws IdentityOAuth2Exception;

    default Set<AccessTokenDO> getAccessTokens(String consumerKey, String appTenantDomain,
            AuthenticatedUser userName, String userStoreDomain, boolean includeExpired)
            throws IdentityOAuth2Exception {

        return getAccessTokens(consumerKey, userName, userStoreDomain, includeExpired);
    }

    AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired) throws IdentityOAuth2Exception;

    Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception;

    /**
     * @deprecated Use {@link #getAccessTokensByUserForOpenidScope(AuthenticatedUser, boolean)} instead.
     */
    @Deprecated
    default Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        return null;
    }

    default Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser,
            boolean includeExpiredAccessTokensWithActiveRefreshToken) throws IdentityOAuth2Exception {

        return getAccessTokensByUserForOpenidScope(authenticatedUser);
    }

    Set<String> getActiveTokensByConsumerKey(String consumerKey) throws IdentityOAuth2Exception;

    Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception;

    default Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey, String appTenantDomain)
            throws IdentityOAuth2Exception {

        return getActiveAcessTokenDataByConsumerKey(consumerKey);
    }

    Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) throws IdentityOAuth2Exception;

    default Set<AccessTokenDO> getAccessTokensByAuthorizedOrg(String organizationId) throws IdentityOAuth2Exception {

        return Collections.emptySet();
    }

    Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) throws
            IdentityOAuth2Exception;

    /**
     * This method is to revoke specific tokens where tokens should be plain text tokens.
     *
     * @param tokens tokens that needs to be revoked
     * @throws IdentityOAuth2Exception if failed to revoke the access token
     */
    void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception;

    void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception;

    void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception;

    /**
     * This method is to revoke specific tokens where tokens can be plain text tokens or hashed tokens. Hashed tokens
     * can be reached here from internal calls such as from any listeners ex: IdentityOathEventListener etc. We need
     * to differentiate this types of internal calls hence these calls retrieved the tokens from the DB and then try
     * to revoke it.
     * When the Token Hashing Feature enabled, the token which is retrieve from the DB will be a hashed token. Hence
     * we don't need to hash it again.
     *
     * @param tokens        Tokens that needs to be revoked.
     * @param isHashedToken Indicate provided token is a hashed token or plain text token.
     * @throws IdentityOAuth2Exception if failed to revoke the access token
     */
    default void revokeAccessTokens(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
    }

    /**
     * Revoke the access token(s) as a batch.
     *
     * @param tokens        Token that needs to be revoked.
     * @param isHashedToken Given token is hashed token or plain text.
     * @throws IdentityOAuth2Exception
     */
    default void revokeAccessTokensInBatch(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
    }

    /**
     * Revoke the access token(s) individually.
     *
     * @param tokens        Token that needs to be revoked.
     * @param isHashedToken Given token is hashed token or plain text.
     * @throws IdentityOAuth2Exception
     */
    default void revokeAccessTokensIndividually(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
    }

    void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception;

    void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                           String tokenStateId, AccessTokenDO accessTokenDO,
                                           String userStoreDomain) throws IdentityOAuth2Exception;

    default void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                   String tokenStateId, AccessTokenDO accessTokenDO,
                                                   String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception {
        invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey, tokenStateId, accessTokenDO,
                userStoreDomain);
    }

    /**
     * Performs a graceful rotation of the refresh token: instead of marking the previous token INACTIVE, the
     * previous row is set to {@code oldTokenNewState} with a fresh TOKEN_STATE_ID assigned to avoid the unique
     * constraint conflict with the new ACTIVE token row that is inserted in the same transaction. The grace deadline
     * is persisted as an extended attribute in {@code oldTokenExtendedAttributeUpdates}. Additionally, upserts the
     * provided key/value pairs onto the old token row's extended-attribute store within the same transaction.
     *
     * <p><b>Default fallback behaviour for custom DAO implementations that have not overridden this method:</b>
     * <ul>
     *   <li><b>First rotation</b> ({@code oldTokenNewStateId} is non-null): delegates to
     *       {@link #invalidateAndCreateNewAccessToken} using the caller-supplied {@code oldTokenNewState}
     *       (typically {@code GRACEFULLY_ROTATED}). Extended-attribute updates are silently dropped because
     *       the legacy method has no attribute-store path.</li>
     *   <li><b>Reuse rotation</b> ({@code oldTokenNewStateId} is {@code null}): degrades to a standard
     *       (non-graceful) rotation — the old token is marked {@code INACTIVE} and a new token is created via
     *       {@link #invalidateAndCreateNewAccessToken}. The grace window and extended-attribute updates are
     *       silently dropped. Custom DAO implementations should override this method to support true graceful
     *       refresh token reuse.</li>
     * </ul>
     *
     * @param oldAccessTokenId                 old access token id
     * @param oldRefreshTokenIssuedTime        refresh token issued time of the previous token
     * @param oldTokenNewStateId               new TOKEN_STATE_ID for the previous token row; pass {@code null}
     *                                         on graceful reuses (newReuseCount &gt; 0) to skip updating the old
     *                                         row's state (preserves the original grace deadline)
     * @param oldTokenNewState                 new TOKEN_STATE for the previous token row; only applied when
     *                                         {@code oldTokenNewStateId} is non-null
     * @param consumerKey                      consumer key
     * @param accessTokenDO                    new access token to persist
     * @param userStoreDomain                  user store domain
     * @param grantType                        grant type of the previous token
     * @param oldTokenExtendedAttributeUpdates key/value pairs to upsert on the old token row
     * @throws IdentityOAuth2Exception on persistence failure
     */
    default void gracefullyRotateAndCreateNewAccessToken(String oldAccessTokenId,
                                                         Timestamp oldRefreshTokenIssuedTime,
                                                         String oldTokenNewStateId, String oldTokenNewState,
                                                         String consumerKey,
                                                         AccessTokenDO accessTokenDO, String userStoreDomain,
                                                         String grantType,
                                                         Map<String, String> oldTokenExtendedAttributeUpdates)
            throws IdentityOAuth2Exception {

        if (oldTokenNewStateId == null) {
            // Reuse path: graceful semantics unsupported in the legacy DAO path. Degrade to a standard
            // rotation so the flow still produces a valid new token. Grace window and attribute updates
            // are silently dropped — override this method for full graceful reuse support.
            invalidateAndCreateNewAccessToken(oldAccessTokenId,
                    OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, consumerKey,
                    UUID.randomUUID().toString(), accessTokenDO, userStoreDomain, grantType);
            return;
        }
        // First-rotation fallback: honour the caller's state (typically GRACEFULLY_ROTATED) instead of
        // hardcoding INACTIVE. Extended-attribute updates are silently dropped — the legacy method has
        // no path for them; this is documented in the javadoc.
        invalidateAndCreateNewAccessToken(oldAccessTokenId, oldTokenNewState, consumerKey,
                oldTokenNewStateId, accessTokenDO, userStoreDomain, grantType);
    }

    default String getAccessTokenExtendedAttributeValue(String tokenId, String attributeName,
            String userStoreDomain) throws IdentityOAuth2Exception {

        return null;
    }

    void updateUserStoreDomain(int tenantId, String currentUserStoreDomain,
                               String newUserStoreDomain) throws IdentityOAuth2Exception;

    String getTokenIdByAccessToken(String token) throws IdentityOAuth2Exception;

    List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                              String userStoreDomain, String scope,
                                              boolean includeExpiredTokens, int limit) throws IdentityOAuth2Exception;

    /**
     * Get latest access tokens.
     *
     * @param consumerKey consumer key.
     * @param authzUser authorized user.
     * @param userStoreDomain user store domain.
     * @param scope scope.
     * @param tokenBindingReference token binding reference.
     * @param includeExpiredTokens include expired tokens.
     * @param limit limit.
     * @return list of latest access tokens.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    default List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
            String userStoreDomain, String scope, String tokenBindingReference, boolean includeExpiredTokens, int limit)
            throws IdentityOAuth2Exception {

        return getLatestAccessTokens(consumerKey, authzUser, userStoreDomain, scope, includeExpiredTokens, limit);
    }

    default AccessTokenDO getActiveTokenByExtendedAttribute(String attributeName, String attributeValue,
                                                            String userStoreDomain)
            throws IdentityOAuth2Exception {

        return null;
    }

    /**
     * Update access token to the given state.
     *
     * @param tokenId         ID of the access token to update the state.
     * @param tokenState      state to update.
     * @deprecated to use {{@link #updateAccessTokenState(String, String, String)}}
     * @throws IdentityOAuth2Exception
     */
    void updateAccessTokenState(String tokenId, String tokenState) throws IdentityOAuth2Exception;

    /**
     * Update access token to the given state.
     *
     * @param tokenId         ID of the access token to update the state.
     * @param tokenState      state to update.
     * @param grantType      state to update.
     * @throws IdentityOAuth2Exception
     */
    default void updateAccessTokenState(String tokenId, String tokenState, String grantType)
            throws IdentityOAuth2Exception {
        updateAccessTokenState(tokenId, tokenState);
    }

    default Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(String consumerKey)
            throws IdentityOAuth2Exception {

        return Collections.emptySet();
    }

    default Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyAndScope(String consumerKey,
                                                                                  List<String> scopes)
            throws IdentityOAuth2Exception {

        return Collections.emptySet();
    }

    default Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyAndScope(String consumerKey,
            String appTenantDomain, List<String> scopes) throws IdentityOAuth2Exception {

        return getActiveTokenSetWithTokenIdByConsumerKeyAndScope(consumerKey, scopes);
    }

    /**
     * Retrieve the active access tokens of a given user with a given access token binding reference.
     *
     * @param user       authenticated user
     * @param bindingRef access token binding reference
     * @return set of active access objects
     * @throws IdentityOAuth2Exception if the retrieval process fails
     */
    default Set<AccessTokenDO> getAccessTokensByBindingRef(AuthenticatedUser user, String bindingRef) throws
            IdentityOAuth2Exception {

        return null;
    }

    /**
     * Retrieve the active access tokens with a given access token binding reference.
     *
     * @param bindingRef access token binding reference
     * @return set of active access objects
     * @throws IdentityOAuth2Exception if the retrieval process fails
     */
    default Set<AccessTokenDO> getAccessTokensByBindingRef(String bindingRef) throws IdentityOAuth2Exception {

        return Collections.emptySet();
    }

    /**
     * Retrieve the access token for a given token id.
     *
     * @param tokenId token id.
     * @return access token.
     * @throws IdentityOAuth2Exception if the retrieval process fails.
     */
    default String getAccessTokenByTokenId(String tokenId) throws IdentityOAuth2Exception {

        return null;
    }

    /**
     * Updates whether the token is issued for a consent required grant.
     *
     * @param tokenId ID of the token.
     * @param isConsentedGrant Grant type which the corresponding token is issued.
     * @throws IdentityOAuth2Exception If there are any failures in update.
     */
    default void updateTokenIsConsented(String tokenId, boolean isConsentedGrant)
            throws IdentityOAuth2Exception {
    }
}
