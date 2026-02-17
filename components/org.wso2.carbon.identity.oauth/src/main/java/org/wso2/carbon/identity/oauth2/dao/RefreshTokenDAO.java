/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;

import java.util.Set;

/**
 * Refresh token related data access interface for Non-Persistence Access token scenarios.
 */
public interface RefreshTokenDAO {

    /**
     * Inserts a refresh token into the database.
     *
     * @param accessToken       The access token associated with the refresh token.
     * @param consumerKey       The consumer key of the application.
     * @param accessTokenDO     The AccessTokenDO object containing details of the access token.
     * @param userStoreDomain   The user store domain of the authenticated user.
     * @throws IdentityOAuth2Exception If an error occurs while inserting the refresh token.
     */
    void insertRefreshToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                           String userStoreDomain) throws IdentityOAuth2Exception;

    /**
     * Inserts a refresh token into the database, with an option to update an existing access token.
     *
     * @param accessToken            The access token associated with the refresh token.
     * @param consumerKey            The consumer key of the application.
     * @param newAccessTokenDO       The new AccessTokenDO object containing details of the access token.
     * @param existingAccessTokenDO  The existing AccessTokenDO object to be updated, if applicable.
     * @param rawUserStoreDomain     The user store domain of the authenticated user.
     * @return true if the refresh token was inserted successfully, false otherwise.
     * @throws IdentityOAuth2Exception If an error occurs while inserting the refresh token.
     */
    boolean insertRefreshToken(String accessToken, String consumerKey,
                              AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO,
                              String rawUserStoreDomain) throws IdentityOAuth2Exception;

    /**
     * Retrieves an active refresh token for a given consumer key, authenticated user, user store domain, and scope.
     *
     * @param consumerKey      The consumer key of the application.
     * @param authzUser        The authenticated user.
     * @param userStoreDomain  The user store domain of the authenticated user.
     * @param scope            The scope of the access token.
     * @return An AccessTokenDO object representing the active refresh token.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the refresh token.
     */
    AccessTokenDO getActiveRefreshToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                               String scope) throws IdentityOAuth2Exception;

    /**
     * Invalidates the existing refresh token and creates a new one.
     *
     * @param tokenId              The ID of the existing refresh token to be invalidated.
     * @param tokenStateInactive   The state to set for the existing refresh token (e.g., inactive).
     * @param clientId             The client ID associated with the refresh token.
     * @param accessTokenBean      The AccessTokenDO object containing details of the new access token.
     * @param userStoreDomain      The user store domain of the authenticated user.
     * @throws IdentityOAuth2Exception If an error occurs while invalidating and creating a new refresh token.
     */
    void invalidateAndCreateNewRefreshToken(String tokenId, String tokenStateInactive, String clientId,
                                            AccessTokenDO accessTokenBean, String userStoreDomain)
            throws IdentityOAuth2Exception;

    /**
     * Revokes a refresh token.
     *
     * @param refreshToken The refresh token to be revoked.
     * @throws IdentityOAuth2Exception If an error occurs while revoking the refresh token.
     */
    void revokeToken(String refreshToken) throws IdentityOAuth2Exception;

    /**
     * Validates a refresh token and retrieves associated data.
     *
     * @param consumerKey   The consumer key of the application.
     * @param refreshToken  The refresh token to validate.
     * @return A RefreshTokenValidationDataDO object containing validation data.
     * @throws IdentityOAuth2Exception If an error occurs during validation.
     */
    RefreshTokenValidationDataDO validateRefreshToken(String consumerKey, String refreshToken)
            throws IdentityOAuth2Exception;

    /**
     * Retrieves a refresh token by its value.
     *
     * @param refreshToken The refresh token to retrieve.
     * @return An AccessTokenDO object representing the refresh token.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the refresh token.
     */
    AccessTokenDO getRefreshToken(String refreshToken) throws IdentityOAuth2Exception;

    /**
     * Revokes all refresh tokens associated with a specific application identified by its consumer key.
     *
     * @param consumerKey The consumer key of the application for which to revoke tokens.
     * @throws IdentityOAuth2Exception If an error occurs while revoking the tokens.
     */
    void revokeTokensForApp(String consumerKey) throws IdentityOAuth2Exception;

    /**
     * Revokes all refresh tokens associated with a specific user in a given tenant and user store domain.
     *
     * @param authenticatedUser The authenticated user whose tokens are to be revoked.
     * @param tenantId          The tenant ID of the user.
     * @param userStoreDomain   The user store domain of the authenticated user.
     * @throws IdentityOAuth2Exception If an error occurs while revoking the tokens.
     */
    void revokeTokensByUser(AuthenticatedUser authenticatedUser, int tenantId, String userStoreDomain)
            throws IdentityOAuth2Exception;

    /**
     * Retrieves all refresh tokens for a specific user with the 'openid' scope.
     *
     * @param authenticatedUser The authenticated user whose tokens are to be retrieved.
     * @return A set of AccessTokenDO objects representing the access tokens for the user with 'openid' scope.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the access tokens.
     */
    Set<AccessTokenDO> getRefreshTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception;
}
