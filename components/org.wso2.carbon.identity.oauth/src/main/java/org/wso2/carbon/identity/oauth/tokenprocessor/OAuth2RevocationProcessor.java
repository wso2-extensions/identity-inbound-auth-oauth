/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

/**
 * Abstraction layer between OAuth2Service and persistence layer to handle revocation logic during token persistence
 * and non-persistence scenarios.
 */
public interface OAuth2RevocationProcessor {

    /**
     * Revoke access token.
     *
     * @param revokeRequestDTO Metadata containing revoke token request.
     * @param accessTokenDO    {@link AccessTokenDO} instance.
     * @throws IdentityOAuth2Exception If an error occurs while revoking the access token.
     * @throws UserIdNotFoundException If the user id is not found.
     */
    void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception, UserIdNotFoundException;

    /**
     * Revoke refresh token.
     *
     * @param revokeRequestDTO Metadata containing revoke token request.
     * @param refreshTokenDO   {@link RefreshTokenValidationDataDO} instance.
     * @throws IdentityOAuth2Exception If an error occurs while revoking the refresh token.
     */
    void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                            RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception;

    /**
     * Handle indirect token revocation for internal user events.
     *
     * @param username         User on which the event occurred.
     * @param userStoreManager User store manager.
     * @return true if revocation is successful. Else return false.
     * @throws UserStoreException If an error occurs while revoking tokens for users.
     */
    boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException;
}
