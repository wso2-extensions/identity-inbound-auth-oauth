/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.util.Optional;

/**
 * This class represents the token binding DO.
 */
public interface TokenBindingMgtDAO {

    /**
     * Get access token binding by token id.
     *
     * @param tokenId token id.
     * @return token binding optional.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    Optional<TokenBinding> getTokenBinding(String tokenId) throws IdentityOAuth2Exception;

    /**
     * Get access token binding by token id and binding reference.
     *
     * @param tokenId    Token id.
     * @param bindingRef Binding reference.
     * @return Token binding optional.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    default Optional<TokenBinding> getTokenBindingByBindingRef(String tokenId, String bindingRef)
            throws IdentityOAuth2Exception {

        return Optional.empty();
    }

    /**
     * Check whether the token binding exists for the token binding reference.
     *
     * @param tokenBindingReference token binding reference.
     * @return true if token binding reference exists.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    boolean isTokenBindingExistsForBindingReference(String tokenBindingReference) throws IdentityOAuth2Exception;

    /**
     * Store access token binding.
     *
     * @param tokenBinding token binding.
     * @param tenantId tenant id.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    void storeTokenBinding(TokenBinding tokenBinding, int tenantId) throws IdentityOAuth2Exception;

    /**
     * Delete access token binding.
     *
     * @param tokenId token id.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    void deleteTokenBinding(String tokenId) throws IdentityOAuth2Exception;

    /**
     * Obtain token binding from refresh token.
     *
     * @param refreshToken Refresh token sent in the request.
     * @param isTokenHashingEnabled Whether token hashing is enabled.
     * @return  Optional token binding for the refresh token.
     * @throws IdentityOAuth2Exception An exception is thrown if an error occurs while obtaining the token binding.
     */
    default Optional<TokenBinding> getBindingFromRefreshToken(String refreshToken, boolean isTokenHashingEnabled)
            throws IdentityOAuth2Exception {

        return Optional.empty();
    }
}
