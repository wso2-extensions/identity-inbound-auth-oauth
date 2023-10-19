/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
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

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

/**
 * The AccessTokenProvider interface defines the contract for classes that are responsible
 * for verifying and providing access tokens. Implementing classes should offer methods
 * to retrieve access tokens based on token identifiers, with verification of the token's
 * validity, ensuring it is in an active or expired state.
 */
public interface AccessTokenProvider {

    /**
     *  token.
     *
     * @param accessToken    access token
     * @param includeExpired include expired tokens
     * @return AccessTokenDO
     * @throws IdentityOAuth2Exception if an error occurred while validating the token
     */
    AccessTokenDO getVerifiedAccessToken(String accessToken, boolean includeExpired) throws IdentityOAuth2Exception;
}

/**
 * Find access tokenDO from token identifier by chaining through all available token issuers.
 *
 * @param tokenIdentifier access token data object from the validation request.
 * @return AccessTokenDO
 * @throws IdentityOAuth2Exception
 */