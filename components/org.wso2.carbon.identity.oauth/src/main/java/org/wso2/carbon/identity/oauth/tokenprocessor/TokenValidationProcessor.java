/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

/**
 * Token validation Processor.
 */
public interface TokenValidationProcessor {

    /**
     * Validate token.
     *
     * @param accessToken    access token
     * @param includeExpired include expired tokens
     * @return AccessTokenDO
     * @throws IdentityOAuth2Exception if an error occurred while validating the token
     */
    AccessTokenDO validateToken(String accessToken, boolean includeExpired) throws IdentityOAuth2Exception;
}
