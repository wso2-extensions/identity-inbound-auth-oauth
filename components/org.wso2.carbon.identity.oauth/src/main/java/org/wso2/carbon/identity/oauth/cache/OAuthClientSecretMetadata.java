/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.cache;

/**
 * Holds non-sensitive metadata of an OAuth client secret.
 * <p>
 * This class intentionally does NOT store the raw client secret.
 * Only the hashed secret and expiration timestamp are cached.
 * </p>
 */
public final class OAuthClientSecretMetadata {

    private final String secretHash;
    private final Long expiresAt;

    /**
     * Creates a metadata entry for a client secret.
     *
     * @param secretHash Hashed form of the client secret stored in DB
     * @param expiresAt Expiration timestamp in milliseconds since epoch.
     *                  Null means the secret does not expire.
     */
    public OAuthClientSecretMetadata(String secretHash, Long expiresAt) {

        this.secretHash = secretHash;
        this.expiresAt = expiresAt;
    }

    /**
     * @return Hashed client secret
     */
    public String getSecretHash() {

        return secretHash;
    }

    /**
     * @return Expiration time in milliseconds since epoch, or null if non-expiring
     */
    public Long getExpiresAt() {

        return expiresAt;
    }
}

