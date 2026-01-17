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

import java.util.ArrayList;
import java.util.List;

/**
 * Cache entry holding all secrets of a given OAuth client.
 * <p>
 * This entry is immutable to ensure thread safety.
 * </p>
 */
public final class OAuthClientSecretsCacheEntry extends CacheEntry {

    private final List<OAuthClientSecretMetadata> secrets;

    /**
     * Creates an empty cache entry with no secrets.
     */
    public OAuthClientSecretsCacheEntry() {

        this.secrets = new ArrayList<>();
    }

    /**
     * @return Immutable list of client secret metadata
     */
    public List<OAuthClientSecretMetadata> getSecrets() {

        return secrets;
    }

    /**
     * @return true if the cache entry contains no secrets
     */
    public boolean isEmpty() {

        return secrets.isEmpty();
    }

    /**
     * Adds a secret metadata entry to this cache entry.
     *
     * <p>If the secret already exists (same hash), this operation is idempotent.</p>
     *
     * @param metadata metadata of the secret to add
     */
    public void addSecret(OAuthClientSecretMetadata metadata) {

        if (metadata != null) {
            secrets.add(metadata);
        }
    }
}

