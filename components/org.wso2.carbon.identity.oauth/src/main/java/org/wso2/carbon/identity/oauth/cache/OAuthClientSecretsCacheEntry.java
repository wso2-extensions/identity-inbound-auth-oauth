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

import java.util.Collections;
import java.util.List;

/**
 * Cache entry holding all secrets of a given OAuth client.
 *
 * Cache entries are immutable snapshots and replaced on update.
 * This ensures thread-safety and prevents partially visible or inconsistent state
 * when multiple threads access the cache concurrently.
 */
public final class OAuthClientSecretsCacheEntry extends CacheEntry {

    private final List<OAuthClientSecretMetadata> secrets;

    /**
     * Creates an empty cache entry with no secrets.
     */
    public OAuthClientSecretsCacheEntry(List<OAuthClientSecretMetadata> secrets) {

        this.secrets = Collections.unmodifiableList(secrets);
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
}

