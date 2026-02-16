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

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Cache storing OAuth client secrets metadata indexed by consumer key.
 * <p>
 * Key   : consumerKey (client_id)
 * Value : OAuthClientSecretsCacheEntry
 * </p>
 */
public class OAuthClientSecretsCache
        extends AuthenticationBaseCache<String, OAuthClientSecretsCacheEntry> {

    private static final String CACHE_NAME = "OAuthClientSecretsCache";
    private static volatile OAuthClientSecretsCache instance;

    private OAuthClientSecretsCache() {
        super(CACHE_NAME);
    }

    /**
     * Returns the singleton instance of the client secrets cache.
     *
     * @return OAuthClientSecretsCache instance
     */
    public static OAuthClientSecretsCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OAuthClientSecretsCache.class) {
                if (instance == null) {
                    instance = new OAuthClientSecretsCache();
                }
            }
        }
        return instance;
    }
}

