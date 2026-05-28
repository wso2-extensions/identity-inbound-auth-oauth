/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.cache.BaseCache;

/**
 * Cache for the graceful refresh token reuse count, keyed by tokenId.
 * Avoids a DB round-trip for the reuse count on every graceful refresh token rotation.
 */
public class RefreshTokenCache
        extends BaseCache<RefreshTokenCacheKey, RefreshTokenCacheEntry> {

    private static final Log LOG = LogFactory.getLog(RefreshTokenCache.class);
    private static final String REFRESH_TOKEN_CACHE = "RefreshTokenCache";
    private static volatile RefreshTokenCache instance;

    private RefreshTokenCache() {

        super(REFRESH_TOKEN_CACHE);
    }

    public static RefreshTokenCache getInstance() {

        if (instance == null) {
            synchronized (RefreshTokenCache.class) {
                if (instance == null) {
                    instance = new RefreshTokenCache();
                }
            }
        }
        return instance;
    }

    public void addToCache(RefreshTokenCacheKey key,
                           RefreshTokenCacheEntry entry, int tenantId) {

        super.addToCache(key, entry, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Graceful refresh token reuse count " + entry.getGracefulReuseCount()
                    + " added to cache for key: " + key.getCacheKeyString());
        }
    }

    public void addToCacheOnRead(RefreshTokenCacheKey key,
                                 RefreshTokenCacheEntry entry, int tenantId) {

        super.addToCacheOnRead(key, entry, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("[AddToCacheOnRead] Graceful refresh token reuse count " + entry.getGracefulReuseCount()
                    + " added to cache for key: " + key.getCacheKeyString());
        }
    }

    public RefreshTokenCacheEntry getValueFromCache(
            RefreshTokenCacheKey key, int tenantId) {

        RefreshTokenCacheEntry entry = super.getValueFromCache(key, tenantId);
        if (LOG.isDebugEnabled()) {
            if (entry != null) {
                LOG.debug("Graceful refresh token reuse count cache hit for key: " + key.getCacheKeyString()
                        + ", reuse count: " + entry.getGracefulReuseCount());
            } else {
                LOG.debug("Graceful refresh token reuse count cache miss for key: " + key.getCacheKeyString());
            }
        }
        return entry;
    }

    public void clearCacheEntry(RefreshTokenCacheKey key, int tenantId) {

        super.clearCacheEntry(key, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Graceful refresh token reuse count cache entry cleared for key: " + key.getCacheKeyString()
                    + " in tenant: " + tenantId);
        }
    }
}
