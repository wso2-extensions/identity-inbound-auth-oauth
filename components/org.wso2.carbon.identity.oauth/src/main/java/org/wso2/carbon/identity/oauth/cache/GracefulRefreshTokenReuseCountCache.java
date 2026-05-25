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
public class GracefulRefreshTokenReuseCountCache
        extends BaseCache<GracefulRefreshTokenReuseCountCacheKey, GracefulRefreshTokenReuseCountCacheEntry> {

    private static final Log log = LogFactory.getLog(GracefulRefreshTokenReuseCountCache.class);
    private static final String GRACEFUL_REFRESH_TOKEN_REUSE_COUNT_CACHE = "GracefulRefreshTokenReuseCountCache";
    private static volatile GracefulRefreshTokenReuseCountCache instance;

    private GracefulRefreshTokenReuseCountCache() {

        super(GRACEFUL_REFRESH_TOKEN_REUSE_COUNT_CACHE);
    }

    public static GracefulRefreshTokenReuseCountCache getInstance() {

        if (instance == null) {
            synchronized (GracefulRefreshTokenReuseCountCache.class) {
                if (instance == null) {
                    instance = new GracefulRefreshTokenReuseCountCache();
                }
            }
        }
        return instance;
    }

    public void addToCache(GracefulRefreshTokenReuseCountCacheKey key,
                           GracefulRefreshTokenReuseCountCacheEntry entry, int tenantId) {

        super.addToCache(key, entry, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Graceful refresh token reuse count " + entry.getReuseCount()
                    + " added to cache for key: " + key.getCacheKeyString());
        }
    }

    public void addToCacheOnRead(GracefulRefreshTokenReuseCountCacheKey key,
                                 GracefulRefreshTokenReuseCountCacheEntry entry, int tenantId) {

        super.addToCacheOnRead(key, entry, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("[AddToCacheOnRead] Graceful refresh token reuse count " + entry.getReuseCount()
                    + " added to cache for key: " + key.getCacheKeyString());
        }
    }

    public GracefulRefreshTokenReuseCountCacheEntry getValueFromCache(
            GracefulRefreshTokenReuseCountCacheKey key, int tenantId) {

        GracefulRefreshTokenReuseCountCacheEntry entry = super.getValueFromCache(key, tenantId);
        if (log.isDebugEnabled()) {
            if (entry != null) {
                log.debug("Graceful refresh token reuse count cache hit for key: " + key.getCacheKeyString()
                        + ", reuse count: " + entry.getReuseCount());
            } else {
                log.debug("Graceful refresh token reuse count cache miss for key: " + key.getCacheKeyString());
            }
        }
        return entry;
    }

    public void clearCacheEntry(GracefulRefreshTokenReuseCountCacheKey key, int tenantId) {

        super.clearCacheEntry(key, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Graceful refresh token reuse count cache entry cleared for key: " + key.getCacheKeyString()
                    + " in tenant: " + tenantId);
        }
    }
}
