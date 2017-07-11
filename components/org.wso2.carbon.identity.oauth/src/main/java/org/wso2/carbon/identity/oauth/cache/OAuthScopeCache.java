/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.bean.Scope;

/**
 * OAuthScopeCache is used to cache scope binding information.
 */
public class OAuthScopeCache extends BaseCache<OAuthScopeCacheKey, Scope> {

    private static final Log log = LogFactory.getLog(OAuthScopeCache.class);
    private static final String OAUTH_SCOPE_CACHE_NAME = "OAuthScopeCache";
    private static final String IDENTITY_CACHE_MANAGER = "IdentityApplicationManagementCacheManager";
    private static volatile OAuthScopeCache instance;

    private OAuthScopeCache() {
        super(OAUTH_SCOPE_CACHE_NAME);
    }

    public static OAuthScopeCache getInstance() {
        if (instance == null) {
            synchronized (OAuthScopeCache.class) {
                if (instance == null) {
                    instance = new OAuthScopeCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add a cache entry.
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    public void addToCache(OAuthScopeCacheKey key, Scope entry) {
        if (IdentityUtil.getIdentityCacheConfig(IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME).isEnabled()) {
            super.addToCache(key, entry);
            if (log.isDebugEnabled()) {
                log.debug("Scope is added to the cache. \n" + entry.toString());
            }
        }
    }

    /**
     * Retrieves a cache entry.
     *
     * @param key CacheKey
     * @return Cached entry.
     */
    public Scope getValueFromCache(OAuthScopeCacheKey key) {
        Scope entry = null;
        if (IdentityUtil.getIdentityCacheConfig(IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME).isEnabled()) {
            entry = super.getValueFromCache(key);
            if (log.isDebugEnabled()) {
                log.debug("Scope is getting from the cache. \n" + entry.toString());
            }
        }
        return entry;
    }

    /**
     * Clears a cache entry.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntry(OAuthScopeCacheKey key) {
        if (IdentityUtil.getIdentityCacheConfig(IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME).isEnabled()) {
            super.clearCacheEntry(key);
            if (log.isDebugEnabled()) {
                log.debug("Scope: " + key.getScopeName() + " is deleted from the cache.");
            }
        }
    }
}
