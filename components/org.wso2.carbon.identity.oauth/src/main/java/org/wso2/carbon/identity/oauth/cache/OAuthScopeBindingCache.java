/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.oauth2.bean.Scope;

/**
 * OAuthScopeBindingCache is used to cache scope binding type information.
 */
public class OAuthScopeBindingCache extends BaseCache<OAuthScopeBindingCacheKey, Scope[]> {

    private static final Log log = LogFactory.getLog(OAuthScopeBindingCache.class);
    private static final String OAUTH_SCOPE_BINDING_CACHE = "OAuthScopeBindingCache";
    private static volatile OAuthScopeBindingCache instance;

    private OAuthScopeBindingCache() {

        super(OAUTH_SCOPE_BINDING_CACHE);
    }

    public static OAuthScopeBindingCache getInstance() {

        if (instance == null) {
            synchronized (OAuthScopeBindingCache.class) {
                if (instance == null) {
                    instance = new OAuthScopeBindingCache();
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
    public void addToCache(OAuthScopeBindingCacheKey key, Scope[] entry) {

        super.addToCache(key, entry);
        if (log.isDebugEnabled()) {
            log.debug("Scope bindings are added to the cache. \n" + ArrayUtils.toString(entry));
        }
    }

    /**
     * Retrieves a cache entry.
     *
     * @param key CacheKey
     * @return Cached entry.
     */
    public Scope[] getValueFromCache(OAuthScopeBindingCacheKey key) {

        Scope[] entry = super.getValueFromCache(key);
        if (log.isDebugEnabled()) {
            log.debug("Scopes are getting from the cache. \n" + ArrayUtils.toString(entry));
        }
        return entry;
    }

    /**
     * Clears a cache entry.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntry(OAuthScopeBindingCacheKey key) {

        super.clearCacheEntry(key);
        if (log.isDebugEnabled()) {
            log.debug("Scope bindings type : " + key.getBindingType() + "" +
                    "is removed from the cache in tenant: " + key.getTenantID());
        }
    }
}
