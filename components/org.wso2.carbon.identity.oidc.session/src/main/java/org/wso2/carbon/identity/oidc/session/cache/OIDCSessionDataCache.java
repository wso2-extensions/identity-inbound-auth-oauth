/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * This is the class used to cache request session.
 */
public class OIDCSessionDataCache extends BaseCache<OIDCSessionDataCacheKey, OIDCSessionDataCacheEntry> {

    private static final String SESSION_DATA_CACHE_NAME = "OIDCSessionDataCache";

    private static volatile OIDCSessionDataCache instance;

    private OIDCSessionDataCache() {

        super(SESSION_DATA_CACHE_NAME);
    }

    public static OIDCSessionDataCache getInstance() {

        if (instance == null) {
            synchronized (OIDCSessionDataCache.class) {
                if (instance == null) {
                    instance = new OIDCSessionDataCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add OIDCSessionDataCache to cache.
     *
     * @param key   OIDCSessionDataCacheKey.
     * @param entry OIDCSessionDataCacheEntry.
     */
    public void addToCache(OIDCSessionDataCacheKey key, OIDCSessionDataCacheEntry entry) {

        super.addToCache(key, entry);
        SessionDataStore.getInstance().storeSessionData(key.getSessionDataId(), SESSION_DATA_CACHE_NAME, entry);
    }

    /**
     * Get OIDCSessionDataCacheEntry from OIDCSessionDataCache.
     *
     * @param key OIDCSessionDataCacheKey.
     * @return OIDCSessionDataCacheEntry.
     */
    public OIDCSessionDataCacheEntry getValueFromCache(OIDCSessionDataCacheKey key) {

        OIDCSessionDataCacheEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            cacheEntry = (OIDCSessionDataCacheEntry) SessionDataStore.getInstance().
                    getSessionData(key.getSessionDataId(), SESSION_DATA_CACHE_NAME);
        }
        return cacheEntry;
    }

    /**
     * Clear OIDCSessionDataCache.
     *
     * @param key OIDCSessionDataCacheKey.
     */
    public void clearCacheEntry(OIDCSessionDataCacheKey key) {

        super.clearCacheEntry(key);
        SessionDataStore.getInstance().clearSessionData(key.getSessionDataId(), SESSION_DATA_CACHE_NAME);
    }
}
