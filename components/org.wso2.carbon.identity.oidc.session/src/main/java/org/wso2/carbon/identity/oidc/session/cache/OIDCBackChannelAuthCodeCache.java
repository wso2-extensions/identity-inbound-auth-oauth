/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * This class is used to cache Authorization code  against session ID (sid) for OIDCBackChannel Logout
 */
public class OIDCBackChannelAuthCodeCache extends BaseCache<OIDCBackChannelAuthCodeCacheKey,
        OIDCBackChannelAuthCodeCacheEntry> {

    private static final Log log = LogFactory.getLog(OIDCBackChannelAuthCodeCache.class);
    private static final String OIDC_BACKCHANNEL_DATA_CACHE_NAME = "OIDCBackChannelAuthCodeCache";

    private static volatile OIDCBackChannelAuthCodeCache instance;

    public OIDCBackChannelAuthCodeCache() {
        super(OIDC_BACKCHANNEL_DATA_CACHE_NAME);
    }

    /**
     * Returns OIDCBackChannelAuthCodeCache singleton instance
     *
     * @return OIDCBackChannelAuthCodeCache instance
     */
    public static OIDCBackChannelAuthCodeCache getInstance() {
        if (instance == null) {
            synchronized (OIDCBackChannelAuthCodeCache.class) {
                if (instance == null) {
                    instance = new OIDCBackChannelAuthCodeCache();
                }
            }
        }
        return instance;
    }

    /**
     * Adds session information to the cache
     * Cache key includes authorization code
     * Cache entry includes session id or sid claim which is unique for all RPs belong to same browser session
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    @Override
    public void addToCache(OIDCBackChannelAuthCodeCacheKey key, OIDCBackChannelAuthCodeCacheEntry entry) {
        super.addToCache(key, entry);
        SessionDataStore.getInstance().storeSessionData(key.getAuthCode(), OIDC_BACKCHANNEL_DATA_CACHE_NAME, entry);
        if (log.isDebugEnabled()) {
            log.debug("SessionID added to cache and persistence queue.");
        }
    }

    /**
     * Retrieve the sessionid information from the cache.
     * At a cache miss data is loaded from the persistence store
     *
     * @param key CacheKey Key which cache entry is indexed.
     * @return Cache entry
     */
    @Override
    public OIDCBackChannelAuthCodeCacheEntry getValueFromCache(OIDCBackChannelAuthCodeCacheKey key) {
        OIDCBackChannelAuthCodeCacheEntry entry = super.getValueFromCache(key);
        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("SessionID cannot be found. Retrieving from session persistence store.");
            }
            entry = (OIDCBackChannelAuthCodeCacheEntry) SessionDataStore.getInstance()
                    .getSessionData(key.getAuthCode(), OIDC_BACKCHANNEL_DATA_CACHE_NAME);
        }
        return entry;
    }

    /**
     * Clears the sessionid information from the cache and remove from persistence store
     *
     * @param key Key to clear cache.
     */
    @Override
    public void clearCacheEntry(OIDCBackChannelAuthCodeCacheKey key) {
        super.clearCacheEntry(key);
        SessionDataStore.getInstance().clearSessionData(key.getAuthCode(), OIDC_BACKCHANNEL_DATA_CACHE_NAME);
        if (log.isDebugEnabled()) {
            log.debug("Session ID cleared from cache and remove request added to persistence queue.");
        }
    }
}
