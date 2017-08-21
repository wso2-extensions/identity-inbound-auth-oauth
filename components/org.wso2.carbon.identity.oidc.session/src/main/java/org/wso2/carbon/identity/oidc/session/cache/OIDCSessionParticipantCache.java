/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * This is the class which caches OIDC session state information
 */
public class OIDCSessionParticipantCache
        extends BaseCache<OIDCSessionParticipantCacheKey, OIDCSessionParticipantCacheEntry> {

    private static final Log log = LogFactory.getLog(OIDCSessionParticipantCache.class);
    private static final String OIDC_SESSION_PARTICIPANT_CACHE_NAME = "OIDCSessionParticipantCache";

    private static volatile OIDCSessionParticipantCache instance;

    private OIDCSessionParticipantCache() {
        super(OIDC_SESSION_PARTICIPANT_CACHE_NAME);
    }

    /**
     * Returns OIDCSessionParticipantCache singleton instance
     *
     * @return OIDCSessionParticipantCache instance
     */
    public static OIDCSessionParticipantCache getInstance() {
        if (instance == null) {
            synchronized (OIDCSessionParticipantCache.class) {
                if (instance == null) {
                    instance = new OIDCSessionParticipantCache();
                }
            }
        }
        return instance;
    }

    /**
     * Adds session information to the cache
     * Cache key includes the browser state cookie id
     * Cache entry includes the authenticated user, and clients authenticated for that user who participates in the
     * same browser session
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    @Override
    public void addToCache(OIDCSessionParticipantCacheKey key, OIDCSessionParticipantCacheEntry entry) {
        super.addToCache(key, entry);
        SessionDataStore.getInstance().storeSessionData(key.getSessionID(), OIDC_SESSION_PARTICIPANT_CACHE_NAME, entry);
        if (log.isDebugEnabled()) {
            log.debug("Session corresponding to the key : " + key.getSessionID() + " added to cache and persistence "
                    + "queue.");
        }
    }

    /**
     * Retrieve the session information from the cache.
     * At a cache miss data is loaded from the persistence store
     *
     * @param key CacheKey Key which cache entry is indexed.
     * @return Cache entry
     */
    @Override
    public OIDCSessionParticipantCacheEntry getValueFromCache(OIDCSessionParticipantCacheKey key) {
        OIDCSessionParticipantCacheEntry entry = super.getValueFromCache(key);
        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Session corresponding to the key : " + key.getSessionID() + " cannot be found. Retrieving " +
                        "from session persistence store.");
            }
            entry = (OIDCSessionParticipantCacheEntry) SessionDataStore.getInstance().getSessionData(key.getSessionID
                    (), OIDC_SESSION_PARTICIPANT_CACHE_NAME);
        }

        return entry;
    }

    /**
     * Clears the session information from the cache and remove from persistence store
     *
     * @param key Key to clear cache.
     */
    @Override
    public void clearCacheEntry(OIDCSessionParticipantCacheKey key) {
        super.clearCacheEntry(key);
        SessionDataStore.getInstance().clearSessionData(key.getSessionID(), OIDC_SESSION_PARTICIPANT_CACHE_NAME);
        if (log.isDebugEnabled()) {
            log.debug("Session corresponding to the key : " + key.getSessionID() + " cleared from cache and " +
                    "remove request added to persistence queue.");
        }
    }
}
