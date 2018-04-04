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

package org.wso2.carbon.identity.oidc.session;

import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCacheKey;

/**
 * This class provides session state CRUD operations
 */
public class OIDCSessionManager {

    /**
     * Stores the session state against the provided session id
     *
     * @param sessionId    session id value
     * @param sessionState OIDCSessionState instance
     */
    public void storeOIDCSessionState(String sessionId, OIDCSessionState sessionState) {

        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCacheEntry cacheEntry = new OIDCSessionParticipantCacheEntry();
        cacheEntry.setSessionState(sessionState);

        OIDCSessionParticipantCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    /**
     * Retrieves session state for the given session id
     *
     * @param sessionId session id value
     * @return OIDCSessionState instance
     */
    public OIDCSessionState getOIDCSessionState(String sessionId) {

        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCacheEntry cacheEntry = OIDCSessionParticipantCache.getInstance().getValueFromCache
                (cacheKey);

        return cacheEntry == null ? null : cacheEntry.getSessionState();
    }

    /**
     * Removes the session against the old session id and restore against the provided new session id
     *
     * @param oldSessionId
     * @param newSessionId
     * @param sessionState
     */
    public void restoreOIDCSessionState(String oldSessionId, String newSessionId, OIDCSessionState sessionState) {

        removeOIDCSessionState(oldSessionId);
        storeOIDCSessionState(newSessionId, sessionState);
    }

    /**
     * Removes the session against the given session id
     *
     * @param sessionId session id value
     */
    public void removeOIDCSessionState(String sessionId) {

        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCache.getInstance().clearCacheEntry(cacheKey);
    }

    /**
     * Checks if there is a session exists for the gives session id
     *
     * @param sessionId session id value
     * @return true if session exists
     */
    public boolean sessionExists(String sessionId) {
        return getOIDCSessionState(sessionId) != null;
    }
}
