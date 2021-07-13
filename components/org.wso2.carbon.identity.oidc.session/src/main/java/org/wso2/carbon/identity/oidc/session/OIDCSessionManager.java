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

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCacheKey;

/**
 * This class provides session state CRUD operations.
 */
public class OIDCSessionManager {

    /**
     * Stores the session state against the provided session id.
     *
     * @param sessionId    session id value
     * @param sessionState OIDCSessionState instance
     *
     * @deprecated This method was deprecated to move OIDCSessionParticipantCache to the tenant space.
     * Use {@link #storeOIDCSessionState(String, OIDCSessionState, String)} instead.
     */
    @Deprecated
    public void storeOIDCSessionState(String sessionId, OIDCSessionState sessionState) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        storeOIDCSessionState(sessionId, sessionState, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Retrieves session state for the given session id.
     *
     * @param sessionId session id value
     * @return OIDCSessionState instance
     *
     * @deprecated This method was deprecated to move OIDCSessionParticipantCache to the tenant space.
     * Use {@link #getOIDCSessionState(String, String)} instead.
     */
    @Deprecated
    public OIDCSessionState getOIDCSessionState(String sessionId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        return getOIDCSessionState(sessionId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Removes the session against the old session id and restore against the provided new session id.
     *
     * @param oldSessionId
     * @param newSessionId
     * @param sessionState
     *
     * @deprecated This method was deprecated to move OIDCSessionParticipantCache to the tenant space.
     * Use {@link #restoreOIDCSessionState(String, String, OIDCSessionState, String)} instead.
     */
    @Deprecated
    public void restoreOIDCSessionState(String oldSessionId, String newSessionId, OIDCSessionState sessionState) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        restoreOIDCSessionState(oldSessionId, newSessionId, sessionState,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Removes the session against the given session id.
     *
     * @param sessionId session id value
     *
     * @deprecated This method was deprecated to move OIDCSessionParticipantCache to the tenant space.
     * Use {@link #removeOIDCSessionState(String, String)} instead.
     */
    @Deprecated
    public void removeOIDCSessionState(String sessionId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        removeOIDCSessionState(sessionId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Checks if there is a session exists for the gives session id.
     *
     * @param sessionId session id value
     * @return true if session exists
     */
    @Deprecated
    public boolean sessionExists(String sessionId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        return sessionExists(sessionId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Stores the session state against the provided session id.
     *
     * @param sessionId    session id value
     * @param sessionState OIDCSessionState instance
     * @param loginTenantDomain login tenant domain
     */
    public void storeOIDCSessionState(String sessionId, OIDCSessionState sessionState, String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCacheEntry cacheEntry = new OIDCSessionParticipantCacheEntry();
        cacheEntry.setSessionState(sessionState);
        cacheEntry.setTenantDomain(tenantDomain);

        OIDCSessionParticipantCache.getInstance().addToCache(cacheKey, cacheEntry, tenantDomain);
    }

    /**
     * Retrieves session state for the given session id.
     *
     * @param sessionId session id value
     * @param loginTenantDomain login tenant domain
     * @return OIDCSessionState instance
     */
    public OIDCSessionState getOIDCSessionState(String sessionId, String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCacheEntry cacheEntry = OIDCSessionParticipantCache.getInstance().getValueFromCache
                (cacheKey, tenantDomain);

        return cacheEntry == null ? null : cacheEntry.getSessionState();
    }

    /**
     * Removes the session against the old session id and restore against the provided new session id.
     *
     * @param oldSessionId old session id value
     * @param newSessionId new session id value
     * @param sessionState OIDCSessionState instance
     * @param loginTenantDomain login tenant domain
     */
    public void restoreOIDCSessionState(String oldSessionId, String newSessionId, OIDCSessionState sessionState,
                                        String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        removeOIDCSessionState(oldSessionId, tenantDomain);
        storeOIDCSessionState(newSessionId, sessionState, tenantDomain);
    }

    /**
     * Removes the session against the given session id.
     *
     * @param sessionId session id value
     * @param loginTenantDomain login tenant domain
     */
    public void removeOIDCSessionState(String sessionId, String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCache.getInstance().clearCacheEntry(cacheKey, tenantDomain);
    }

    /**
     * Checks if there is a session exists for the gives session id.
     *
     * @param sessionId session id value
     * @param loginTenantDomain login tenant domain
     * @return true if session exists
     */
    public boolean sessionExists(String sessionId, String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        return getOIDCSessionState(sessionId, tenantDomain) != null;
    }

    private String resolveCacheTenantDomain(String tenantDomain) {

        if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }
}
