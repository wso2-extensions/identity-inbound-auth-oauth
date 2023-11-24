/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.carbon.identity.oauth2.device.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Stores authenticated user attributes against the device code during OIDC Authorization request.
 * Those values are later required to serve OIDC Token request and build IDToken.
 */
public class DeviceAuthorizationGrantCache
        extends BaseCache<DeviceAuthorizationGrantCacheKey, DeviceAuthorizationGrantCacheEntry> {

    private static final String DEVICE_AUTHORIZATION_GRANT_CACHE_NAME = "DeviceAuthorizationGrantCache";

    private static volatile DeviceAuthorizationGrantCache instance;
    private static final Log log = LogFactory.getLog(DeviceAuthorizationGrantCache.class);

    private DeviceAuthorizationGrantCache() {

        super(DEVICE_AUTHORIZATION_GRANT_CACHE_NAME);
    }

    /**
     * Return DeviceAuthorizationGrantCache instance.
     *
     * @return DeviceAuthorizationGrantCache instance.
     */
    public static DeviceAuthorizationGrantCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (DeviceAuthorizationGrantCache.class) {
                if (instance == null) {
                    instance = new DeviceAuthorizationGrantCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add a cache entry by device code.
     *
     * @param cacheKey   DeviceAuthorizationGrantCacheKey.
     * @param cacheEntry DeviceAuthorizationGrantCacheEntry.
     */
    public void addToCache(DeviceAuthorizationGrantCacheKey cacheKey,
                           DeviceAuthorizationGrantCacheEntry cacheEntry) {

        super.addToCache(cacheKey, cacheEntry);
        storeToSessionStore(cacheKey.getCacheKeyString(), cacheEntry);
    }

    /**
     * Retrieves cache entry by device code.
     *
     * @param cacheKey DeviceAuthorizationGrantCacheKey to clear cache.
     * @return DeviceAuthorizationGrantCacheEntry
     */
    public DeviceAuthorizationGrantCacheEntry getValueFromCache(DeviceAuthorizationGrantCacheKey cacheKey) {

        DeviceAuthorizationGrantCacheEntry cacheEntry = super.getValueFromCache(cacheKey);
        if (cacheEntry == null) {
            String deviceCode = cacheKey.getCacheKeyString();
            if (log.isDebugEnabled()) {
                log.debug("Getting cache entry from session store using device code: " + deviceCode);
            }
            cacheEntry = getFromSessionStore(deviceCode);
        }
        return cacheEntry;
    }

    /**
     * Clears a cache entry by device code.
     *
     * @param cacheKey DeviceAuthorizationGrantCacheKey to clear cache.
     */
    public void clearCacheEntry(DeviceAuthorizationGrantCacheKey cacheKey) {

        super.clearCacheEntry(cacheKey);
        clearFromSessionStore(cacheKey.getCacheKeyString());
    }

    private void storeToSessionStore(String deviceCode, DeviceAuthorizationGrantCacheEntry cacheEntry) {

        SessionDataStore.getInstance()
                .storeSessionData(deviceCode, DEVICE_AUTHORIZATION_GRANT_CACHE_NAME, cacheEntry);
    }

    private DeviceAuthorizationGrantCacheEntry getFromSessionStore(String deviceCode) {

        return (DeviceAuthorizationGrantCacheEntry) SessionDataStore.getInstance()
                .getSessionData(deviceCode, DEVICE_AUTHORIZATION_GRANT_CACHE_NAME);
    }

    private void clearFromSessionStore(String deviceCode) {

        SessionDataStore.getInstance().clearSessionData(deviceCode, DEVICE_AUTHORIZATION_GRANT_CACHE_NAME);
    }
}
