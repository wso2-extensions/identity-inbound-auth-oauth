package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * This class is used to cache Authorization code and session ID (sid) for OIDCBackChannel Logout
 */
public class OIDCBackChannelAuthCodeCache extends BaseCache<OIDCBackChannelAuthCodeCacheKey,
        OIDCBackChannelAuthCodeCacheEntry> {

    private static final String SESSION_DATA_CACHE_NAME = "OIDCBackChannelAuthCodeCache";

    private static volatile OIDCBackChannelAuthCodeCache instance;

    public OIDCBackChannelAuthCodeCache() {

        super(SESSION_DATA_CACHE_NAME);
    }


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
}
