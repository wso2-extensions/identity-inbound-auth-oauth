package org.wso2.carbon.identity.oauth.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Stores whether scope validation is enabled or disabled for a specific OAuth application against
 * the application clientId
 *
 */
public class ValidateScopeCache extends BaseCache<String, Boolean> {

    private static final String VALIDATE_SCOPE_CACHE_NAME = "ValidateScopeCache";

    private static volatile ValidateScopeCache instance;

    private ValidateScopeCache() {
        super(VALIDATE_SCOPE_CACHE_NAME);
    }

    /**
     * Returns ValidateScopeCache instance
     *
     * @return instance of ValidateScopeCache
     */
    public static ValidateScopeCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (ValidateScopeCache.class) {
                if (instance == null) {
                    instance = new ValidateScopeCache();
                }
            }
        }
        return instance;
    }
}

