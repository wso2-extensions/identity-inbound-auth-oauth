/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Implements a cache to store unified OIDC scope claim references aggregated from the organization hierarchy.
 */
public class UnifiedOIDCScopeClaimCache extends BaseCache<Integer, OIDCScopeClaimCacheEntry> {

    public static final String UNIFIED_OIDC_SCOPE_CLAIM_CACHE = "UnifiedOIDCScopeClaimCache";
    private static volatile UnifiedOIDCScopeClaimCache instance;

    private UnifiedOIDCScopeClaimCache() {

        super(UNIFIED_OIDC_SCOPE_CLAIM_CACHE);
    }

    public static UnifiedOIDCScopeClaimCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (UnifiedOIDCScopeClaimCache.class) {
                if (instance == null) {
                    instance = new UnifiedOIDCScopeClaimCache();
                }
            }
        }
        return instance;
    }

    public void addScopeClaimMap(int tenantId, OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry) {

        super.addToCache(tenantId, oidcScopeClaimCacheEntry, tenantId);
    }

    public void clearScopeClaimMap(int tenantId) {

        super.clearCacheEntry(tenantId, tenantId);
    }

    public OIDCScopeClaimCacheEntry getScopeClaimMap(int tenantId) {

        return super.getValueFromCache(tenantId, tenantId);
    }
}
