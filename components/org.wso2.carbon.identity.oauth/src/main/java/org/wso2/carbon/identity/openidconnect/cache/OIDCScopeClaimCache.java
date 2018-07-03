/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.openidconnect.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Implements a cache to store OIDC Scope claim references
 */
public class OIDCScopeClaimCache extends BaseCache<Integer, OIDCScopeClaimCacheEntry> {

    public static final String OIDC_SCOPE_CLAIM_CACHE = "OIDCScopeClaimCache";
    private static volatile OIDCScopeClaimCache instance;

    private OIDCScopeClaimCache() {

        super(OIDC_SCOPE_CLAIM_CACHE);
    }

    public static OIDCScopeClaimCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OIDCScopeClaimCache.class) {
                if (instance == null) {
                    instance = new OIDCScopeClaimCache();
                }
            }
        }
        return instance;
    }

    public void addScopeClaimMap(int tenantId, OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry) {

        super.addToCache(tenantId, oidcScopeClaimCacheEntry);
    }

    public void clearScopeClaimMap(int tenantId) {

        super.clearCacheEntry(tenantId);
    }

    public OIDCScopeClaimCacheEntry getScopeClaimMap(int tenantId) {

        OIDCScopeClaimCacheEntry scopeClaimMap = super.getValueFromCache(tenantId);
        return scopeClaimMap;
    }
}
