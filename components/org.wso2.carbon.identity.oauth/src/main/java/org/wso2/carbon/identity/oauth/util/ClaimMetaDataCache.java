/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth.util;

import org.wso2.carbon.identity.core.cache.AbstractCacheListener;
import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.identity.oauth.listener.ClaimMetaDataCacheRemoveListener;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Claim Meta Data Cache.
 */
public class ClaimMetaDataCache extends BaseCache<ClaimMetaDataCacheKey, ClaimMetaDataCacheEntry> {

    private static final String CLAIM_META_DATA_CACHE_NAME = "ClaimMetaDataCache";

    private static ClaimMetaDataCache instance = new ClaimMetaDataCache();
    private static final List<AbstractCacheListener<ClaimMetaDataCacheKey, ClaimMetaDataCacheEntry>>
            cacheListeners = new ArrayList<>();

    static {
        cacheListeners.add(new ClaimMetaDataCacheRemoveListener());
    }

    private ClaimMetaDataCache() {
        super(CLAIM_META_DATA_CACHE_NAME, cacheListeners);
    }

    public static ClaimMetaDataCache getInstance() {
        CarbonUtils.checkSecurity();
        return instance;
    }
}

