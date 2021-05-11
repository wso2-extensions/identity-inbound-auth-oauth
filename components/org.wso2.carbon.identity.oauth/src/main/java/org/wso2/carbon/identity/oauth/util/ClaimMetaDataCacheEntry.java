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

import org.wso2.carbon.identity.core.cache.CacheEntry;

/**
 * Claim Meta Data Cache Entry.
 */
public class ClaimMetaDataCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -1695934148047205833L;

    private ClaimCacheKey claimCacheKey;

    public ClaimMetaDataCacheEntry(ClaimCacheKey claimCacheKey) {
        this.claimCacheKey = claimCacheKey;
    }

    public ClaimCacheKey getClaimCacheKey() {
        return claimCacheKey;
    }

    public void setClaimCacheKey(ClaimCacheKey claimCacheKey) {
        this.claimCacheKey = claimCacheKey;
    }
}
