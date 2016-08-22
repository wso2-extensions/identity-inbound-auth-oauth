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

package org.wso2.carbon.identity.oauth.listener;

import org.wso2.carbon.identity.application.common.listener.AbstractCacheListener;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheKey;
import org.wso2.carbon.identity.oauth.util.UserClaims;

import javax.cache.event.CacheEntryEvent;
import javax.cache.event.CacheEntryListenerException;
import javax.cache.event.CacheEntryRemovedListener;

/**
 * Claim Cache Remove Listener.
 */
public class ClaimCacheRemoveListener extends AbstractCacheListener<ClaimCacheKey, UserClaims>
        implements CacheEntryRemovedListener<ClaimCacheKey, UserClaims> {
    @Override
    public void entryRemoved(CacheEntryEvent<? extends ClaimCacheKey, ? extends UserClaims> cacheEntryEvent)
            throws CacheEntryListenerException {

        if(cacheEntryEvent == null || cacheEntryEvent.getKey() == null ||
                cacheEntryEvent.getKey().getAuthenticatedUser() == null) {
            return;
        }

        ClaimMetaDataCache.getInstance().clearCacheEntry(
                new ClaimMetaDataCacheKey(cacheEntryEvent.getKey().getAuthenticatedUser()));
    }
}
