/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.listener;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheEntry;

import javax.cache.Cache;
import javax.cache.event.CacheEntryEvent;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({ClaimCache.class})
public class ClaimMetaDataCacheRemoveListenerTest {

    @Mock
    private ClaimCache mockedClaimCache;

    @DataProvider(name = "provideParams")
    public Object[][] providePostParams() {
        final Cache cache = mock(Cache.class);

        CacheEntryEvent<? extends ClaimMetaDataCacheEntry,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEventNullInstance = null;

        CacheEntryEvent<? extends ClaimMetaDataCacheEntry,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEvent_ValueNull =
                new CacheEntryEvent<ClaimMetaDataCacheEntry, ClaimMetaDataCacheEntry>(cache) {
                    @Override
                    public ClaimMetaDataCacheEntry getKey() {
                        return null;
                    }

                    @Override
                    public ClaimMetaDataCacheEntry getValue() {
                        return null;
                    }

                };

        CacheEntryEvent<? extends ClaimMetaDataCacheEntry,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEvent_ValueNotnull =
                new CacheEntryEvent<ClaimMetaDataCacheEntry, ClaimMetaDataCacheEntry>(cache) {
                    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                    ClaimCacheKey claimCacheKey = new ClaimCacheKey(authenticatedUser);
                    ClaimMetaDataCacheEntry claimMetaDataCacheEntry = new ClaimMetaDataCacheEntry(claimCacheKey);

                    @Override
                    public ClaimMetaDataCacheEntry getKey() {
                        return claimMetaDataCacheEntry;
                    }

                    @Override
                    public ClaimMetaDataCacheEntry getValue() {
                        return claimMetaDataCacheEntry;
                    }
                };
        cacheEntryEvent_ValueNotnull.getValue().setClaimCacheKey(null);

        CacheEntryEvent<? extends ClaimMetaDataCacheEntry,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEventQualified =
                new CacheEntryEvent<ClaimMetaDataCacheEntry, ClaimMetaDataCacheEntry>(cache) {
                    ClaimCacheKey claimCacheKey = mock(ClaimCacheKey.class);
                    ClaimMetaDataCacheEntry claimMetaDataCacheEntry = new ClaimMetaDataCacheEntry(claimCacheKey);

                    @Override
                    public ClaimMetaDataCacheEntry getKey() {
                        return claimMetaDataCacheEntry;
                    }

                    @Override
                    public ClaimMetaDataCacheEntry getValue() {
                        return claimMetaDataCacheEntry;
                    }
                };
        cacheEntryEventQualified.getValue().setClaimCacheKey(cacheEntryEventQualified.getValue().getClaimCacheKey());

        return new Object[][]{
                {cacheEntryEventNullInstance},
                {cacheEntryEvent_ValueNull},
                {cacheEntryEvent_ValueNotnull},
                {cacheEntryEventQualified}
        };
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Test(dataProvider = "provideParams")
    public void testEntryRemoved(Object object) throws Exception {
        mockStatic(ClaimCache.class);
        when(ClaimCache.getInstance()).thenReturn(mockedClaimCache);
        ClaimMetaDataCacheRemoveListener claimMetaDataCacheRemoveListener = new ClaimMetaDataCacheRemoveListener();
        claimMetaDataCacheRemoveListener.entryRemoved((CacheEntryEvent<? extends ClaimMetaDataCacheEntry,
                ? extends ClaimMetaDataCacheEntry>) object);
    }

}
