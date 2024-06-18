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
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheEntry;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheKey;

import javax.cache.Cache;
import javax.cache.event.CacheEntryEvent;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@Listeners(MockitoTestNGListener.class)
public class ClaimMetaDataCacheRemoveListenerTest {

    @Mock
    private ClaimCache mockedClaimCache;

    @DataProvider(name = "provideParams")
    public Object[][] providePostParams() {
        final Cache cache = mock(Cache.class);
        ClaimCacheKey claimCacheKey = mock(ClaimCacheKey.class);
        ClaimMetaDataCacheKey claimMetaDataCacheKey = mock(ClaimMetaDataCacheKey.class);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setTenantDomain("foo.com");
        when(claimCacheKey.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(claimMetaDataCacheKey.getAuthenticatedUser()).thenReturn(authenticatedUser);


        CacheEntryEvent<? extends ClaimMetaDataCacheKey,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEventNullInstance = null;

        CacheEntryEvent<? extends ClaimMetaDataCacheKey,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEventValueNull =
                new CacheEntryEvent<ClaimMetaDataCacheKey, ClaimMetaDataCacheEntry>(cache) {
                    @Override
                    public ClaimMetaDataCacheKey getKey() {
                        return null;
                    }

                    @Override
                    public ClaimMetaDataCacheEntry getValue() {
                        return null;
                    }

                };

        CacheEntryEvent<? extends ClaimMetaDataCacheKey,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEventValueNotnull =
                new CacheEntryEvent<ClaimMetaDataCacheKey, ClaimMetaDataCacheEntry>(cache) {
                    ClaimMetaDataCacheEntry claimMetaDataCacheEntry = new ClaimMetaDataCacheEntry(claimCacheKey);

                    @Override
                    public ClaimMetaDataCacheKey getKey() {
                        return claimMetaDataCacheKey;
                    }

                    @Override
                    public ClaimMetaDataCacheEntry getValue() {
                        return claimMetaDataCacheEntry;
                    }
                };
        cacheEntryEventValueNotnull.getValue().setClaimCacheKey(null);

        CacheEntryEvent<? extends ClaimMetaDataCacheKey,
                ? extends ClaimMetaDataCacheEntry> cacheEntryEventQualified =
                new CacheEntryEvent<ClaimMetaDataCacheKey, ClaimMetaDataCacheEntry>(cache) {
                    ClaimMetaDataCacheEntry claimMetaDataCacheEntry = new ClaimMetaDataCacheEntry(claimCacheKey);

                    @Override
                    public ClaimMetaDataCacheKey getKey() {
                        return claimMetaDataCacheKey;
                    }

                    @Override
                    public ClaimMetaDataCacheEntry getValue() {
                        return claimMetaDataCacheEntry;
                    }
                };
        cacheEntryEventQualified.getValue().setClaimCacheKey(cacheEntryEventQualified.getValue().getClaimCacheKey());

        return new Object[][]{
                {cacheEntryEventNullInstance},
                {cacheEntryEventValueNull},
                {cacheEntryEventValueNotnull},
                {cacheEntryEventQualified}
        };
    }

    @Test(dataProvider = "provideParams")
    public void testEntryRemoved(Object object) throws Exception {

        try (MockedStatic<ClaimCache> claimCache = mockStatic(ClaimCache.class)) {
            claimCache.when(ClaimCache::getInstance).thenReturn(mockedClaimCache);
            ClaimMetaDataCacheRemoveListener claimMetaDataCacheRemoveListener = new ClaimMetaDataCacheRemoveListener();
            claimMetaDataCacheRemoveListener.entryRemoved((CacheEntryEvent<? extends ClaimMetaDataCacheKey,
                    ? extends ClaimMetaDataCacheEntry>) object);
        }
    }

}
