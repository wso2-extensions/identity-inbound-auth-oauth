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
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth.util.UserClaims;

import java.util.SortedMap;
import javax.cache.Cache;
import javax.cache.event.CacheEntryEvent;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({ClaimMetaDataCache.class})
public class ClaimCacheRemoveListenerTest {

    @Mock
    private ClaimMetaDataCache mockedClaimMetaDataCache;

    @DataProvider(name = "provideParams")
    public Object[][] providePostParams() {
        Cache cache = mock(Cache.class);
        CacheEntryEvent<? extends ClaimCacheKey, ? extends UserClaims> cacheEntryEvent_NullInstance = null;

        CacheEntryEvent<? extends ClaimCacheKey, ? extends UserClaims> cacheEntryEvent_KeyNull =
                new CacheEntryEvent<ClaimCacheKey, UserClaims>(cache) {
                    @Override
                    public ClaimCacheKey getKey() {
                        return null;
                    }

                    @Override
                    public UserClaims getValue() {
                        return null;
                    }
                };

        CacheEntryEvent<? extends ClaimCacheKey, ? extends UserClaims> cacheEntryEvent_KeyNotNull =
                new CacheEntryEvent<ClaimCacheKey, UserClaims>(cache) {
                    AuthenticatedUser authenticatedUser = null;
                    ClaimCacheKey claimCacheKey = new ClaimCacheKey(authenticatedUser);

                    @Override
                    public ClaimCacheKey getKey() {
                        return claimCacheKey;
                    }

                    @Override
                    public UserClaims getValue() {
                        return null;
                    }
                };

        CacheEntryEvent<? extends ClaimCacheKey, ? extends UserClaims> cacheEntryEvent_Qualified =
                new CacheEntryEvent<ClaimCacheKey, UserClaims>(cache) {
                    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                    ClaimCacheKey claimCacheKey = new ClaimCacheKey(authenticatedUser);

                    @Override
                    public ClaimCacheKey getKey() {
                        return claimCacheKey;
                    }

                    @Override
                    public UserClaims getValue() {
                        return null;
                    }
                };

        return new Object[][]{
                {cacheEntryEvent_NullInstance}, {cacheEntryEvent_KeyNull}, {cacheEntryEvent_KeyNotNull},
                {cacheEntryEvent_Qualified}
        };
    }

    @Test(dataProvider = "provideParams")
    public void testEntryRemoved(Object object) throws Exception {
        mockStatic(ClaimMetaDataCache.class);
        when(ClaimMetaDataCache.getInstance()).thenReturn(mockedClaimMetaDataCache);
        ClaimCacheRemoveListener claimCacheRemoveListener = new ClaimCacheRemoveListener();
        claimCacheRemoveListener.entryRemoved((CacheEntryEvent<? extends ClaimCacheKey, ? extends UserClaims>) object);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
