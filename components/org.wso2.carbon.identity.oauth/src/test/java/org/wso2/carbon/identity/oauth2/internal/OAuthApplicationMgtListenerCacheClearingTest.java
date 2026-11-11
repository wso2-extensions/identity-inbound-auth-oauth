/*
 * Copyright (c) 2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.internal;

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests the cache clearing done by {@link OAuthApplicationMgtListener} after an application update.
 */
public class OAuthApplicationMgtListenerCacheClearingTest {

    @Test
    public void testTokenAndAuthzCodeLookupSkippedWhenClaimConfigUnchanged() throws Exception {

        OAuthApplicationMgtListener listener = new OAuthApplicationMgtListener();
        Field flagField = OAuthApplicationMgtListener.class.getDeclaredField("threadLocalForClaimConfigUpdates");
        flagField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ThreadLocal<Boolean> claimConfigUpdated = (ThreadLocal<Boolean>) flagField.get(listener);
        Method method = OAuthApplicationMgtListener.class.getDeclaredMethod("removeEntriesFromCache", Set.class);
        method.setAccessible(true);

        OAuthTokenPersistenceFactory factory = mock(OAuthTokenPersistenceFactory.class);
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        OAuthCache oAuthCache = mock(OAuthCache.class);
        try (MockedStatic<OAuthTokenPersistenceFactory> factoryStatic = mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<AppInfoCache> appInfoCacheStatic = mockStatic(AppInfoCache.class);
             MockedStatic<OAuthCache> oAuthCacheStatic = mockStatic(OAuthCache.class)) {
            factoryStatic.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(factory);
            appInfoCacheStatic.when(AppInfoCache::getInstance).thenReturn(appInfoCache);
            oAuthCacheStatic.when(OAuthCache::getInstance).thenReturn(oAuthCache);

            claimConfigUpdated.set(false);
            try {
                method.invoke(listener, Collections.singleton("consumerKey"));
            } finally {
                claimConfigUpdated.remove();
            }

            // The heavy token and authz code lookups must not run, but the app cache is still cleared.
            verify(factory, never()).getAccessTokenDAOImpl(anyString());
            verify(factory, never()).getAuthorizationCodeDAO();
            verify(appInfoCache).clearCacheEntry("consumerKey");
        }
    }
}
