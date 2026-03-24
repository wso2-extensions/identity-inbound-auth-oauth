/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.cache;

import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.IdentityCacheConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for OAuthScopeCache.addToCacheOnRead method.
 */
public class OAuthScopeCacheTest {

    private static final String IDENTITY_CACHE_MANAGER = "IdentityApplicationManagementCacheManager";
    private static final String OAUTH_SCOPE_CACHE_NAME = "OAuthScopeCache";
    private static final int TENANT_ID = -1234;

    @Test
    public void testGetInstance() {

        assertNotNull(OAuthScopeCache.getInstance(), "OAuthScopeCache instance should not be null.");
    }

    @DataProvider(name = "cacheEnabledProvider")
    public Object[][] cacheEnabledProvider() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    /**
     * Verifies that addToCacheOnRead always clears the OAuthScopeBindingCache for each scope binding,
     * regardless of whether the cache is enabled or disabled.
     */
    @Test(dataProvider = "cacheEnabledProvider")
    public void testAddToCacheOnReadClearsBindingCacheForEachBinding(boolean cacheEnabled) {

        OAuthScopeBindingCache mockBindingCache = mock(OAuthScopeBindingCache.class);
        IdentityCacheConfig mockConfig = mock(IdentityCacheConfig.class);
        when(mockConfig.isEnabled()).thenReturn(cacheEnabled);

        try (MockedStatic<OAuthScopeBindingCache> mockedBindingCache = mockStatic(OAuthScopeBindingCache.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            mockedBindingCache.when(OAuthScopeBindingCache::getInstance).thenReturn(mockBindingCache);
            mockedIdentityUtil.when(() -> IdentityUtil.getIdentityCacheConfig(
                    IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME)).thenReturn(mockConfig);

            ScopeBinding binding1 = new ScopeBinding("ROLE", Collections.singletonList("admin"));
            ScopeBinding binding2 = new ScopeBinding("GROUP", Collections.singletonList("finance"));
            List<ScopeBinding> bindings = Arrays.asList(binding1, binding2);

            Scope scope = new Scope("read", "Read", bindings, "Read scope");
            OAuthScopeCacheKey key = new OAuthScopeCacheKey("read");

            OAuthScopeCache.getInstance().addToCacheOnRead(key, scope, TENANT_ID);

            // clearCacheEntry should be called once per scope binding
            verify(mockBindingCache, times(2)).clearCacheEntry(any(OAuthScopeBindingCacheKey.class), eq(TENANT_ID));
        }
    }

    /**
     * Verifies that addToCacheOnRead clears the binding cache with the correct binding type key
     * for each scope binding.
     */
    @Test
    public void testAddToCacheOnReadClearsBindingCacheWithCorrectKey() {

        OAuthScopeBindingCache mockBindingCache = mock(OAuthScopeBindingCache.class);
        IdentityCacheConfig mockConfig = mock(IdentityCacheConfig.class);
        when(mockConfig.isEnabled()).thenReturn(true);

        try (MockedStatic<OAuthScopeBindingCache> mockedBindingCache = mockStatic(OAuthScopeBindingCache.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            mockedBindingCache.when(OAuthScopeBindingCache::getInstance).thenReturn(mockBindingCache);
            mockedIdentityUtil.when(() -> IdentityUtil.getIdentityCacheConfig(
                    IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME)).thenReturn(mockConfig);

            ScopeBinding binding = new ScopeBinding("ROLE", Collections.singletonList("admin"));
            Scope scope = new Scope("write", "Write", Collections.singletonList(binding), "Write scope");
            OAuthScopeCacheKey key = new OAuthScopeCacheKey("write");

            OAuthScopeCache.getInstance().addToCacheOnRead(key, scope, TENANT_ID);

            verify(mockBindingCache).clearCacheEntry(
                    eq(new OAuthScopeBindingCacheKey("ROLE")), eq(TENANT_ID));
        }
    }

    /**
     * Verifies that when a scope has no bindings, addToCacheOnRead does not invoke clearCacheEntry
     * on the OAuthScopeBindingCache.
     */
    @Test
    public void testAddToCacheOnReadWithNoBindingsDoesNotClearBindingCache() {

        OAuthScopeBindingCache mockBindingCache = mock(OAuthScopeBindingCache.class);
        IdentityCacheConfig mockConfig = mock(IdentityCacheConfig.class);
        when(mockConfig.isEnabled()).thenReturn(true);

        try (MockedStatic<OAuthScopeBindingCache> mockedBindingCache = mockStatic(OAuthScopeBindingCache.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            mockedBindingCache.when(OAuthScopeBindingCache::getInstance).thenReturn(mockBindingCache);
            mockedIdentityUtil.when(() -> IdentityUtil.getIdentityCacheConfig(
                    IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME)).thenReturn(mockConfig);

            Scope scope = new Scope("delete", "Delete", "Delete scope");
            scope.setScopeBindings(Collections.emptyList());
            OAuthScopeCacheKey key = new OAuthScopeCacheKey("delete");

            OAuthScopeCache.getInstance().addToCacheOnRead(key, scope, TENANT_ID);

            verify(mockBindingCache, never()).clearCacheEntry(any(OAuthScopeBindingCacheKey.class), any(Integer.class));
        }
    }

    /**
     * Verifies behaviour parity between addToCache and addToCacheOnRead:
     * both should clear the OAuthScopeBindingCache for the same scope bindings.
     */
    @Test
    public void testAddToCacheOnReadMatchesAddToCacheBehaviourForBindingCacheClearing() {

        OAuthScopeBindingCache mockBindingCache = mock(OAuthScopeBindingCache.class);
        IdentityCacheConfig mockConfig = mock(IdentityCacheConfig.class);
        when(mockConfig.isEnabled()).thenReturn(true);

        try (MockedStatic<OAuthScopeBindingCache> mockedBindingCache = mockStatic(OAuthScopeBindingCache.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            mockedBindingCache.when(OAuthScopeBindingCache::getInstance).thenReturn(mockBindingCache);
            mockedIdentityUtil.when(() -> IdentityUtil.getIdentityCacheConfig(
                    IDENTITY_CACHE_MANAGER, OAUTH_SCOPE_CACHE_NAME)).thenReturn(mockConfig);

            ScopeBinding binding = new ScopeBinding("PERMISSION", Collections.singletonList("read:resource"));
            Scope scope = new Scope("profile", "Profile", Collections.singletonList(binding), "Profile scope");
            OAuthScopeCacheKey key = new OAuthScopeCacheKey("profile");

            // Both addToCache and addToCacheOnRead should clear the binding cache
            OAuthScopeCache.getInstance().addToCache(key, scope, TENANT_ID);
            verify(mockBindingCache, times(1)).clearCacheEntry(any(OAuthScopeBindingCacheKey.class), eq(TENANT_ID));

            OAuthScopeCache.getInstance().addToCacheOnRead(key, scope, TENANT_ID);
            verify(mockBindingCache, times(2)).clearCacheEntry(any(OAuthScopeBindingCacheKey.class), eq(TENANT_ID));
        }
    }
}
