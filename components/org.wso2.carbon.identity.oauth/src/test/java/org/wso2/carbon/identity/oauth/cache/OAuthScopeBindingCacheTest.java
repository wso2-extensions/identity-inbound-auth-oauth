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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;

import java.util.Collections;

import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for OAuthScopeBindingCache.addToCacheOnRead method.
 */
@WithCarbonHome
public class OAuthScopeBindingCacheTest {

    private static final int TENANT_ID = -1234;

    @Test
    public void testGetInstance() {

        assertNotNull(OAuthScopeBindingCache.getInstance(), "OAuthScopeBindingCache instance should not be null.");
    }

    /**
     * Verifies that addToCacheOnRead does not throw for a valid scope array entry,
     * and that the entry is subsequently retrievable.
     */
    @Test
    public void testAddToCacheOnReadStoresEntry() {

        OAuthScopeBindingCache cache = OAuthScopeBindingCache.getInstance();
        OAuthScopeBindingCacheKey key = new OAuthScopeBindingCacheKey("ROLE");

        ScopeBinding binding = new ScopeBinding("ROLE", Collections.singletonList("admin"));
        Scope scope = new Scope("read", "Read", Collections.singletonList(binding), "Read scope");
        Scope[] entry = new Scope[]{scope};

        // Should not throw
        cache.addToCacheOnRead(key, entry, TENANT_ID);

        // Entry should be retrievable after addToCacheOnRead
        Scope[] retrieved = cache.getValueFromCache(key, TENANT_ID);
        assertNotNull(retrieved, "Entry stored via addToCacheOnRead should be retrievable from cache.");
    }

    /**
     * Verifies that addToCacheOnRead and addToCache store entries in the same way —
     * both entries must be non-null after the respective writes.
     */
    @Test
    public void testAddToCacheOnReadParityWithAddToCache() {

        OAuthScopeBindingCache cache = OAuthScopeBindingCache.getInstance();

        ScopeBinding binding = new ScopeBinding("GROUP", Collections.singletonList("finance"));
        Scope scope = new Scope("write", "Write", Collections.singletonList(binding), "Write scope");
        Scope[] entry = new Scope[]{scope};

        OAuthScopeBindingCacheKey keyWrite = new OAuthScopeBindingCacheKey("GROUP_WRITE");
        OAuthScopeBindingCacheKey keyRead = new OAuthScopeBindingCacheKey("GROUP_READ");

        cache.addToCache(keyWrite, entry, TENANT_ID);
        cache.addToCacheOnRead(keyRead, entry, TENANT_ID);

        assertNotNull(cache.getValueFromCache(keyWrite, TENANT_ID),
                "Entry added via addToCache should be retrievable.");
        assertNotNull(cache.getValueFromCache(keyRead, TENANT_ID),
                "Entry added via addToCacheOnRead should be retrievable.");
    }
}
