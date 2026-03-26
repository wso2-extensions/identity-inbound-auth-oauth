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

package org.wso2.carbon.identity.oauth2.dao;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.internal.cache.OAuthUserConsentedScopeCache;
import org.wso2.carbon.identity.oauth2.internal.cache.OAuthUserConsentedScopeCacheEntry;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for CacheBackedOAuthUserConsentedScopesDAOImpl.getUserConsentForApplication,
 * specifically verifying that cache population on a DB read uses addToCacheOnRead (not addToCache).
 */
public class CacheBackedOAuthUserConsentedScopesDAOImplTest {

    private static final String USER_ID = "user-123";
    private static final String APP_ID = "app-456";
    private static final int TENANT_ID = -1234;

    /**
     * On a cache miss, the DAO should fetch from the backing store and populate the cache
     * using addToCacheOnRead (read-safe, no invalidation side-effects).
     */
    @Test
    public void testGetUserConsentCacheMissUsesAddToCacheOnRead() throws Exception {

        OAuthUserConsentedScopeCache mockCache = mock(OAuthUserConsentedScopeCache.class);
        OAuthUserConsentedScopesDAO mockDao = mock(OAuthUserConsentedScopesDAO.class);
        UserApplicationScopeConsentDO expectedConsent = new UserApplicationScopeConsentDO(APP_ID);

        when(mockCache.getValueFromCache(USER_ID, TENANT_ID)).thenReturn(null);
        when(mockDao.getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID)).thenReturn(expectedConsent);
        doNothing().when(mockCache).addToCacheOnRead(anyString(), any(OAuthUserConsentedScopeCacheEntry.class),
                anyInt());

        CacheBackedOAuthUserConsentedScopesDAOImpl daoImpl =
                createDaoWithMocks(mockCache, mockDao);

        UserApplicationScopeConsentDO result =
                daoImpl.getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID);

        assertEquals(result, expectedConsent, "Returned consent should match the DB result.");
        verify(mockDao).getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID);
        verify(mockCache).addToCacheOnRead(eq(USER_ID), any(OAuthUserConsentedScopeCacheEntry.class), eq(TENANT_ID));
        verify(mockCache, never()).addToCache(anyString(), any(), anyInt());
    }

    /**
     * On a cache hit with matching appId, the DAO should return the cached value without
     * a DB call and without calling addToCacheOnRead again.
     */
    @Test
    public void testGetUserConsentCacheHitReturnsCachedValue() throws Exception {

        OAuthUserConsentedScopeCache mockCache = mock(OAuthUserConsentedScopeCache.class);
        OAuthUserConsentedScopesDAO mockDao = mock(OAuthUserConsentedScopesDAO.class);
        UserApplicationScopeConsentDO cachedConsent = new UserApplicationScopeConsentDO(APP_ID);
        OAuthUserConsentedScopeCacheEntry cacheEntry =
                new OAuthUserConsentedScopeCacheEntry(APP_ID, cachedConsent);

        when(mockCache.getValueFromCache(USER_ID, TENANT_ID)).thenReturn(cacheEntry);

        CacheBackedOAuthUserConsentedScopesDAOImpl daoImpl =
                createDaoWithMocks(mockCache, mockDao);

        UserApplicationScopeConsentDO result =
                daoImpl.getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID);

        assertEquals(result, cachedConsent, "Cached consent should be returned on cache hit.");
        verify(mockDao, never()).getUserConsentForApplication(anyString(), anyString(), anyInt());
        verify(mockCache, never()).addToCacheOnRead(anyString(), any(), anyInt());
    }

    /**
     * On a cache hit but for a different appId, the DAO falls through to DB and uses addToCacheOnRead.
     */
    @Test
    public void testGetUserConsentCacheHitWithDifferentAppIdFetchesFromDb() throws Exception {

        OAuthUserConsentedScopeCache mockCache = mock(OAuthUserConsentedScopeCache.class);
        OAuthUserConsentedScopesDAO mockDao = mock(OAuthUserConsentedScopesDAO.class);
        UserApplicationScopeConsentDO dbConsent = new UserApplicationScopeConsentDO(APP_ID);
        OAuthUserConsentedScopeCacheEntry cacheEntryForDifferentApp =
                new OAuthUserConsentedScopeCacheEntry("different-app", 
                new UserApplicationScopeConsentDO("different-app"));

        when(mockCache.getValueFromCache(USER_ID, TENANT_ID)).thenReturn(cacheEntryForDifferentApp);
        when(mockDao.getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID)).thenReturn(dbConsent);
        doNothing().when(mockCache).addToCacheOnRead(anyString(), any(OAuthUserConsentedScopeCacheEntry.class),
                anyInt());

        CacheBackedOAuthUserConsentedScopesDAOImpl daoImpl =
                createDaoWithMocks(mockCache, mockDao);

        UserApplicationScopeConsentDO result =
                daoImpl.getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID);

        assertEquals(result, dbConsent, "DB result should be returned when cached entry has different appId.");
        verify(mockDao).getUserConsentForApplication(USER_ID, APP_ID, TENANT_ID);
        verify(mockCache).addToCacheOnRead(eq(USER_ID), any(OAuthUserConsentedScopeCacheEntry.class), eq(TENANT_ID));
    }

    /**
     * Helper: creates a CacheBackedOAuthUserConsentedScopesDAOImpl with injected mock cache and DAO.
     */
    private CacheBackedOAuthUserConsentedScopesDAOImpl createDaoWithMocks(
            OAuthUserConsentedScopeCache mockCache, OAuthUserConsentedScopesDAO mockDao) throws Exception {

        CacheBackedOAuthUserConsentedScopesDAOImpl impl = new CacheBackedOAuthUserConsentedScopesDAOImpl();

        Field cacheField = CacheBackedOAuthUserConsentedScopesDAOImpl.class.getDeclaredField("cache");
        cacheField.setAccessible(true);
        cacheField.set(impl, mockCache);

        Field daoField = CacheBackedOAuthUserConsentedScopesDAOImpl.class.getDeclaredField("dao");
        daoField.setAccessible(true);
        daoField.set(impl, mockDao);

        return impl;
    }
}
