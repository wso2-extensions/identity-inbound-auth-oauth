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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

/**
 * Unit tests for AuthorizationGrantCache operation based lookups.
 */
@PrepareForTest({IdentityTenantUtil.class, SessionDataStore.class})
public class AuthorizationGrantCacheTest extends PowerMockTestCase {

    private static final String AUTHORIZATION_GRANT_CACHE_NAME = "AuthorizationGrantCache";

    private SessionDataStore mockSessionDataStore;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        mockStatic(SessionDataStore.class);
        mockSessionDataStore = mock(SessionDataStore.class);
        when(SessionDataStore.getInstance()).thenReturn(mockSessionDataStore);
    }

    @Test
    public void testGetFromSessionStoreByOperation() {

        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry(new HashMap<>());
        when(mockSessionDataStore.getSessionData("token-id-1", AUTHORIZATION_GRANT_CACHE_NAME,
                OAuth2Constants.STORE_OPERATION)).thenReturn(entry);

        assertSame(AuthorizationGrantCache.getInstance().getFromSessionStore("token-id-1",
                OAuth2Constants.STORE_OPERATION), entry);
        verify(mockSessionDataStore).getSessionData("token-id-1", AUTHORIZATION_GRANT_CACHE_NAME,
                OAuth2Constants.STORE_OPERATION);
    }

    @Test
    public void testGetValueFromCacheByTokenIdAndOperationFallsBackToSessionStore() {

        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey("access-token-2");
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry(new HashMap<>());
        when(mockSessionDataStore.getSessionData("token-id-2", AUTHORIZATION_GRANT_CACHE_NAME,
                OAuth2Constants.STORE_OPERATION)).thenReturn(entry);

        AuthorizationGrantCache cache = AuthorizationGrantCache.getInstance();
        assertSame(cache.getValueFromCacheByTokenId(key, "token-id-2", OAuth2Constants.STORE_OPERATION), entry);
        assertNull(cache.getValueFromCache(key));

        verify(mockSessionDataStore, times(1)).getSessionData("token-id-2", AUTHORIZATION_GRANT_CACHE_NAME,
                OAuth2Constants.STORE_OPERATION);
        verify(mockSessionDataStore, never()).getSessionData(anyString(), anyString());
    }

    @Test
    public void testGetValueFromCacheByTokenIdAndOperationWhenNotFound() {

        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey("access-token-3");

        assertNull(AuthorizationGrantCache.getInstance().getValueFromCacheByTokenId(key, "token-id-3",
                OAuth2Constants.STORE_OPERATION));
        assertNull(AuthorizationGrantCache.getInstance().getValueFromCache(key));
    }
}
