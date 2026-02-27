/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oidc.session.cache;

import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit test coverage for OIDCSessionDataCache class.
 * Migrated from PowerMock to plain Mockito (Java 21 compatible).
 */
@WithCarbonHome
@WithRealmService
public class OIDCSessionDataCacheTest {

    @Test
    public void testGetInstance() {

        assertNotNull(OIDCSessionDataCache.getInstance(), "OIDCSessionDataCache is null.");
    }

    @Test
    public void testAddToCache() {

        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        OIDCSessionDataCacheKey key = mock(OIDCSessionDataCacheKey.class);
        OIDCSessionDataCacheEntry entry = mock(OIDCSessionDataCacheEntry.class);
        OIDCSessionDataCache.getInstance().addToCache(key, entry);
        assertNotNull(OIDCSessionDataCache.getInstance().getValueFromCache(key),
                "OIDCSessionDataCache is null.");
    }

    @Test
    public void testClearCacheEntry() {

        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        OIDCSessionDataCacheKey key = mock(OIDCSessionDataCacheKey.class);
        OIDCSessionDataCache.getInstance().clearCacheEntry(key);
        assertNull(OIDCSessionDataCache.getInstance().getValueFromCache(key),
                "OIDCSessionDataCache is not null.");
    }
}
