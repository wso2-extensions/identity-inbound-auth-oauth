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

package org.wso2.carbon.identity.oauth.cache;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

@PrepareForTest({IdentityTenantUtil.class})
public class SessionDataCacheTest extends PowerMockTestCase {
    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private String sessionDataId = "835434_263277_7722";

    @BeforeMethod
    public void setup() {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }
    @Test
    public void testGetInstance() throws Exception {
        assertNotNull(SessionDataCache.getInstance(), "Message not equal");
    }

    @Test
    public void testAddToCache() throws Exception {
        SessionDataCacheKey key = mock(SessionDataCacheKey.class);
        SessionDataCacheEntry entry = mock(SessionDataCacheEntry.class);
        when(key.getSessionDataId()).thenReturn(sessionDataId);
        SessionDataCache.getInstance().addToCache(key, entry);
        assertNotNull(SessionDataCache.getInstance().getValueFromCache(key), "SessionDataCache is null");
    }

    @Test
    public void testGetValueFromCache() throws Exception {
        SessionDataCacheKey key = mock(SessionDataCacheKey.class);
        when(key.getSessionDataId()).thenReturn(sessionDataId);
        assertNull(SessionDataCache.getInstance().getValueFromCache(key));
    }

    @Test
    public void testClearCacheEntry() throws Exception {
        SessionDataCacheKey key = mock(SessionDataCacheKey.class);
        when(key.getSessionDataId()).thenReturn(sessionDataId);
        SessionDataCache.getInstance().clearCacheEntry(key);
        assertNull(SessionDataCache.getInstance().getValueFromCache(key), "SessionDataCacheEntry is not null");
    }
}
