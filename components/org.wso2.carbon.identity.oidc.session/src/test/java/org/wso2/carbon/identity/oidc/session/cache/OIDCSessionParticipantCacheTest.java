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
package org.wso2.carbon.identity.oidc.session.cache;

import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit test coverage for OIDCSessionParticipantCache class.
 * Migrated from PowerMockTestCase to plain Mockito (Java 21 compatible).
 * Note: mock()/when() usage here is on instance mocks only, which Mockito handles without PowerMock.
 */
@WithCarbonHome
@WithRealmService
public class OIDCSessionParticipantCacheTest {

    private static final String SESSION_ID = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";

    @Test
    public void testGetInstance() {

        assertNotNull(OIDCSessionParticipantCache.getInstance(), "OIDCSessionParticipantCache is null");
    }

    @Test
    public void testAddToCache() {

        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        OIDCSessionParticipantCacheKey key = mock(OIDCSessionParticipantCacheKey.class);
        OIDCSessionParticipantCacheEntry entry = mock(OIDCSessionParticipantCacheEntry.class);
        when(key.getSessionID()).thenReturn(SESSION_ID);
        OIDCSessionParticipantCache.getInstance().addToCache(key, entry, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNotNull(OIDCSessionParticipantCache.getInstance().getValueFromCache(key,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), "OIDCSessionParticipantCacheEntry is null");
    }

    @Test
    public void testClearCacheEntry() {

        TestUtil.startTenantFlow("carbon.super");
        OIDCSessionParticipantCacheKey key = mock(OIDCSessionParticipantCacheKey.class);
        when(key.getSessionID()).thenReturn(SESSION_ID);
        OIDCSessionParticipantCache.getInstance().clearCacheEntry(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNull(OIDCSessionParticipantCache.getInstance().getValueFromCache(key,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), "OIDCSessionParticipantCacheEntry is not null");
    }
}
