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

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit test coverage for OIDCSessionParticipantCache class.
 */
public class OIDCSessionParticipantCacheTest extends PowerMockTestCase {

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
        OIDCSessionParticipantCache.getInstance().addToCache(key, entry);
        assertNotNull(OIDCSessionParticipantCache.getInstance().getValueFromCache(key),
                "OIDCSessionParticipantCacheEntry is null");
    }

    @Test
    public void testClearCacheEntry() {
        TestUtil.startTenantFlow("carbon.super");
        OIDCSessionParticipantCacheKey key = mock(OIDCSessionParticipantCacheKey.class);
        when(key.getSessionID()).thenReturn(SESSION_ID);
        OIDCSessionParticipantCache.getInstance().clearCacheEntry(key);
        assertNull(OIDCSessionParticipantCache.getInstance().getValueFromCache(key),
                "OIDCSessionParticipantCacheEntry is not null");
    }
}
