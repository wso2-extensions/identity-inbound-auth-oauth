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
package org.wso2.carbon.identity.oidc.session;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCacheEntry;
import org.wso2.carbon.identity.oidc.session.servlet.TestOIDCSessionBase;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit test coverage for OIDCSessionManager
 */
@PrepareForTest({OIDCSessionParticipantCache.class, OIDCSessionParticipantCacheEntry.class})
public class OIDCSessionManagerTest extends TestOIDCSessionBase {

    @Mock
    OIDCSessionState oidcSessionState;

    private OIDCSessionManager oidcSessionManager;
    private static final String SESSION_ID = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String NEW_SESSION_ID = "080907ce-eab0-40d2-a46d-acd4bb33f0d0";

    @BeforeMethod
    public void setUp() throws Exception {
        oidcSessionManager=new OIDCSessionManager();
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Test
    public void testStoreOIDCSessionState() {
        oidcSessionManager.storeOIDCSessionState(SESSION_ID, oidcSessionState);
        assertNotNull(oidcSessionManager.getOIDCSessionState(SESSION_ID), "Session Id is not stored in OIDCSession " +
                "state");
    }

    @Test
    public void testRemoveOIDCSessionState(){
        oidcSessionManager.removeOIDCSessionState(SESSION_ID);
        assertNull(oidcSessionManager.getOIDCSessionState(SESSION_ID), "Session Id is removed from OIDCSession " +
                "state");
    }

    @Test
    public void testRestoreOIDCSessionState() {
        OIDCSessionState oidcSessionState = new OIDCSessionState();
        oidcSessionManager.restoreOIDCSessionState(SESSION_ID, NEW_SESSION_ID, oidcSessionState);
        assertNotNull(oidcSessionManager.getOIDCSessionState(NEW_SESSION_ID), "Session Id is not stored in " +
                "OIDCSession state");
    }

    @Test
    public void testSessionNotExists(){
       assertFalse(oidcSessionManager.sessionExists(SESSION_ID));
    }

}
