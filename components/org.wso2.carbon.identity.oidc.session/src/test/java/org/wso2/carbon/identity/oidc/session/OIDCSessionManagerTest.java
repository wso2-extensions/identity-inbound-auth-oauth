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
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oidc.session.servlet.TestOIDCSessionBase;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit test coverage for OIDCSessionManager
 */
@Listeners(MockitoTestNGListener.class)
public class OIDCSessionManagerTest extends TestOIDCSessionBase {

    @Mock
    OIDCSessionState oidcSessionState;

    private OIDCSessionManager oidcSessionManager;
    private static final String SESSION_ID = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String NEW_SESSION_ID = "080907ce-eab0-40d2-a46d-acd4bb33f0d0";

    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void init() throws Exception {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        initiateInMemoryH2SessionDB(identityDatabaseUtil);
    }

    @AfterClass
    public void tearDownClass() {

        identityDatabaseUtil.close();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        oidcSessionManager = new OIDCSessionManager();
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).
                thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID)).
                thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @AfterMethod
    public void tearDown() {

        identityTenantUtil.close();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @Test
    public void testStoreOIDCSessionState() {

        oidcSessionManager.storeOIDCSessionState(SESSION_ID, oidcSessionState,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNotNull(oidcSessionManager.getOIDCSessionState(SESSION_ID, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                "Session Id is not stored in OIDCSession state");
    }

    @Test
    public void testRemoveOIDCSessionState() {

        oidcSessionManager.removeOIDCSessionState(SESSION_ID, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNull(oidcSessionManager.getOIDCSessionState(SESSION_ID, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                "Session Id is removed from OIDCSession state");
    }

    @Test
    public void testRestoreOIDCSessionState() {

        OIDCSessionState oidcSessionState = new OIDCSessionState();
        oidcSessionManager.restoreOIDCSessionState(SESSION_ID, NEW_SESSION_ID, oidcSessionState,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNotNull(oidcSessionManager.getOIDCSessionState(NEW_SESSION_ID,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), "Session Id is not stored in " +
                "OIDCSession state");
    }

    @Test
    public void testSessionNotExists() {

        assertFalse(oidcSessionManager.sessionExists(SESSION_ID, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
    }

}
