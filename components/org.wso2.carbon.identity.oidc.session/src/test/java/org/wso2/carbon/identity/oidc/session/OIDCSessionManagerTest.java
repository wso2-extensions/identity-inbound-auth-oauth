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
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit test coverage for OIDCSessionManager.
 * Migrated from PowerMock to Mockito MockedStatic (Java 21 compatible).
 *
 * Why IdentityConfigParser is mocked:
 *   getOIDCSessionState() -> OIDCSessionParticipantCache.getValueFromCache()
 *   -> SessionDataStore.getSessionContextData()
 *   -> IdentityDatabaseUtil.getSessionDBConnection()
 *   -> JDBCPersistenceManager.getInstance()
 *   -> IdentityConfigParser.getInstance()
 *   -> reads identity.xml from CARBON_HOME (null in unit tests) -> FileNotFoundException.
 *   Mocking IdentityConfigParser cuts this chain before any file I/O occurs.
 */
public class OIDCSessionManagerTest {

    @Mock
    OIDCSessionState oidcSessionState;

    @Mock
    IdentityConfigParser identityConfigParser;

    private OIDCSessionManager oidcSessionManager;
    private MockedStatic<IdentityConfigParser> identityConfigParserMock;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMock;
    private AutoCloseable mocks;

    private static final String SESSION_ID = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String NEW_SESSION_ID = "080907ce-eab0-40d2-a46d-acd4bb33f0d0";

    @BeforeMethod
    public void setUp() throws Exception {

        mocks = MockitoAnnotations.openMocks(this);
        oidcSessionManager = new OIDCSessionManager();
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        identityConfigParserMock = Mockito.mockStatic(IdentityConfigParser.class);
        identityConfigParserMock.when(IdentityConfigParser::getInstance).thenReturn(identityConfigParser);

        identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantDomain(
                MultitenantConstants.SUPER_TENANT_ID))
                .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        identityTenantUtilMock.close();
        identityConfigParserMock.close();
        mocks.close();
    }

    @Test
    public void testStoreOIDCSessionState() {

        oidcSessionManager.storeOIDCSessionState(SESSION_ID, oidcSessionState,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNotNull(oidcSessionManager.getOIDCSessionState(SESSION_ID,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                "Session Id is not stored in OIDCSession state");
    }

    @Test
    public void testRemoveOIDCSessionState() {

        oidcSessionManager.removeOIDCSessionState(SESSION_ID, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNull(oidcSessionManager.getOIDCSessionState(SESSION_ID,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                "Session Id is removed from OIDCSession state");
    }

    @Test
    public void testRestoreOIDCSessionState() {

        OIDCSessionState newOidcSessionState = new OIDCSessionState();
        oidcSessionManager.restoreOIDCSessionState(SESSION_ID, NEW_SESSION_ID, newOidcSessionState,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNotNull(oidcSessionManager.getOIDCSessionState(NEW_SESSION_ID,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                "Session Id is not stored in OIDCSession state");
    }

    @Test
    public void testSessionNotExists() {

        assertFalse(oidcSessionManager.sessionExists(SESSION_ID, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
    }
}
