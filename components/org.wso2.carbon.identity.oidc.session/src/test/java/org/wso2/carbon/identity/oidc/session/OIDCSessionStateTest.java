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

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit test coverage for OIDCSessionState class.
 */
public class OIDCSessionStateTest extends PowerMockIdentityBaseTest {

    private static final String USERNAME = "user1";
    private static final String CLIENT_ID_VALUE = "3T9l2uUf8AzNOfmGS9lPEIsdrR8a";
    private OIDCSessionState oidcSessionState;

    @BeforeTest
    public void setUp() {
        oidcSessionState = new OIDCSessionState();
    }

    @Test
    public void testSetAuthenticatedUser() {
        oidcSessionState.setAuthenticatedUser(USERNAME);
        assertNotNull(oidcSessionState.getAuthenticatedUser(), "User is not authenticated");
    }

    @Test
    public void testSetSessionParticipants() {
        Set<String> authenticatedUesrs = new HashSet<>();
        authenticatedUesrs.add(CLIENT_ID_VALUE);
        oidcSessionState.setSessionParticipants(authenticatedUesrs);
        assertNotNull(oidcSessionState.getSessionParticipants(), "Session participants is null");
    }

    @Test
    public void testAddSessionParticipant() {
        String client_id = "ES9l2uUf8AzNOfmGS9lPEIsdrR8a";
        oidcSessionState.addSessionParticipant(client_id);
        Set sessionParticipants = oidcSessionState.getSessionParticipants();
        assertNotNull(sessionParticipants.contains(client_id), "Client_id is not a session participant");
    }

    @Test
    public void testSetAuthenticated() throws Exception {
        oidcSessionState.setAuthenticated(true);
        assertTrue(oidcSessionState.isAuthenticated(), "Authenticated flag is false");
    }

    @Test
    public void testSetAddSessionState() throws Exception {
        oidcSessionState.setAddSessionState(true);
        assertTrue(oidcSessionState.isAddSessionState(), "Add session state flag is false");
    }
}
