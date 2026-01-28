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

package org.wso2.carbon.identity.oauth.listener;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.inbound.dto.ApplicationDTO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.User;

import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for UserApplicationCreationListener.
 */
public class UserApplicationCreationListenerTest extends IdentityBaseTest {

    private static final String AGENT_USERNAME = "agent123";
    private static final String AGENT_USERSTORE_DOMAIN = "AGENT";
    private static final String PRIMARY_USERSTORE_DOMAIN = "PRIMARY";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    public static final String AGENT_LISTENER_ENABLE = "AgentIdentity.ApplicationCreatorListener.Enabled";

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private User user;

    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;

    @Mock
    private ApplicationManagementService applicationManagementService;

    private MockedStatic<IdentityUtil> identityUtilMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic;

    private UserApplicationCreationListener listener;

    @BeforeMethod
    public void setUp() {

        openMocks(this);

        // Set up static mocks BEFORE creating the listener
        identityUtilMockedStatic = mockStatic(IdentityUtil.class);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        oAuthComponentServiceHolderMockedStatic = mockStatic(OAuthComponentServiceHolder.class);

        when(IdentityUtil.getProperty(AGENT_LISTENER_ENABLE)).thenReturn("true");

        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);
        when(oAuthComponentServiceHolder.getApplicationManagementService())
                .thenReturn(applicationManagementService);

        // Create the listener AFTER setting up the static mocks and property
        listener = new UserApplicationCreationListener();
    }

    @AfterMethod
    public void tearDown() {

        identityUtilMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        oAuthComponentServiceHolderMockedStatic.close();
    }

    @Test
    public void testDoPostAddUserWithID_ListenerDisabled() throws UserStoreException,
            IdentityApplicationManagementException {

        // Create a listener that returns false for isEnable()
        UserApplicationCreationListener disabledListener = new UserApplicationCreationListener() {
            @Override
            public boolean isEnable() {
                return false;
            }
        };

        setupCommonMocks();

        when(user.getUserStoreDomain()).thenReturn(AGENT_USERSTORE_DOMAIN);
        when(IdentityUtil.getAgentIdentityUserstoreName()).thenReturn(AGENT_USERSTORE_DOMAIN);

        boolean result = disabledListener.doPostAddUserWithID(user, "password", new String[]{"role1"},
                new HashMap<>(), null, userStoreManager);

        assertTrue(result, "Listener should return true when disabled");
        verify(applicationManagementService, never()).createApplication(
                any(ApplicationDTO.class), anyString(), anyString());
    }

    @Test
    public void testDoPostAddUserWithID_RegularUserNotAgent() throws UserStoreException,
            IdentityApplicationManagementException {

        setupCommonMocks();
        when(user.getUserStoreDomain()).thenReturn(PRIMARY_USERSTORE_DOMAIN);
        when(IdentityUtil.getAgentIdentityUserstoreName()).thenReturn(AGENT_USERSTORE_DOMAIN);

        boolean result = listener.doPostAddUserWithID(user, "password", new String[]{"role1"},
                new HashMap<>(), null, userStoreManager);

        assertTrue(result, "Listener should return true for regular users");
        verify(applicationManagementService, never()).createApplication(
                any(ApplicationDTO.class), anyString(), anyString());
    }

    @Test
    public void testDoPostAddUserWithID_AgentUserSuccessfulAppCreation()
            throws UserStoreException, IdentityApplicationManagementException {

        setupCommonMocks();
        setupAgentUserMocks();
        when(applicationManagementService.createApplication(any(ApplicationDTO.class), anyString(),
                anyString())).thenReturn(AGENT_USERNAME);

        boolean result = listener.doPostAddUserWithID(user, "password", new String[]{"role1"},
                new HashMap<>(), null, userStoreManager);

        assertTrue(result, "Listener should return true after successful application creation");

        ArgumentCaptor<ApplicationDTO> applicationDTOCaptor =
                ArgumentCaptor.forClass(ApplicationDTO.class);
        verify(applicationManagementService).createApplication(applicationDTOCaptor.capture(),
                eq(TENANT_DOMAIN), eq(AGENT_USERNAME));

        ApplicationDTO capturedAppDTO = applicationDTOCaptor.getValue();
        assertNotNull(capturedAppDTO, "ApplicationDTO should not be null");
        assertNotNull(capturedAppDTO.getServiceProvider(), "ServiceProvider should not be null");

        // Verify that the application resource ID passed to the service equals the agent username
        assertEquals(capturedAppDTO.getServiceProvider().getApplicationResourceId(),
                AGENT_USERNAME,
                "Application resource ID should match the agent username");

        // Verify that when createApplication is called, it returns the agent username as application ID
        String returnedApplicationId =
                applicationManagementService.createApplication(
                        capturedAppDTO, TENANT_DOMAIN, AGENT_USERNAME);
        assertEquals(returnedApplicationId, AGENT_USERNAME,
                "The application ID returned by createApplication should equal the agent username");

    }

    private void setupCommonMocks() throws UserStoreException {

        when(user.getUsername()).thenReturn(AGENT_USERNAME);
        when(userStoreManager.getTenantId()).thenReturn(TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
    }

    private void setupAgentUserMocks() {

        when(user.getUserStoreDomain()).thenReturn(AGENT_USERSTORE_DOMAIN);
        when(IdentityUtil.getAgentIdentityUserstoreName()).thenReturn(AGENT_USERSTORE_DOMAIN);
    }
}
