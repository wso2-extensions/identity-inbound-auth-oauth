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
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.inbound.dto.ApplicationDTO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;

import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class UserApplicationCreationListenerTest extends IdentityBaseTest {

    private static final String AGENT_USERNAME = "agent123";
    private static final String AGENT_USERSTORE_DOMAIN = "AGENT";
    private static final String PRIMARY_USERSTORE_DOMAIN = "PRIMARY";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    public static final String AGENT_LISTENER_ENABLE = "AgentIdentity.ApplicationCreatorListener.Enabled";
    public static final String AGENT_LISTENER_ORDER_ID = "AgentIdentity.ApplicationCreatorListener.Order";

    @Mock
    private AbstractUserStoreManager userStoreManager;

    @Mock
    private User user;

    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;

    @Mock
    private ApplicationManagementService applicationManagementService;

    @Mock
    private ServiceProvider mockServiceProvider;

    private MockedStatic<IdentityUtil> identityUtilMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic;

    private UserApplicationCreationListener listener;

    @BeforeMethod
    public void setUp() throws Exception {

        openMocks(this);

        // Initialize the ThreadLocal in IdentityUtil before mocking
        // Since threadLocalProperties is static final, we can't replace it,
        // but we can set its value
        IdentityUtil.threadLocalProperties.set(new HashMap<>());

        // Set up static mocks - use CALLS_REAL_METHODS to allow field access
        identityUtilMockedStatic = mockStatic(IdentityUtil.class, org.mockito.Mockito.CALLS_REAL_METHODS);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        oAuthComponentServiceHolderMockedStatic = mockStatic(OAuthComponentServiceHolder.class);

        // Mock only the specific static methods we need
        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(AGENT_LISTENER_ENABLE)).thenReturn("true");
        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(AGENT_LISTENER_ORDER_ID)).thenReturn("99");

        oAuthComponentServiceHolderMockedStatic.when(() -> OAuthComponentServiceHolder.getInstance())
                .thenReturn(oAuthComponentServiceHolder);
        when(oAuthComponentServiceHolder.getApplicationManagementService())
                .thenReturn(applicationManagementService);

        listener = new UserApplicationCreationListener();
    }

    @AfterMethod
    public void tearDown() {

        // Clean up the ThreadLocal
        IdentityUtil.threadLocalProperties.remove();

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
        identityUtilMockedStatic.when(() -> IdentityUtil.getAgentIdentityUserstoreName())
                .thenReturn(AGENT_USERSTORE_DOMAIN);

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
        identityUtilMockedStatic.when(() -> IdentityUtil.getAgentIdentityUserstoreName())
                .thenReturn(AGENT_USERSTORE_DOMAIN);

        boolean result = listener.doPostAddUserWithID(user, "password", new String[]{"role1"},
                new HashMap<>(), null, userStoreManager);

        assertTrue(result, "Listener should return true for regular users");
        verify(applicationManagementService, never()).createApplication(
                any(ApplicationDTO.class), anyString(), anyString());
    }

    @Test
    public void testDoPostAddUserWithID_NonUserServingAgentNoAppCreation()
            throws UserStoreException, IdentityApplicationManagementException {

        setupCommonMocks();
        when(user.getUserStoreDomain()).thenReturn(AGENT_USERSTORE_DOMAIN);
        identityUtilMockedStatic.when(() -> IdentityUtil.getAgentIdentityUserstoreName())
                .thenReturn(AGENT_USERSTORE_DOMAIN);
        // Set isUserServingAgent to false in threadLocalProperties
        IdentityUtil.threadLocalProperties.get().put("isUserServingAgent", false);

        boolean result = listener.doPostAddUserWithID(user, "password", new String[]{"role1"},
                new HashMap<>(), null, userStoreManager);

        assertTrue(result, "Listener should return true for non-user-serving agents");
        verify(applicationManagementService, never()).createApplication(
                any(ApplicationDTO.class), anyString(), anyString());
    }

    @Test
    public void testDoPostAddUserWithID_AgentUserSuccessfulAppCreation()
            throws UserStoreException, IdentityApplicationManagementException {

        setupCommonMocks();
        setupAgentUserMocks();

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

        // Verify that the application resource ID is set and is derived from the agent username
        String resourceId = capturedAppDTO.getServiceProvider().getApplicationResourceId();
        assertNotNull(resourceId, "Application resource ID should not be null");
        assertTrue(resourceId.contains(AGENT_USERNAME),
                "Application resource ID should be derived from the agent username");

        // Verify that API-based authentication is enabled on the agent application
        assertTrue(capturedAppDTO.getServiceProvider().isAPIBasedAuthenticationEnabled(),
                "API-based authentication should be enabled for agent applications");
    }

    @Test
    public void testDoPostAddUserWithID_AppCreationFailureRollsBackAndThrows()
            throws IdentityApplicationManagementException {

        String agentUserId = "agent-user-id-123";
        try {
            setupCommonMocks();
        } catch (UserStoreException e) {
            fail("Setup failed: " + e.getMessage());
        }
        setupAgentUserMocks();
        when(user.getUserID()).thenReturn(agentUserId);
        doThrow(new IdentityApplicationManagementException("Application creation failed"))
                .when(applicationManagementService)
                .createApplication(any(ApplicationDTO.class), anyString(), anyString());

        try {
            listener.doPostAddUserWithID(user, "password", new String[]{"role1"},
                    new HashMap<>(), null, userStoreManager);
            fail("Expected UserStoreException to be thrown when application creation fails");
        } catch (UserStoreException e) {
            // Must throw UserStoreException so the failure propagates to the API layer,
            // which then returns an HTTP error and prevents the UI from showing a false success.
            assertTrue(e.getMessage().contains("Agent application creation failed for agent"),
                    "Exception message should indicate agent application creation failure");
        }

        // Verify the agent was deleted (rollback) before the exception was thrown.
        try {
            verify(userStoreManager).deleteUserWithID(agentUserId);
        } catch (UserStoreException e) {
            fail("Verification failed: " + e.getMessage());
        }
    }

    @Test
    public void testDoPreDeleteUserWithID_AppDeletionFailureBlocksAgentDeletion()
            throws IdentityApplicationManagementException {

        String agentUserId = "agent-user-id-456";
        String agentAppName = "AGENT-agent123";

        try {
            when(userStoreManager.getUserWithID(agentUserId, null, null)).thenReturn(user);
            when(user.getUsername()).thenReturn(AGENT_USERNAME);
            when(user.getUserStoreDomain()).thenReturn(AGENT_USERSTORE_DOMAIN);
            when(userStoreManager.getTenantId()).thenReturn(TENANT_ID);
        } catch (UserStoreException e) {
            fail("Setup failed: " + e.getMessage());
        }
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                .thenReturn(TENANT_DOMAIN);
        identityUtilMockedStatic.when(() -> IdentityUtil.getAgentIdentityUserstoreName())
                .thenReturn(AGENT_USERSTORE_DOMAIN);
        when(applicationManagementService.getApplicationByResourceId(AGENT_USERNAME, TENANT_DOMAIN))
                .thenReturn(mockServiceProvider);
        when(mockServiceProvider.getApplicationName()).thenReturn(agentAppName);
        doThrow(new IdentityApplicationManagementException("Application deletion failed"))
                .when(applicationManagementService)
                .deleteApplication(anyString(), anyString(), anyString());

        try {
            listener.doPreDeleteUserWithID(agentUserId, userStoreManager);
            fail("Expected UserStoreException to be thrown when application deletion fails");
        } catch (UserStoreException e) {
            // App deletion failed — agent must not be deleted to avoid leaving orphan data.
            assertTrue(e.getMessage().contains("Agent application deletion failed for agent"),
                    "Exception message should indicate agent application deletion failure");
        }
    }

    private void setupCommonMocks() throws UserStoreException {

        when(user.getUsername()).thenReturn(AGENT_USERNAME);
        when(userStoreManager.getTenantId()).thenReturn(TENANT_ID);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                .thenReturn(TENANT_DOMAIN);
    }

    private void setupAgentUserMocks() {

        when(user.getUserStoreDomain()).thenReturn(AGENT_USERSTORE_DOMAIN);
        identityUtilMockedStatic.when(() -> IdentityUtil.getAgentIdentityUserstoreName())
                .thenReturn(AGENT_USERSTORE_DOMAIN);
        // Set isUserServingAgent to true in threadLocalProperties
        IdentityUtil.threadLocalProperties.get().put("isUserServingAgent", true);
    }
}
