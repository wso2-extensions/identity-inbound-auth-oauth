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

package org.wso2.carbon.identity.oauth2.validators.validationhandler.impl;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerException;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link RoleBasedScopeValidationHandler}.
 */
@Listeners(MockitoTestNGListener.class)
public class RoleBasedScopeValidationHandlerTest {

    private static final String APP_ID = "app-id-001";
    private static final String SHARED_APP_ID = "shared-app-id-002";
    private static final String APP_TENANT_DOMAIN = "app.org.com";
    private static final String USER_TENANT_DOMAIN = "user.org.com";
    private static final String APP_ORG_ID = "app-org-id";
    private static final String USER_ORG_ID = "user-org-id";
    private static final String ROLE_ID_1 = "role-1";
    private static final String ROLE_ID_2 = "role-2";

    @Mock
    private OAuth2ServiceComponentHolder oAuth2ServiceComponentHolder;
    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;
    @Mock
    private OrganizationManager organizationManager;
    @Mock
    private ApplicationManagementService applicationManagementService;
    @Mock
    private ApplicationManagementService appMgtServiceForAudience;
    @Mock
    private RoleManagementService roleManagementService;
    @Mock
    private AuthenticatedUser authenticatedUser;

    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic;
    private MockedStatic<AuthzUtil> authzUtilMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<IdentityUtil> identityUtilMockedStatic;

    private RoleBasedScopeValidationHandler handler;

    @BeforeMethod
    public void setUp() {

        handler = new RoleBasedScopeValidationHandler();

        oAuth2ServiceComponentHolderMockedStatic = mockStatic(OAuth2ServiceComponentHolder.class);
        oAuthComponentServiceHolderMockedStatic = mockStatic(OAuthComponentServiceHolder.class);
        authzUtilMockedStatic = mockStatic(AuthzUtil.class);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityUtilMockedStatic = mockStatic(IdentityUtil.class);

        oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getInstance)
                .thenReturn(oAuth2ServiceComponentHolder);
        oAuthComponentServiceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance)
                .thenReturn(oAuthComponentServiceHolder);

        lenient().when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        lenient().when(oAuthComponentServiceHolder.getApplicationManagementService())
                .thenReturn(applicationManagementService);
        lenient().when(oAuthComponentServiceHolder.getRoleV2ManagementService())
                .thenReturn(roleManagementService);
        oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getApplicationMgtService)
                .thenReturn(appMgtServiceForAudience);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                .thenReturn(APP_TENANT_DOMAIN);
        identityUtilMockedStatic.when(IdentityUtil::getMaximumItemPerPage).thenReturn(100);
    }

    @AfterMethod
    public void tearDown() {

        oAuth2ServiceComponentHolderMockedStatic.close();
        oAuthComponentServiceHolderMockedStatic.close();
        authzUtilMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        identityUtilMockedStatic.close();
    }

    @DataProvider(name = "canHandleDataProvider")
    public Object[][] canHandleDataProvider() {

        return new Object[][] {
                {"RBAC", "authorization_code", "USER", true},
                {"RBAC", "client_credentials", "APPLICATION", false},
                {"RBAC", "organization_switch", "APPLICATION", false},
                {"RBAC", "organization_switch", "USER", true},
                {"OTHER_POLICY", "authorization_code", "USER", false},
        };
    }

    @Test(dataProvider = "canHandleDataProvider")
    public void testCanHandle(String policyId, String grantType, String userType, boolean expected) {

        ScopeValidationContext ctx = buildContext(policyId, grantType, userType, APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);
        assertEquals(handler.canHandle(ctx), expected);
    }

    @Test
    public void testValidateScopesWhenUserRolesEmpty() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Collections.emptyList());
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any()))
                .thenReturn(true);

        List<String> result = handler.validateScopes(
                Arrays.asList("scope1", "scope2"),
                Arrays.asList("scope1", "scope2"),
                ctx);

        assertTrue(result.isEmpty(), "Expected empty list when user has no roles");
    }

    @Test
    public void testValidateScopes() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);

        List<String> userRoles = Arrays.asList(ROLE_ID_1, ROLE_ID_2);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString())).thenReturn(userRoles);
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(true);

        // Application audience is APPLICATION, so roles associated with the app are fetched.
        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(APP_ID, APP_TENANT_DOMAIN))
                .thenReturn(RoleConstants.APPLICATION);
        when(applicationManagementService.getTenantIdByApp(APP_ID)).thenReturn(1);
        when(applicationManagementService.getAssociatedRolesOfApplication(eq(APP_ID), any()))
                .thenReturn(Collections.emptyList());
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(Collections.emptyList());

        handler.validateScopes(Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);

        // Organization manager must NOT be invoked when domains are equal.
        verify(organizationManager, never()).resolveOrganizationId(anyString());
        verify(applicationManagementService, never()).getSharedAppId(anyString(), anyString(), anyString());
    }

    @Test
    public void testValidateScopesOrgSharedApps() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        List<String> userRoles = Arrays.asList(ROLE_ID_1, ROLE_ID_2);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString())).thenReturn(userRoles);
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID))
                .thenReturn(SHARED_APP_ID);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(SHARED_APP_ID, USER_TENANT_DOMAIN))
                .thenReturn(RoleConstants.APPLICATION);
        when(applicationManagementService.getTenantIdByApp(SHARED_APP_ID)).thenReturn(2);

        org.wso2.carbon.identity.application.common.model.RoleV2 roleV2 =
                new org.wso2.carbon.identity.application.common.model.RoleV2();
        roleV2.setId(ROLE_ID_1);
        when(applicationManagementService.getAssociatedRolesOfApplication(eq(SHARED_APP_ID), any()))
                .thenReturn(Collections.singletonList(roleV2));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(eq(Arrays.asList(ROLE_ID_1)),
                eq(USER_TENANT_DOMAIN))).thenReturn(Arrays.asList("scope1", "scope2"));

        List<String> result = handler.validateScopes(
                Arrays.asList("scope1", "scope2"),
                Arrays.asList("scope1", "scope2"),
                ctx);

        assertEquals(result, Arrays.asList("scope1", "scope2"));

        verify(applicationManagementService).getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID);
        verify(applicationManagementService).getAssociatedRolesOfApplication(eq(SHARED_APP_ID), any());
    }

    @Test
    public void testValidateScopesLegacySaaSApps() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        List<String> userRoles = Arrays.asList(ROLE_ID_1);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString())).thenReturn(userRoles);
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID)).thenReturn("");

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(APP_ID, USER_TENANT_DOMAIN))
                .thenReturn(RoleConstants.APPLICATION);
        when(applicationManagementService.getTenantIdByApp(APP_ID)).thenReturn(1);
        when(applicationManagementService.getAssociatedRolesOfApplication(eq(APP_ID), any()))
                .thenReturn(Collections.emptyList());
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(Collections.emptyList());

        handler.validateScopes(Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);

        verify(applicationManagementService).getAssociatedRolesOfApplication(eq(APP_ID), any());
    }

    @Test
    public void testAssociatedScopesRetrievedWithUserTenantDomain() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        List<String> userRoles = Arrays.asList(ROLE_ID_1);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString())).thenReturn(userRoles);
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID)).thenReturn(SHARED_APP_ID);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(SHARED_APP_ID, USER_TENANT_DOMAIN))
                .thenReturn(RoleConstants.APPLICATION);
        when(applicationManagementService.getTenantIdByApp(SHARED_APP_ID)).thenReturn(2);

        org.wso2.carbon.identity.application.common.model.RoleV2 roleV2 =
                new org.wso2.carbon.identity.application.common.model.RoleV2();
        roleV2.setId(ROLE_ID_1);
        when(applicationManagementService.getAssociatedRolesOfApplication(eq(SHARED_APP_ID), any()))
                .thenReturn(Collections.singletonList(roleV2));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(Arrays.asList("scope1"));

        handler.validateScopes(Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);

        authzUtilMockedStatic.verify(() ->
                AuthzUtil.getAssociatedScopesForRoles(any(), eq(USER_TENANT_DOMAIN)));
        authzUtilMockedStatic.verify(() ->
                AuthzUtil.getAssociatedScopesForRoles(any(), eq(APP_TENANT_DOMAIN)), never());
    }

    @Test(expectedExceptions = ScopeValidationHandlerException.class)
    public void testValidateScopesThrowsOnOrganizationManagementException() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(anyString()))
                .thenThrow(new OrganizationManagementException("org error"));

        handler.validateScopes(Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);
    }

    @Test(expectedExceptions = ScopeValidationHandlerException.class)
    public void testValidateScopesThrowsOnApplicationManagementException() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(true);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(APP_ID, APP_TENANT_DOMAIN))
                .thenThrow(new IdentityApplicationManagementException("app mgt error"));

        handler.validateScopes(Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);
    }

    @Test
    public void testValidateScopesFiltersInternalScopesForSubOrgAccess() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);

        // Same domain after resolving accessing org tenant.
        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID)).thenReturn(SHARED_APP_ID);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(anyString(), anyString()))
                .thenReturn(RoleConstants.APPLICATION);
        when(applicationManagementService.getTenantIdByApp(anyString())).thenReturn(2);
        org.wso2.carbon.identity.application.common.model.RoleV2 roleV2 =
                new org.wso2.carbon.identity.application.common.model.RoleV2();
        roleV2.setId(ROLE_ID_1);
        when(applicationManagementService.getAssociatedRolesOfApplication(anyString(), any()))
                .thenReturn(Collections.singletonList(roleV2));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(new java.util.ArrayList<>(Arrays.asList("internal_org_user_mgt_view", "internal_login")));

        List<String> appAuthorizedScopes = Arrays.asList("internal_org_user_mgt_view", "internal_login");
        List<String> result = handler.validateScopes(appAuthorizedScopes, appAuthorizedScopes, ctx);

        assertTrue(result.contains("internal_org_user_mgt_view"),
                "internal_org_ scopes should be retained");
        assertFalse(result.contains("internal_login"),
                "plain internal_ scopes should be removed for sub-org access");
    }

    @Test
    public void testValidateScopesWithOrganizationAudience() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1, ROLE_ID_2));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(true);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(APP_ID, APP_TENANT_DOMAIN))
                .thenReturn(RoleConstants.ORGANIZATION);

        RoleBasicInfo orgRole1 = buildRoleBasicInfo(ROLE_ID_1);
        RoleBasicInfo orgRole2 = buildRoleBasicInfo(ROLE_ID_2);
        when(roleManagementService.getRoles(anyString(), eq(100), eq(1), any(), any(), eq(APP_TENANT_DOMAIN)))
                .thenReturn(Arrays.asList(orgRole1, orgRole2));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(
                eq(Arrays.asList(ROLE_ID_1, ROLE_ID_2)), eq(APP_TENANT_DOMAIN)))
                .thenReturn(Arrays.asList("scope1", "scope2"));

        List<String> result = handler.validateScopes(
                Arrays.asList("scope1", "scope2"),
                Arrays.asList("scope1", "scope2"),
                ctx);

        assertEquals(result, Arrays.asList("scope1", "scope2"));
        verify(roleManagementService).getRoles(anyString(), eq(100), eq(1), any(), any(), eq(APP_TENANT_DOMAIN));
        verify(applicationManagementService, never()).getAssociatedRolesOfApplication(anyString(), any());
    }

    @Test
    public void testValidateScopesOrgSharedAppsWithOrganizationAudience() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1, ROLE_ID_2));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID))
                .thenReturn(SHARED_APP_ID);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(SHARED_APP_ID, USER_TENANT_DOMAIN))
                .thenReturn(RoleConstants.ORGANIZATION);

        RoleBasicInfo orgRole = buildRoleBasicInfo(ROLE_ID_1);
        when(roleManagementService.getRoles(anyString(), eq(100), eq(1), any(), any(), eq(USER_TENANT_DOMAIN)))
                .thenReturn(Collections.singletonList(orgRole));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(
                eq(Collections.singletonList(ROLE_ID_1)), eq(USER_TENANT_DOMAIN)))
                .thenReturn(Arrays.asList("scope1", "scope2"));

        List<String> result = handler.validateScopes(
                Arrays.asList("scope1", "scope2"),
                Arrays.asList("scope1", "scope2"),
                ctx);

        assertEquals(result, Arrays.asList("scope1", "scope2"));
        verify(roleManagementService).getRoles(anyString(), eq(100), eq(1), any(), any(), eq(USER_TENANT_DOMAIN));
        verify(applicationManagementService, never()).getAssociatedRolesOfApplication(anyString(), any());
    }

    @Test
    public void testValidateScopesLegacySaaSAppsWithOrganizationAudience() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID)).thenReturn("");

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(APP_ID, USER_TENANT_DOMAIN))
                .thenReturn(RoleConstants.ORGANIZATION);

        RoleBasicInfo orgRole = buildRoleBasicInfo(ROLE_ID_1);
        when(roleManagementService.getRoles(anyString(), eq(100), eq(1), any(), any(), eq(USER_TENANT_DOMAIN)))
                .thenReturn(Collections.singletonList(orgRole));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(Arrays.asList("scope1"));

        List<String> result = handler.validateScopes(
                Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);

        assertEquals(result, Collections.singletonList("scope1"));
        verify(roleManagementService).getRoles(anyString(), eq(100), eq(1), any(), any(), eq(USER_TENANT_DOMAIN));
        verify(applicationManagementService, never()).getAssociatedRolesOfApplication(anyString(), any());
    }

    @Test
    public void testAssociatedScopesRetrievedWithUserTenantDomainWithOrganizationAudience() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, USER_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID)).thenReturn(SHARED_APP_ID);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(SHARED_APP_ID, USER_TENANT_DOMAIN))
                .thenReturn(RoleConstants.ORGANIZATION);

        RoleBasicInfo orgRole = buildRoleBasicInfo(ROLE_ID_1);
        when(roleManagementService.getRoles(anyString(), eq(100), eq(1), any(), any(), eq(USER_TENANT_DOMAIN)))
                .thenReturn(Collections.singletonList(orgRole));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(Arrays.asList("scope1"));

        handler.validateScopes(Arrays.asList("scope1"), Arrays.asList("scope1"), ctx);

        authzUtilMockedStatic.verify(() ->
                AuthzUtil.getAssociatedScopesForRoles(any(), eq(USER_TENANT_DOMAIN)));
        authzUtilMockedStatic.verify(() ->
                AuthzUtil.getAssociatedScopesForRoles(any(), eq(APP_TENANT_DOMAIN)), never());
    }

    @Test
    public void testFiltersInternalScopesForSubOrgAccessWithOrganizationAudience() throws Exception {

        ScopeValidationContext ctx = buildContext("RBAC", "authorization_code", "USER",
                APP_TENANT_DOMAIN, APP_TENANT_DOMAIN);
        when(authenticatedUser.getAccessingOrganization()).thenReturn(USER_ORG_ID);
        when(organizationManager.resolveTenantDomain(USER_ORG_ID)).thenReturn(USER_TENANT_DOMAIN);

        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(any(), anyString()))
                .thenReturn(Arrays.asList(ROLE_ID_1));
        authzUtilMockedStatic.when(() -> AuthzUtil.isUserAccessingResidentOrganization(any())).thenReturn(false);

        when(organizationManager.resolveOrganizationId(APP_TENANT_DOMAIN)).thenReturn(APP_ORG_ID);
        when(organizationManager.resolveOrganizationId(USER_TENANT_DOMAIN)).thenReturn(USER_ORG_ID);
        when(applicationManagementService.getSharedAppId(APP_ID, APP_ORG_ID, USER_ORG_ID)).thenReturn(SHARED_APP_ID);

        when(appMgtServiceForAudience.getAllowedAudienceForRoleAssociation(anyString(), anyString()))
                .thenReturn(RoleConstants.ORGANIZATION);

        RoleBasicInfo orgRole = buildRoleBasicInfo(ROLE_ID_1);
        when(roleManagementService.getRoles(anyString(), eq(100), eq(1), any(), any(), anyString()))
                .thenReturn(Collections.singletonList(orgRole));

        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(any(), anyString()))
                .thenReturn(new java.util.ArrayList<>(Arrays.asList("internal_org_user_mgt_view", "internal_login")));

        List<String> appAuthorizedScopes = Arrays.asList("internal_org_user_mgt_view", "internal_login");
        List<String> result = handler.validateScopes(appAuthorizedScopes, appAuthorizedScopes, ctx);

        assertTrue(result.contains("internal_org_user_mgt_view"),
                "internal_org_ scopes should be retained");
        assertFalse(result.contains("internal_login"),
                "plain internal_ scopes should be removed for sub-org access");
    }

    @Test
    public void testGetPolicyID() {

        assertEquals(handler.getPolicyID(), "RBAC");
    }

    @Test
    public void testGetName() {

        assertEquals(handler.getName(), "RoleBasedScopeValidationHandler");
    }

    private RoleBasicInfo buildRoleBasicInfo(String roleId) {

        RoleBasicInfo role = new RoleBasicInfo();
        role.setId(roleId);
        return role;
    }

    private ScopeValidationContext buildContext(String policyId, String grantType, String userType,
                                               String appTenantDomain, String userTenantDomain) {

        lenient().when(authenticatedUser.getTenantDomain()).thenReturn(userTenantDomain);

        ScopeValidationContext ctx = new ScopeValidationContext();
        ctx.setPolicyId(policyId);
        ctx.setGrantType(grantType);
        ctx.setUserType(userType);
        ctx.setAppId(APP_ID);
        ctx.setAppTenantDomain(appTenantDomain);
        ctx.setAuthenticatedUser(authenticatedUser);
        return ctx;
    }
}
