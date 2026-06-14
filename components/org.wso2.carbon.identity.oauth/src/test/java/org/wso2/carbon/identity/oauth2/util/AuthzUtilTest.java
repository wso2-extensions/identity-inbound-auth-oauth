/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.AuthorizedScopes;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.AuthorizedAPIManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.agent.sharing.util.OrganizationSharedAgentUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.util.OrganizationSharedUserUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.user.core.UserStoreConfigConstants.PRIMARY;

/**
 * Unit tests for AuthzUtil class.
 */
@Listeners(MockitoTestNGListener.class)
public class AuthzUtilTest {

    @Mock
    private OAuth2ServiceComponentHolder oAuth2ServiceComponentHolder;
    @Mock
    private OrganizationManager organizationManager;
    @Mock
    private RoleManagementService roleManagementService;
    @Mock
    private AuthenticatedUser authenticatedUser;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic;
    private MockedStatic<AuthzUtil> authzUtilMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic;

    private static final String AGENT = "AGENT";
    private static final String USER_ID = "test-user-id";
    private static final String ACCESSING_ORGANIZATION = "accessing-org-id";
    private static final String TENANT_DOMAIN = "tenantDomain";
    private static final String USER_RESIDENT_ORG_TENANT = "resident-tenant";
    private static final String ACCESSING_ORG_TENANT = "accessing-tenant";
    private static final String SHARED_AGENT_ID = "shared-agent-id";
    private static final String SHARED_USER_ID = "shared-user-id";
    private static final String CLIENT_ID = "test-client-id";
    private static final String APP_ID = "test-app-id";

    @BeforeMethod
    public void setUp() {

        oAuth2ServiceComponentHolderMockedStatic = mockStatic(OAuth2ServiceComponentHolder.class);
        authzUtilMockedStatic = mockStatic(AuthzUtil.class, Mockito.CALLS_REAL_METHODS);
        oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getInstance)
                .thenReturn(oAuth2ServiceComponentHolder);
        oAuthServerConfigurationMockedStatic = mockStatic(OAuthServerConfiguration.class);
        lenient().when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    @AfterMethod
    public void tearDown() {

        if (oAuth2ServiceComponentHolderMockedStatic != null) {
            oAuth2ServiceComponentHolderMockedStatic.close();
        }
        if (authzUtilMockedStatic != null) {
            authzUtilMockedStatic.close();
        }
        if (oAuthServerConfigurationMockedStatic != null) {
            oAuthServerConfigurationMockedStatic.close();
        }
    }

    @Test
    public void testGetAppAuthorizedScopes() throws Exception {

        ApplicationManagementService applicationManagementService =
                Mockito.mock(ApplicationManagementService.class);
        AuthorizedAPIManagementService authorizedAPIManagementService =
                Mockito.mock(AuthorizedAPIManagementService.class);

        oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getApplicationMgtService)
                .thenReturn(applicationManagementService);
        when(applicationManagementService.getApplicationResourceIDByInboundKey(eq(CLIENT_ID), anyString(),
                eq(TENANT_DOMAIN))).thenReturn(APP_ID);
        when(oAuth2ServiceComponentHolder.getAuthorizedAPIManagementService())
                .thenReturn(authorizedAPIManagementService);
        when(authorizedAPIManagementService.getAuthorizedScopes(APP_ID, TENANT_DOMAIN)).thenReturn(
                Arrays.asList(new AuthorizedScopes("policy1", Arrays.asList("scope1", "scope2")),
                        new AuthorizedScopes("policy2", Arrays.asList("scope2", "scope3"))));

        List<String> scopes = AuthzUtil.getAppAuthorizedScopes(CLIENT_ID, TENANT_DOMAIN);

        // Scopes from all authorized scope policies are flattened and de-duplicated.
        Assert.assertEquals(scopes.size(), 3);
        Assert.assertTrue(scopes.containsAll(Arrays.asList("scope1", "scope2", "scope3")));
    }

    @Test
    public void testGetAuthorizedPermissions() throws Exception {

        List<String> roleIds = Arrays.asList("role1", "role2");
        List<String> permissions = Arrays.asList("perm1", "perm2");

        when(authenticatedUser.getAccessingOrganization()).thenReturn(null);
        when(authenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(authenticatedUser, null)).thenReturn(roleIds);
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(roleIds, TENANT_DOMAIN))
                .thenReturn(permissions);
        when(oAuthServerConfiguration.isUseLegacyPermissionAccessForUserBasedAuth()).thenReturn(false);

        List<String> authorizedPermissions = AuthzUtil.getAuthorizedPermissions(authenticatedUser);
        Assert.assertEquals(authorizedPermissions, permissions);
    }

    @Test
    public void testGetAuthorizedPermissionsWithAccessingOrg() throws Exception {

        List<String> roleIds = Arrays.asList("role1", "role2");
        List<String> permissions = Arrays.asList("perm1", "perm2");

        when(authenticatedUser.getAccessingOrganization()).thenReturn(ACCESSING_ORGANIZATION);
        when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(organizationManager.resolveTenantDomain(ACCESSING_ORGANIZATION)).thenReturn(ACCESSING_ORG_TENANT);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(authenticatedUser, null)).thenReturn(roleIds);
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(roleIds, ACCESSING_ORG_TENANT))
                .thenReturn(permissions);
        when(oAuthServerConfiguration.isUseLegacyPermissionAccessForUserBasedAuth()).thenReturn(false);

        List<String> authorizedPermissions = AuthzUtil.getAuthorizedPermissions(authenticatedUser);
        Assert.assertEquals(authorizedPermissions, permissions);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAuthorizedPermissionsWithRoleManagementException() throws Exception {

        List<String> roleIds = Arrays.asList("role1", "role2");

        when(authenticatedUser.getAccessingOrganization()).thenReturn(null);
        when(authenticatedUser.getTenantDomain()).thenReturn(USER_RESIDENT_ORG_TENANT);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(authenticatedUser, null)).thenReturn(roleIds);
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(roleIds, USER_RESIDENT_ORG_TENANT))
                .thenThrow(new IdentityOAuth2Exception(""));
        when(oAuthServerConfiguration.isUseLegacyPermissionAccessForUserBasedAuth()).thenReturn(false);

        AuthzUtil.getAuthorizedPermissions(authenticatedUser);
    }

    @Test
    public void testGetAuthorizedPermissionsWithLegacyPermissions() throws Exception {

        List<String> roleIds = Arrays.asList("role1", "role2");
        List<String> permissions = Arrays.asList("internal_login", "perm2");
        List<String> internalScopes = Arrays.asList("internal_login", "internal_other");
        Map<String, java.util.Set<String>> legacyMap = new HashMap<>();
        legacyMap.put("internal_login", new java.util.HashSet<>(Arrays.asList("new_scope1")));

        when(authenticatedUser.getAccessingOrganization()).thenReturn(null);
        when(authenticatedUser.getTenantDomain()).thenReturn(USER_RESIDENT_ORG_TENANT);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(authenticatedUser, null)).thenReturn(roleIds);
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(roleIds, USER_RESIDENT_ORG_TENANT))
                .thenReturn(new java.util.ArrayList<>(permissions));
        when(oAuthServerConfiguration.isUseLegacyPermissionAccessForUserBasedAuth()).thenReturn(true);
        authzUtilMockedStatic.when(() -> AuthzUtil.getInternalScopes(USER_RESIDENT_ORG_TENANT)).thenReturn(
                internalScopes);
        when(oAuth2ServiceComponentHolder.getLegacyScopesToNewScopesMap()).thenReturn(legacyMap);
        when(oAuth2ServiceComponentHolder.getLegacyMultipleScopesToNewScopesMap()).thenReturn(new HashMap<>());

        List<String> authorizedPermissions = AuthzUtil.getAuthorizedPermissions(authenticatedUser);
        Assert.assertTrue(authorizedPermissions.contains("new_scope1"));
    }

    @Test
    public void testGetAuthorizedPermissionsWithNoRoles() throws Exception {

        List<String> roleIds = new ArrayList<>();
        List<String> permissions = new ArrayList<>();

        when(authenticatedUser.getAccessingOrganization()).thenReturn(null);
        when(authenticatedUser.getTenantDomain()).thenReturn(USER_RESIDENT_ORG_TENANT);
        authzUtilMockedStatic.when(() -> AuthzUtil.getUserRoles(authenticatedUser, null)).thenReturn(roleIds);
        authzUtilMockedStatic.when(() -> AuthzUtil.getAssociatedScopesForRoles(roleIds, USER_RESIDENT_ORG_TENANT))
                .thenReturn(new java.util.ArrayList<>(permissions));
        when(oAuthServerConfiguration.isUseLegacyPermissionAccessForUserBasedAuth()).thenReturn(false);

        List<String> authorizedPermissions = AuthzUtil.getAuthorizedPermissions(authenticatedUser);
        Assert.assertTrue(authorizedPermissions.isEmpty());
    }

    @Test
    public void testGetSubOrgUserRoles_Success() throws Exception {

        List<String> sharedUserRoles = Arrays.asList("role1", "role2", "role3");
        Map<String, String> mainAppUserRolesMappings = new HashMap<>();
        mainAppUserRolesMappings.put("role1", "main-role1");
        mainAppUserRolesMappings.put("role2", "main-role2");
        mainAppUserRolesMappings.put("role3", "main-role3");

        when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(oAuth2ServiceComponentHolder.getRoleManagementServiceV2()).thenReturn(roleManagementService);

        when(organizationManager.resolveTenantDomain(ACCESSING_ORGANIZATION))
                .thenReturn(USER_RESIDENT_ORG_TENANT)
                .thenReturn(ACCESSING_ORG_TENANT);

        authzUtilMockedStatic.when(() -> AuthzUtil.getRoles(USER_ID, USER_RESIDENT_ORG_TENANT))
                .thenReturn(sharedUserRoles);

        when(roleManagementService.getSharedRoleToMainRoleMappingsBySubOrg(sharedUserRoles, ACCESSING_ORG_TENANT))
                .thenReturn(mainAppUserRolesMappings);

        List<String> result = AuthzUtil.getSubOrgUserRoles(USER_ID, ACCESSING_ORGANIZATION);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.size(), 3);
        Assert.assertTrue(result.contains("main-role1"));
        Assert.assertTrue(result.contains("main-role2"));
        Assert.assertTrue(result.contains("main-role3"));
    }

    @Test
    public void testGetSubOrgUserRoles_EmptySharedRoles() throws Exception {

        List<String> sharedUserRoles = new ArrayList<>();
        Map<String, String> mainAppUserRolesMappings = new HashMap<>();

        when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(oAuth2ServiceComponentHolder.getRoleManagementServiceV2()).thenReturn(roleManagementService);

        when(organizationManager.resolveTenantDomain(ACCESSING_ORGANIZATION))
                .thenReturn(USER_RESIDENT_ORG_TENANT)
                .thenReturn(ACCESSING_ORG_TENANT);

        authzUtilMockedStatic.when(() -> AuthzUtil.getRoles(USER_ID, USER_RESIDENT_ORG_TENANT))
                .thenReturn(sharedUserRoles);

        when(roleManagementService.getSharedRoleToMainRoleMappingsBySubOrg(sharedUserRoles, ACCESSING_ORG_TENANT))
                .thenReturn(mainAppUserRolesMappings);

        List<String> result = AuthzUtil.getSubOrgUserRoles(USER_ID, ACCESSING_ORGANIZATION);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.isEmpty());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Error occurred while getting mapped main app roles.")
    public void testGetSubOrgUserRoles_RoleManagementException() throws Exception {

        List<String> sharedUserRoles = Arrays.asList("role1", "role2");

        when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(oAuth2ServiceComponentHolder.getRoleManagementServiceV2()).thenReturn(roleManagementService);

        when(organizationManager.resolveTenantDomain(ACCESSING_ORGANIZATION))
                .thenReturn(USER_RESIDENT_ORG_TENANT)
                .thenReturn(ACCESSING_ORG_TENANT);

        authzUtilMockedStatic.when(() -> AuthzUtil.getRoles(USER_ID, USER_RESIDENT_ORG_TENANT))
                .thenReturn(sharedUserRoles);

        when(roleManagementService.getSharedRoleToMainRoleMappingsBySubOrg(anyList(), anyString()))
                .thenThrow(new IdentityRoleManagementException("Role management error"));

        AuthzUtil.getSubOrgUserRoles(USER_ID, ACCESSING_ORGANIZATION);
    }

    @Test
    public void testGetSubOrgUserRoles_WithNullUserId() throws Exception {

        List<String> sharedUserRoles = List.of();
        Map<String, String> mainAppUserRolesMappings = new HashMap<>();

        when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(oAuth2ServiceComponentHolder.getRoleManagementServiceV2()).thenReturn(roleManagementService);

        when(organizationManager.resolveTenantDomain(ACCESSING_ORGANIZATION))
                .thenReturn(USER_RESIDENT_ORG_TENANT)
                .thenReturn(ACCESSING_ORG_TENANT);

        authzUtilMockedStatic.when(() -> AuthzUtil.getRoles(null, USER_RESIDENT_ORG_TENANT))
                .thenReturn(sharedUserRoles);

        when(roleManagementService.getSharedRoleToMainRoleMappingsBySubOrg(sharedUserRoles, ACCESSING_ORG_TENANT))
                .thenReturn(mainAppUserRolesMappings);

        List<String> result = AuthzUtil.getSubOrgUserRoles(null, ACCESSING_ORGANIZATION);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.isEmpty());
    }

    @Test
    public void testGetSubOrgUserRoles_WithEmptyOrganization() throws Exception {

        List<String> sharedUserRoles = List.of();
        Map<String, String> mainAppUserRolesMappings = new HashMap<>();

        when(oAuth2ServiceComponentHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(oAuth2ServiceComponentHolder.getRoleManagementServiceV2()).thenReturn(roleManagementService);

        when(organizationManager.resolveTenantDomain(""))
                .thenReturn(USER_RESIDENT_ORG_TENANT)
                .thenReturn(ACCESSING_ORG_TENANT);

        authzUtilMockedStatic.when(() -> AuthzUtil.getRoles(USER_ID, USER_RESIDENT_ORG_TENANT))
                .thenReturn(sharedUserRoles);

        when(roleManagementService.getSharedRoleToMainRoleMappingsBySubOrg(sharedUserRoles, ACCESSING_ORG_TENANT))
                .thenReturn(mainAppUserRolesMappings);

        List<String> result = AuthzUtil.getSubOrgUserRoles(USER_ID, "");
        Assert.assertNotNull(result);
        Assert.assertTrue(result.isEmpty());
    }

    @Test
    public void testAgentGetUserIdOfAssociatedUser() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OrganizationSharedAgentUtil> sharedAgentUtil =
                     mockStatic(OrganizationSharedAgentUtil.class)) {

            when(authenticatedUser.isFederatedUser()).thenReturn(false);
            when(authenticatedUser.getUserId()).thenReturn(USER_ID);
            when(authenticatedUser.getUserStoreDomain()).thenReturn(AGENT);
            when(authenticatedUser.getAccessingOrganization()).thenReturn(ACCESSING_ORGANIZATION);
            identityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(AGENT);
            sharedAgentUtil.when(() -> OrganizationSharedAgentUtil
                    .getAgentIdOfAssociatedAgentByOrgId(USER_ID, ACCESSING_ORGANIZATION))
                    .thenReturn(Optional.of(SHARED_AGENT_ID));
            String result = AuthzUtil.getUserIdOfAssociatedUser(authenticatedUser);
            Assert.assertEquals(result, SHARED_AGENT_ID);
        }
    }

    @Test
    public void testGetUserIdOfAssociatedUserFallsBackToUserSharing() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OrganizationSharedUserUtil> sharedUserUtil =
                     mockStatic(OrganizationSharedUserUtil.class)) {

            when(authenticatedUser.isFederatedUser()).thenReturn(false);
            when(authenticatedUser.getUserId()).thenReturn(USER_ID);
            when(authenticatedUser.getUserStoreDomain()).thenReturn(PRIMARY);
            when(authenticatedUser.getAccessingOrganization()).thenReturn(ACCESSING_ORGANIZATION);
            identityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(AGENT);
            sharedUserUtil.when(() -> OrganizationSharedUserUtil
                    .getUserIdOfAssociatedUserByOrgId(USER_ID, ACCESSING_ORGANIZATION))
                    .thenReturn(Optional.of(SHARED_USER_ID));
            String result = AuthzUtil.getUserIdOfAssociatedUser(authenticatedUser);
            Assert.assertEquals(result, SHARED_USER_ID);
        }
    }
}
