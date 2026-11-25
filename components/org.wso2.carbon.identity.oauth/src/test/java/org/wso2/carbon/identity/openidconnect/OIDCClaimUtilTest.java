/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.logging.Log;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.ApplicationRolesResolver;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.exception.ApplicationRolesException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.util.OrganizationSharedUserUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for OIDCClaimUtil class.
 */
public class OIDCClaimUtilTest {

    @Test
    public void testGetAppAssociatedRolesOfUser() throws ApplicationRolesException {

        try (MockedStatic<OpenIDConnectServiceComponentHolder> openIDConnectServiceComponentHolder =
                     mockStatic(OpenIDConnectServiceComponentHolder.class);) {
            AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
            String applicationId = "testAppId";

            ApplicationRolesResolver appRolesResolver = mock(ApplicationRolesResolver.class);
            Mockito.when(appRolesResolver.getRoles(authenticatedUser, applicationId))
                    .thenReturn(new String[]{"role1", "role2"});

            OpenIDConnectServiceComponentHolder mockOpenIDConnectServiceComponentHolder =
                    mock(OpenIDConnectServiceComponentHolder.class);
            openIDConnectServiceComponentHolder.when(OpenIDConnectServiceComponentHolder::getInstance)
                    .thenReturn(mockOpenIDConnectServiceComponentHolder);
            when(mockOpenIDConnectServiceComponentHolder.getHighestPriorityApplicationRolesResolver())
                    .thenReturn(appRolesResolver);

            String[] roles = OIDCClaimUtil.getAppAssociatedRolesOfUser(authenticatedUser, applicationId);

            assertNotNull(roles);
            assertEquals(roles.length, 2);
            assertTrue(roles[0].equals("role1") && roles[1].equals("role2"));
        }
    }

    @Test
    public void testLogClaimRetrievalErrorDoesNotLeakUsername() {

        String username = "john.doe@example.com";
        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.toString()).thenReturn(username);
        UserStoreException exception = new UserStoreException(
                "30007 - UserNotFound: User " + username + " does not exist in: PRIMARY");
        Log logger = mock(Log.class);

        try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class)) {
            loggerUtils.when(() -> LoggerUtils.getMaskedContent(username)).thenReturn("j***m");
            LoggerUtils.isLogMaskingEnable = true;
            OIDCClaimUtil.logClaimRetrievalError(logger, user, exception);
        }

        ArgumentCaptor<Object> message = ArgumentCaptor.forClass(Object.class);
        verify(logger).error(message.capture());
        verify(logger, never()).error(any(), any(Throwable.class));
        assertFalse(message.getValue().toString().contains(username));
        assertTrue(message.getValue().toString().contains("UserStoreException"));
    }

    private static final String SEPARATOR = ",";

    private static LocalClaim multiValuedLocalClaim(boolean multiValued) {

        LocalClaim localClaim = new LocalClaim("http://wso2.org/claims/testClaim");
        localClaim.setClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY, String.valueOf(multiValued));
        return localClaim;
    }

    @DataProvider(name = "isMultiValuedAttributeData")
    public Object[][] isMultiValuedAttributeData() {

        return new Object[][]{
                // Address is never rendered as an array, even when the value contains the separator
                // or the local claim metadata marks it as multivalued.
                {OAuthConstants.OIDCClaims.ADDRESS, "no 1,street", multiValuedLocalClaim(true), false},
                {OAuthConstants.OIDCClaims.ADDRESS, "no 1,street", null, false},
                // Groups is always rendered as an array, even for a single value or without metadata.
                {OAuthConstants.OIDCClaims.GROUPS, "admin", null, true},
                {OAuthConstants.OIDCClaims.GROUPS, "admin", multiValuedLocalClaim(false), true},
                // When metadata is present, the local claim multiValued property decides.
                {"email", "a@b.com", multiValuedLocalClaim(true), true},
                {"email", "a@b.com,c@d.com", multiValuedLocalClaim(false), false},
                // When metadata is absent, fall back to separator-based detection.
                {"email", "a@b.com,c@d.com", null, true},
                {"email", "a@b.com", null, false},
        };
    }

    @Test(dataProvider = "isMultiValuedAttributeData")
    public void testIsMultiValuedAttribute(String claimKey, String claimValue, LocalClaim localClaim,
                                           boolean expected) {

        assertEquals(OIDCClaimUtil.isMultiValuedAttribute(claimKey, claimValue, SEPARATOR, localClaim), expected);
    }

    private static final String ROOT_TENANT_DOMAIN = "carbon.super";
    private static final String SUB_ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String SUB_ORG_TENANT_DOMAIN = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String SUB_ORG_USER_ID = "3f2b7c1e-5a4d-4e8f-9b6a-2c1d0e9f8a7b";
    private static final String SUB_ORG_USERNAME = "orguser";
    private static final String APP_ID = "app-resource-id";
    private static final String ROLES_CLAIM_URI = "http://wso2.org/claims/roles";

    @DataProvider(name = "organizationSsoUserRoleResolutionData")
    public Object[][] organizationSsoUserRoleResolutionData() {

        return new Object[][]{
                // Organization SSO user without a shared user: roles are resolved for the local user of the
                // resident organization.
                {null, true},
                // Organization SSO user switching to a shared organization: the resolver handles the shared
                // user, so the authenticated user is passed through unchanged.
                {"shared-user-id", false}
        };
    }

    @Test(dataProvider = "organizationSsoUserRoleResolutionData")
    public void testRolesOfOrganizationSsoUserResolvedInResidentOrganization(String sharedUserId,
                                                                            boolean expectResidentOrgUser)
            throws Exception {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(SUB_ORG_USER_ID);
        authenticatedUser.setUserId(SUB_ORG_USER_ID);
        authenticatedUser.setTenantDomain(ROOT_TENANT_DOMAIN);
        authenticatedUser.setFederatedUser(true);
        authenticatedUser.setFederatedIdPName("SSO");
        authenticatedUser.setUserResidentOrganization(SUB_ORG_ID);
        authenticatedUser.setSharedUserId(sharedUserId);

        ServiceProvider serviceProvider = mock(ServiceProvider.class);
        when(serviceProvider.getApplicationResourceId()).thenReturn(APP_ID);
        when(serviceProvider.getTenantDomain()).thenReturn(ROOT_TENANT_DOMAIN);

        Boolean previousLegacyAuthzRuntime = CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME;
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;
        try (MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<OpenIDConnectServiceComponentHolder> openIDConnectServiceComponentHolder =
                     mockStatic(OpenIDConnectServiceComponentHolder.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OrganizationSharedUserUtil> organizationSharedUserUtil =
                     mockStatic(OrganizationSharedUserUtil.class)) {

            OAuthComponentServiceHolder serviceHolder = mock(OAuthComponentServiceHolder.class, RETURNS_DEEP_STUBS);
            oAuthComponentServiceHolder.when(OAuthComponentServiceHolder::getInstance).thenReturn(serviceHolder);
            when(serviceHolder.getOrganizationManager().resolveTenantDomain(SUB_ORG_ID))
                    .thenReturn(SUB_ORG_TENANT_DOMAIN);
            AbstractUserStoreManager residentOrgUserStoreManager = mock(AbstractUserStoreManager.class);
            when(serviceHolder.getRealmService().getTenantUserRealm(anyInt()).getUserStoreManager())
                    .thenReturn(residentOrgUserStoreManager);
            User residentOrgUser = mock(User.class);
            when(residentOrgUser.getFullQualifiedUsername()).thenReturn("PRIMARY/" + SUB_ORG_USERNAME);
            when(residentOrgUserStoreManager.getUser(eq(SUB_ORG_USER_ID), isNull())).thenReturn(residentOrgUser);

            UserRealm userRealm = mock(UserRealm.class);
            UserStoreManager userStoreManager = mock(UserStoreManager.class);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
            when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), isNull()))
                    .thenReturn(Collections.emptyMap());
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
            identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), anyString())).thenReturn(userRealm);
            identityUtil.when(IdentityUtil::getLocalGroupsClaimURI).thenReturn(ROLES_CLAIM_URI);
            organizationSharedUserUtil.when(OrganizationSharedUserUtil::isSharedUserProfileResolverEnabled)
                    .thenReturn(false);

            ApplicationRolesResolver appRolesResolver = mock(ApplicationRolesResolver.class);
            OpenIDConnectServiceComponentHolder oidcServiceHolder = mock(OpenIDConnectServiceComponentHolder.class);
            openIDConnectServiceComponentHolder.when(OpenIDConnectServiceComponentHolder::getInstance)
                    .thenReturn(oidcServiceHolder);
            when(oidcServiceHolder.getHighestPriorityApplicationRolesResolver()).thenReturn(appRolesResolver);
            when(appRolesResolver.getAppAssociatedRolesOfLocalUser(any(), anyString(), anyString()))
                    .thenReturn(new String[0]);

            List<String> claimURIs = new ArrayList<>(Collections.singletonList(ROLES_CLAIM_URI));
            OIDCClaimUtil.getUserClaimsInOIDCDialect(serviceProvider, authenticatedUser, claimURIs);

            ArgumentCaptor<AuthenticatedUser> userCaptor = ArgumentCaptor.forClass(AuthenticatedUser.class);
            verify(appRolesResolver).getAppAssociatedRolesOfLocalUser(userCaptor.capture(), eq(APP_ID),
                    eq(ROOT_TENANT_DOMAIN));
            AuthenticatedUser userForRoleResolution = userCaptor.getValue();
            if (expectResidentOrgUser) {
                assertFalse(userForRoleResolution.isFederatedUser());
                assertEquals(userForRoleResolution.getUserId(), SUB_ORG_USER_ID);
                assertEquals(userForRoleResolution.getUserName(), SUB_ORG_USERNAME);
                assertEquals(userForRoleResolution.getUserStoreDomain(), "PRIMARY");
                assertEquals(userForRoleResolution.getTenantDomain(), SUB_ORG_TENANT_DOMAIN);
            } else {
                assertSame(userForRoleResolution, authenticatedUser);
            }
        } finally {
            CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = previousLegacyAuthzRuntime;
        }
    }
}
