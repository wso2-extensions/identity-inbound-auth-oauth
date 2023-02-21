/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth2.util;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalRole;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.wso2.carbon.identity.oauth2.util.ClaimsUtil.getUpdatedRoleClaimValue;

@PrepareForTest({FrameworkUtils.class, OAuthServerConfiguration.class})
public class ClaimsUtilTest extends PowerMockIdentityBaseTest {

    @Mock
    OAuthServerConfiguration oAuthServerConfigurationMock;

    @Mock
    IdentityProvider residentIdpMock;

    @Mock
    IdentityProvider roleMappingNotConfiguredIdpMock;

    @Mock
    IdentityProvider roleMappingConfiguredIdpMock;

    @Mock
    PermissionsAndRoleConfig permissionsAndRoleConfigMock;

    private static final String unmappedRemoteRolesWithAMatchingRole = "remoteRole,remoteRole1,remoteRole2";
    private static final String unmappedRemoteRolesWithoutAMatchingRole = "remoteRole1,remoteRole2,remoteRole3";
    private static final String mappedLocalRoleWithUnmappedRemoteRoles = "localRole,remoteRole1,remoteRole2";
    private static final String mappedLocalRoleOnly = "localRole";
    private static final String MULTI_ATTRIBUTE_SEPARATOR = ",";
    private final LocalRole localRole = new LocalRole("1", "localRole");
    private final RoleMapping roleMapping = new RoleMapping(localRole, "remoteRole");

    @BeforeMethod
    public void setUp() {

        Mockito.when(residentIdpMock.getIdentityProviderName())
                .thenReturn(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);

        Mockito.when(permissionsAndRoleConfigMock.getRoleMappings()).thenReturn(new RoleMapping[]{roleMapping});
        Mockito.when(roleMappingConfiguredIdpMock.getPermissionAndRoleConfig())
                .thenReturn(permissionsAndRoleConfigMock);
        Mockito.when(roleMappingNotConfiguredIdpMock.getPermissionAndRoleConfig()).thenReturn(null);

        PowerMockito.mockStatic(FrameworkUtils.class);
        Mockito.when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(MULTI_ATTRIBUTE_SEPARATOR);

        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        Mockito.when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfigurationMock);
    }

    @AfterMethod
    public void tearDown() {

    }

    @Test
    public void testGetUpdatedRoleClaimValueWithResidentIdP() {

        // When identity provider is resident IdP
        String updatedRoleClaimValue = getUpdatedRoleClaimValue(residentIdpMock, unmappedRemoteRolesWithAMatchingRole);
        Assert.assertEquals(updatedRoleClaimValue, unmappedRemoteRolesWithAMatchingRole, "Roles should not be mapped " +
                "for the resident identity provider");

    }

    @Test
    public void testGetUpdatedRoleClaimValueWithoutConfiguringIdPRoleMapping() {

        // When role mappings has not been configured in the IdP
        String updatedRoleClaimValue = getUpdatedRoleClaimValue(roleMappingNotConfiguredIdpMock,
                unmappedRemoteRolesWithAMatchingRole);
        Assert.assertEquals(updatedRoleClaimValue, unmappedRemoteRolesWithAMatchingRole, "Roles should not be mapped "
                + "when role mapping is not configured in the identity provider");

    }

    @Test(dataProvider = "getUpdatedRoleClaimValueWithIdPRoleMappingConfiguredTestDataProvider")
    public void testGetUpdatedRoleClaimValueWithIdPRoleMappingConfigured(boolean isReturnOnlyMappedLocalRoles,
                                     String currentRoleClaimValue, String expectedRoleClaimValue, String errorMessage) {

        // Mocks the ReturnOnlyMappedLocalRoles configuration
        Mockito.when(oAuthServerConfigurationMock.isReturnOnlyMappedLocalRoles())
               .thenReturn(isReturnOnlyMappedLocalRoles);

        String updatedRoleClaimValue = getUpdatedRoleClaimValue(roleMappingConfiguredIdpMock, currentRoleClaimValue);
        Assert.assertEquals(updatedRoleClaimValue, expectedRoleClaimValue, errorMessage);

    }

    @DataProvider(name = "getUpdatedRoleClaimValueWithIdPRoleMappingConfiguredTestDataProvider")
    public Object[][] getUpdatedRoleClaimValueWithIdPRoleMappingConfiguredTestDataProvider() {
        // When role mappings configured in IdP:
        return new Object[][]{
                // ReturnOnlyMappedLocalRoles = false and matching roles are present in the role mapping
                {false, unmappedRemoteRolesWithAMatchingRole, mappedLocalRoleWithUnmappedRemoteRoles, "Updated role " +
                        "claim value should contain unmapped remote roles along with the mapped local role"},
                // ReturnOnlyMappedLocalRoles = false and matching roles are absent in the role mapping
                {false, unmappedRemoteRolesWithoutAMatchingRole, unmappedRemoteRolesWithoutAMatchingRole, "Updated " +
                        "role claim value should only contain the unmapped remote roles"},
                // ReturnOnlyMappedLocalRoles = true and matching roles are present in the role mapping
                {true, unmappedRemoteRolesWithAMatchingRole, mappedLocalRoleOnly, "Updated role claim should only " +
                        "contain the mapped local role"},
                // ReturnOnlyMappedLocalRoles = true and matching roles are absent in the role mapping
                {true, unmappedRemoteRolesWithoutAMatchingRole, null, "Updated role claim value should not contain " +
                        "any roles"}
        };
    }

}
