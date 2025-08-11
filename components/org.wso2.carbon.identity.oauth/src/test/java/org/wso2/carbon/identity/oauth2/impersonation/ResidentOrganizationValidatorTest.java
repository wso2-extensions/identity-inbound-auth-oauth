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

package org.wso2.carbon.identity.oauth2.impersonation;

import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.ImpersonatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.validators.ResidentOrganizationValidator;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class ResidentOrganizationValidatorTest {

    @DataProvider(name = "validateImpersonationDataProvider")
    public Object[][] validateImpersonationDataProvider() {

        return new Object[][]{
                // Parent org impersonation.
                {
                        "parentOrgUserId", null, null, null, null, false, false, true
                },
                // Sub org impersonation - Same Sub org user.
                {
                        "subOrgUserId", "subOrg1", null, null, null, true, true, true
                },
                // Sub org impersonation - Different Sub org user.
                {
                        "subOrgUserId", "subOrg1", "subOrgUserId", "subOrg2", "subOrg2", true, false, false
                },
                // Sub org impersonation - Parent org user.
                {
                        "subOrgUserId", "subOrg1", "subOrgUserId", "subOrg1", "parentOrg", false, false, false
                },
        };
    }

    @Test(dataProvider = "validateImpersonationDataProvider")
    public void testValidateImpersonation(String userId, String userResidentOrg, String associatedUserId,
                                          String associatedUserResidentOrg, String associatedOrganizationId,
                                          boolean isSubOrg, boolean isFromSameSubOrg, boolean isValid)
            throws IdentityException, OrganizationManagementException {

        try (MockedStatic<OrganizationManagementUtil> organizationManagementUtilMockedStatic =
                     mockStatic(OrganizationManagementUtil.class)) {
            organizationManagementUtilMockedStatic.when(() -> OrganizationManagementUtil.isOrganization(
                    associatedOrganizationId)).thenReturn(isSubOrg);

            ResidentOrganizationValidator residentOrganizationValidator = new ResidentOrganizationValidator();

            ImpersonationContext impersonationContext = getImpersonationContext(userId, userResidentOrg);

            UserAssociation userAssociation = new UserAssociation();
            if (isFromSameSubOrg) {
                userAssociation = null;
            } else {
                userAssociation.setAssociatedUserId(associatedUserId);
                userAssociation.setUserResidentOrganizationId(associatedUserResidentOrg);
                userAssociation.setOrganizationId(associatedOrganizationId);
            }

            OrganizationUserSharingService mockOrganizationUserSharingService =
                    mock(OrganizationUserSharingService.class);
            OAuthComponentServiceHolder.getInstance()
                    .setOrganizationUserSharingService(mockOrganizationUserSharingService);
            when(mockOrganizationUserSharingService.getUserAssociation(userId, userResidentOrg)).thenReturn(
                    userAssociation);

            impersonationContext = residentOrganizationValidator.validateImpersonation(impersonationContext);
            assertEquals(impersonationContext.isValidated(), isValid, "Impersonation invalid");
        }
    }

    private static ImpersonationContext getImpersonationContext(String userId, String userResidentOrg) {

        ImpersonatedUser impersonatedUser = new ImpersonatedUser();
        impersonatedUser.setUserId(userId);
        impersonatedUser.setUserResidentOrganization(userResidentOrg);

        AuthenticatedUser impersonator = new AuthenticatedUser();
        impersonator.setImpersonatedUser(impersonatedUser);
        impersonator.setUserResidentOrganization(userResidentOrg);

        ImpersonationRequestDTO impersonationRequestDTO = new ImpersonationRequestDTO();
        impersonationRequestDTO.setImpersonator(impersonator);

        ImpersonationContext impersonationContext = new ImpersonationContext();
        impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);

        return impersonationContext;
    }
}
