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

package org.wso2.carbon.identity.oauth2.impersonation.validators;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.ImpersonatedUser;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Error.INVALID_REQUEST;

/**
 * Validator to validate impersonation requests for users from different resident organizations.
 * This validator checks if the impersonated user belongs to a different organization and updates the
 * impersonated user details accordingly.
 */
public class ResidentOrganizationValidator implements ImpersonationValidator {

    private static final String NAME = "ResidentOrganizationValidator";
    private static final Log LOG = LogFactory.getLog(ResidentOrganizationValidator.class);

    @Override
    public int getPriority() {

        return 300;
    }

    @Override
    public String getImpersonationValidatorName() {

        return NAME;
    }

    @Override
    public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext)
            throws IdentityOAuth2Exception {

        try {
            AuthenticatedUser impersonatingActor = impersonationContext.getImpersonationRequestDTO().getImpersonator();
            ImpersonatedUser impersonatedUser = impersonatingActor.getImpersonatedUser();
            String impersonatedUserResidentOrg = impersonatingActor.getUserResidentOrganization();
            String impersonatedUserId = impersonatedUser.getUserId();

            if (impersonatedUserResidentOrg != null) {
                UserAssociation association = getUserAssociation(impersonatedUserId, impersonatedUserResidentOrg);
                if (association != null) {
                    // User from a different org.
                    impersonatedUserResidentOrg = association.getUserResidentOrganizationId();
                    impersonatedUserId = association.getAssociatedUserId();
                    try {
                        if (OrganizationManagementUtil.isOrganization(impersonatedUserResidentOrg)) {
                            // Org is another sub org.
                            impersonatedUser.setUserResidentOrganization(impersonatedUserResidentOrg);
                        }
                    } catch (OrganizationManagementException e) {
                        throw new IdentityOAuth2ClientException(INVALID_REQUEST.getCode(),
                                "Invalid User Id provided for the request. Unable to find the user for given " +
                                        "user id : " + impersonatedUserId + " organization : "
                                        + impersonatedUserResidentOrg, e);
                    }
                } else {
                    // User from the same sub org.
                    impersonatedUser.setUserResidentOrganization(impersonatedUserResidentOrg);
                }
            } else {
                // User from parent org.
                impersonatedUser.setUserResidentOrganization(null);
                impersonatedUser.setUserId(impersonatedUserId);
            }
            impersonationContext.getImpersonationRequestDTO().getImpersonator()
                    .setImpersonatedUser(impersonatedUser);
            impersonationContext.setValidated(true);
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("Error while retrieving impersonated user information for user.", e);
        }

        return impersonationContext;
    }

    private static UserAssociation getUserAssociation(String userId, String userResidentOrg)
            throws IdentityOAuth2Exception {

        try {
            return OAuthComponentServiceHolder.getInstance()
                    .getOrganizationUserSharingService().getUserAssociation(userId, userResidentOrg);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving user association for user: " + userId, e);
        }
    }
}
