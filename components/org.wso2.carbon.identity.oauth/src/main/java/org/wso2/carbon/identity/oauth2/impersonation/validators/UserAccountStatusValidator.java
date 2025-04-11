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
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountDisableServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_CHECKING_ACCOUNT_DISABLE_STATUS;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS;

/**
 * The {@code UserAccountStatusValidator} class is responsible for validating the status of a user account
 * during the impersonation process. It implements the {@code ImpersonationValidator} interface.
 * <p>
 */
public class UserAccountStatusValidator implements ImpersonationValidator {

    private static final String NAME = "UserAccountStatusValidator";
    private static final Log LOG = LogFactory.getLog(UserAccountStatusValidator.class);

    @Override
    public int getPriority() {

        return 200;
    }

    @Override
    public String getImpersonationValidatorName() {

        return NAME;
    }

    @Override
    public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext)
            throws IdentityOAuth2Exception {

        String subjectUserId = impersonationContext.getImpersonationRequestDTO().getSubject();
        AuthenticatedUser subjectUser = OAuth2Util.getImpersonatingUser(subjectUserId,
                impersonationContext.getImpersonationRequestDTO().getImpersonator(),
                impersonationContext.getImpersonationRequestDTO().getClientId());
        String subjectUserName = subjectUser.getUserName();
        String tenantDomain = impersonationContext.getImpersonationRequestDTO().getTenantDomain();
        String domainName = subjectUser.getUserStoreDomain();

        if (isUserAccountLocked(subjectUserName, tenantDomain)
                || isUserAccountDisabled(subjectUserName, tenantDomain, domainName)) {
            impersonationContext.setValidated(false);
            LOG.error("Cannot impersonate user account.");
        } else {
            impersonationContext.setValidated(true);
            LOG.debug("User account is not locked or disabled. Impersonation is allowed.");
        }
        return impersonationContext;
    }

    private boolean isUserAccountLocked(String username, String tenantDomain)
            throws IdentityOAuth2Exception {

        if (username != null && tenantDomain != null) {
            try {
                return OAuth2ServiceComponentHolder.getAccountLockService().isAccountLocked(username, tenantDomain);
            } catch (AccountLockServiceException e) {
                throw new IdentityOAuth2Exception(ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS.getCode(),
                        String.format(ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS.getMessage(), username), e);
            }
        }
        return true;
    }

    private boolean isUserAccountDisabled(String username, String tenantDomain, String userDomain)
            throws IdentityOAuth2Exception {

        if (username != null && tenantDomain != null && userDomain != null) {
            try {
                if (!isAccountDisablingEnabled(tenantDomain)) {
                    return false;
                }
                return OAuth2ServiceComponentHolder.getAccountDisableService().isAccountDisabled(
                        username, tenantDomain, userDomain);
            } catch (IllegalArgumentException | AccountDisableServiceException | FrameworkException e) {
                throw new IdentityOAuth2Exception(ERROR_WHILE_CHECKING_ACCOUNT_DISABLE_STATUS.getCode(),
                        String.format(ERROR_WHILE_CHECKING_ACCOUNT_DISABLE_STATUS.getMessage(), username), e);
            }
        }
        return true;
    }

    private boolean isAccountDisablingEnabled(String tenantDomain) throws FrameworkException {

        Property accountDisableConfigProperty = FrameworkUtils.getResidentIdpConfiguration(
                ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY, tenantDomain);

        return accountDisableConfigProperty != null && Boolean.parseBoolean(accountDisableConfigProperty.getValue());
    }
}
