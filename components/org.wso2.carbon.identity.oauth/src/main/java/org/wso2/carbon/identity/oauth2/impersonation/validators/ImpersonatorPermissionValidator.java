/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.validators;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;

import java.util.List;

import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_SCOPE_NAME;

/**
 * The ImpersonatorPermissionValidator class is responsible for validating whether an authenticated user
 * has the necessary impersonation permissions within a given tenant and for a specified client.
 * The validation process involves checking if the authenticated user has the "internal_user_impersonate"
 * in their authorized scopes. If the scope is present, the impersonation context is marked as validated.
 */
public class ImpersonatorPermissionValidator implements ImpersonationValidator {

    private static final String NAME = "ImpersonatorPermissionValidator";
    private static final Log LOG = LogFactory.getLog(ImpersonatorPermissionValidator.class);
    private DefaultOAuth2ScopeValidator scopeValidator;

    public ImpersonatorPermissionValidator() {

        this.scopeValidator = new DefaultOAuth2ScopeValidator();
    }

    @Override
    public int getPriority() {

        return 100;
    }

    @Override
    public String getImpersonationValidatorName() {

        return NAME;
    }

    @Override
    public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext)
            throws IdentityOAuth2Exception {

        ImpersonationRequestDTO impersonationRequestDTO = impersonationContext.getImpersonationRequestDTO();
        OAuthAuthzReqMessageContext authzReqMessageContext = impersonationRequestDTO.getoAuthAuthzReqMessageContext();

        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        authzReqMessageContext.getAuthorizationReqDTO().setScopes(authzReqMessageContext.getRequestedScopes());
        List<String> authorizedScopes = scopeValidator.validateScope(authzReqMessageContext);
        if (authorizedScopes.contains(IMPERSONATION_SCOPE_NAME)) {
            impersonationContext.setValidated(true);
        } else {
            impersonationContext.setValidated(false);
            impersonationContext.setValidationFailureErrorMessage("Authenticated user : " + authzReqMessageContext
                    .getAuthorizationReqDTO().getUser().getLoggableMaskedUserId() + " doesn't have impersonation " +
                    "permission for client : " + clientId +  " in the tenant : " + tenantDomain);
            LOG.error("Authenticated user : " + authzReqMessageContext
                    .getAuthorizationReqDTO().getUser().getLoggableMaskedUserId() + "doesn't have impersonation " +
                    "permission for client : " + clientId +  " in the tenant : " + tenantDomain);
        }
        return impersonationContext;
    }
}
