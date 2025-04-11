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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;

import java.util.List;

/**
 * The {@code SubjectScopeValidator} class implements the {@link ImpersonationValidator} interface
 * to validate impersonation requests based on subject scopes.
 * It checks the authorization scopes associated with the impersonation request to determine if the request is valid.
 */
public class SubjectScopeValidator implements ImpersonationValidator {

    private static final String NAME = "SubjectScopeValidator";
    private static final Log LOG = LogFactory.getLog(SubjectScopeValidator.class);
    private DefaultOAuth2ScopeValidator scopeValidator;

    public SubjectScopeValidator() {

        this.scopeValidator = new DefaultOAuth2ScopeValidator();
    }


    @Override
    public int getPriority() {

        return 80;
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

        String subjectUserId = impersonationRequestDTO.getSubject();
        AuthenticatedUser impersonator = impersonationRequestDTO.getImpersonator();

        authzReqMessageContext.getAuthorizationReqDTO().setScopes(authzReqMessageContext.getRequestedScopes());

        // Switching end-user as authenticated user to validate scopes.
        AuthenticatedUser subjectUser = OAuth2Util.getImpersonatingUser(subjectUserId, impersonator,
                impersonationRequestDTO.getClientId());
        authzReqMessageContext.getAuthorizationReqDTO().setUser(subjectUser);
        List<String> authorizedScopes = scopeValidator.validateScope(authzReqMessageContext);
        authzReqMessageContext.setApprovedScope(authorizedScopes.toArray(new String[0]));
        // Switching impersonator as authenticated user back.
        authzReqMessageContext.getAuthorizationReqDTO().setUser(impersonator);

        impersonationContext.setValidated(true);
        return impersonationContext;
    }
}
