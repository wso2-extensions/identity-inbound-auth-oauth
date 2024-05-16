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

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;

import java.util.List;

/**
 * The {@code SubjectScopeValidator} class implements the {@link ImpersonationValidator} interface
 * to validate impersonation requests based on subject scopes.
 * It checks the authorization scopes associated with the impersonation request to determine if the request is valid.
 */
public class SubjectScopeValidator implements ImpersonationValidator {

    /**
     * The name of the subject scope validator.
     */
    private static final String NAME = "SubjectScopeValidator";

    /**
     * The scope validator used to validate authorization scopes.
     */
    private final DefaultOAuth2ScopeValidator scopeValidator;

    /**
     * Constructs a new instance of the {@code SubjectScopeValidator} class.
     */
    public SubjectScopeValidator() {

        this.scopeValidator = new DefaultOAuth2ScopeValidator();
    }

    /**
     * Gets the priority of the subject scope validator.
     *
     * @return the priority of the subject scope validator
     */
    @Override
    public int getPriority() {

        return 100;
    }

    /**
     * Gets the name of the subject scope validator.
     *
     * @return the name of the subject scope validator
     */
    @Override
    public String getImpersonationValidatorName() {

        return NAME;
    }

    /**
     * Validates an impersonation request based on the provided impersonation context and request DTO.
     * It checks the scopes associated with the impersonation request to determine if the request is valid.
     *
     * @param impersonationContext    the impersonation context containing information about the validation process
     * @param impersonationRequestDTO the impersonation request DTO containing information about the request
     * @return an {@code ImpersonationContext} object representing the validation context,
     *         including validation status and any validation failure details
     * @throws IdentityOAuth2Exception if an error occurs during impersonation request validation
     */
    @Override
    public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext,
                                                      ImpersonationRequestDTO impersonationRequestDTO)
            throws IdentityOAuth2Exception {

        OAuthAuthzReqMessageContext authzReqMessageContext = impersonationRequestDTO.getoAuthAuthzReqMessageContext();

        List<String> authorizedScopes = scopeValidator.validateScope(authzReqMessageContext);
        authzReqMessageContext.setApprovedScope(authorizedScopes.toArray(new String[0]));
        impersonationContext.setValidated(true);
        return impersonationContext;
    }
}
