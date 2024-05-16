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


import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.OAUTH_2;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.INTERNAL_LOGIN_SCOPE;

/**
 * The {@code SubjectScopeValidator} class implements the {@link ImpersonationValidator} interface
 * to validate impersonation requests based on subject scopes.
 * It checks the authorization scopes associated with the impersonation request to determine if the request is valid.
 */
public class SubjectScopeValidator implements ImpersonationValidator {

    private static final String NAME = "SubjectScopeValidator";
    private DefaultOAuth2ScopeValidator scopeValidator;

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

        List<String> requestedScopes = Arrays.asList(authzReqMessageContext.getRequestedScopes());
        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String appId = getApplicationId(clientId, tenantDomain);
        String subjectUserId = authzReqMessageContext.getAuthorizationReqDTO().getRequestedSubjectId();

        AuthenticatedUser subjectUser = getAuthenticatedSubjectUser(subjectUserId, tenantDomain);

        List<String> authorizedScopes = scopeValidator.getAuthorizedScopes(requestedScopes, subjectUser, appId,
                null, null, tenantDomain);
        handleInternalLoginScope(requestedScopes, authorizedScopes);
        authzReqMessageContext.setApprovedScope(authorizedScopes.toArray(new String[0]));
        impersonationContext.setValidated(true);
        return impersonationContext;
    }

    private AuthenticatedUser getAuthenticatedSubjectUser(String subjectUserId, String tenantDomain)
            throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;

        String username;
        try {
            username = OAuth2Util.resolveUsernameFromUserId(tenantDomain, subjectUserId);
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Use mapped local subject is mandatory but a local user couldn't be found");
        }
        String userStore = OAuth2Util.getUserStoreDomainFromUserId(subjectUserId);

        authenticatedUser = OAuth2Util.createAuthenticatedUser(username, userStore, tenantDomain, null);
        authenticatedUser.setAuthenticatedSubjectIdentifier(subjectUserId);
        return authenticatedUser;
    }

    /**
     * Get the application resource id for the given client id
     *
     * @param clientId   Client Id.
     * @param tenantName Tenant name.
     * @return Application resource id.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving application resource id.
     */
    private String getApplicationId(String clientId, String tenantName) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            return applicationMgtService.getApplicationResourceIDByInboundKey(clientId, OAUTH_2, tenantName);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving application resource id for client : " +
                    clientId + " tenant : " + tenantName, e);
        }
    }

    /**
     * This is to persist the previous behaviour with the "internal_login" scope.
     *
     * @param requestedScopes requested scopes.
     * @param authorizedScopes authorized scopes.
     */
    private void handleInternalLoginScope(List<String> requestedScopes, List<String> authorizedScopes) {

        if ((requestedScopes.contains(SYSTEM_SCOPE) || requestedScopes.contains(INTERNAL_LOGIN_SCOPE))
                && !authorizedScopes.contains(INTERNAL_LOGIN_SCOPE)) {
            authorizedScopes.add(INTERNAL_LOGIN_SCOPE);
        }
    }
}
