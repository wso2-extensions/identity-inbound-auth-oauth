/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.rar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.common.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProvider;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProviderFactory;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;
import org.wso2.carbon.identity.oauth2.rar.model.ValidationResult;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * {@code AuthorizationDetailsValidator} class responsible for managing and validating authorization details.
 */
public class AuthorizationDetailsValidator {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsValidator.class);
    private final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory;

    public AuthorizationDetailsValidator() {

        this(AuthorizationDetailsProviderFactory.getInstance());
    }

    public AuthorizationDetailsValidator(AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory) {

        this.authorizationDetailsProviderFactory = authorizationDetailsProviderFactory;
    }

    /**
     * Retrieves and validates the authorization details for a given OAuth2 parameters context.
     *
     * @param oAuth2Parameters  The OAuth2 parameters associated with the request.
     * @param oAuthAppDO        The OAuth application details.
     * @param authenticatedUser The authenticated user information.
     * @return An {@link AuthorizationDetails} object containing the validated authorization details.
     */
    public AuthorizationDetails getValidatedAuthorizationDetails(
            final OAuth2Parameters oAuth2Parameters, final OAuthAppDO oAuthAppDO,
            final AuthenticatedUser authenticatedUser) throws AuthorizationDetailsProcessingException {

        final Set<AuthorizationDetail> validatedAuthorizationDetails = new HashSet<>();
        final Set<String> authorizedAuthorizationDetailsTypes = this.getAuthorizedAuthorizationDetailsTypes(
                oAuth2Parameters.getClientId(), oAuth2Parameters.getTenantDomain());
        for (AuthorizationDetail authorizationDetail : oAuth2Parameters.getAuthorizationDetails().getDetails()) {

            if (!isSupportedAuthorizationDetailType(authorizationDetail.getType())) {
                throw new AuthorizationDetailsProcessingException(String.format(AuthorizationDetailsConstants
                        .TYPE_NOT_SUPPORTED_ERR_MSG_FORMAT, authorizationDetail.getType()));
            }

            if (isAuthorizedAuthorizationDetail(authorizationDetail, authorizedAuthorizationDetailsTypes)) {

                final AuthorizationDetailsContext authorizationDetailsContext = new AuthorizationDetailsContext(
                        oAuth2Parameters, oAuthAppDO, authenticatedUser, authorizationDetail);

                if (isValidAuthorizationDetail(authorizationDetailsContext)) {
                    validatedAuthorizationDetails.add(getEnrichedAuthorizationDetail(authorizationDetailsContext));
                }
            }
        }

        return new AuthorizationDetails(validatedAuthorizationDetails);
    }

    private boolean isAuthorizedAuthorizationDetail(final AuthorizationDetail authorizationDetail,
                                                    final Set<String> authorizedAuthorizationDetailsTypes) {

        return authorizedAuthorizationDetailsTypes.contains(authorizationDetail.getType());
    }

    private boolean isSupportedAuthorizationDetailType(final String authorizationDetailType) {

        return this.authorizationDetailsProviderFactory
                .isSupportedAuthorizationDetailsType(authorizationDetailType);
    }

    /**
     * Checks if the provided authorization details context is valid.
     *
     * @param authorizationDetailsContext The context containing authorization details.
     * @return {@code true} if the authorization details are valid; {@code false} otherwise.
     */
    private boolean isValidAuthorizationDetail(final AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException {

        Optional<AuthorizationDetailsProvider> optionalProvider = this.authorizationDetailsProviderFactory
                .getProviderByType(authorizationDetailsContext.getAuthorizationDetail().getType());

        if (optionalProvider.isPresent()) {

            final ValidationResult validationResult = optionalProvider.get().validate(authorizationDetailsContext);
            if (log.isDebugEnabled() && validationResult.isInvalid()) {

                log.debug(String.format("Authorization details validation failed for type %s. Caused by, %s",
                        authorizationDetailsContext.getAuthorizationDetail().getType(), validationResult.getReason()));

            }
            return validationResult.isValid();
        }
        throw new AuthorizationDetailsProcessingException(String.format(
                AuthorizationDetailsConstants.TYPE_NOT_SUPPORTED_ERR_MSG_FORMAT,
                authorizationDetailsContext.getAuthorizationDetail().getType()));
    }

    /**
     * Enriches the authorization details using the provided context.
     *
     * @param authorizationDetailsContext The context containing authorization details.
     * @return An enriched {@link AuthorizationDetail} object.
     */
    private AuthorizationDetail getEnrichedAuthorizationDetail(
            final AuthorizationDetailsContext authorizationDetailsContext) {

        return this.authorizationDetailsProviderFactory
                .getProviderByType(authorizationDetailsContext.getAuthorizationDetail().getType())
                .map(authorizationDetailsService -> authorizationDetailsService.enrich(authorizationDetailsContext))
                // If provider is missing, return the original authorization detail instance
                .orElse(authorizationDetailsContext.getAuthorizationDetail());
    }

    /**
     * Retrieves the set of authorized authorization types for the given client and tenant domain.
     *
     * @param clientID     The client ID.
     * @param tenantDomain The tenant domain.
     * @return A set of strings representing the authorized authorization types.
     */
    private Set<String> getAuthorizedAuthorizationDetailsTypes(final String clientID, final String tenantDomain) {

//        try {
//            final String appId = OAuth2Util
//                    .getApplicationResourceIDByClientId(clientID, tenantDomain, this.applicationMgtService);
//
////        OAuth2ServiceComponentHolder.getInstance().getAuthorizedAPIManagementService()
// .getAuthorizedAuthorizationDetailsTypes(appId, tenantDomain);
//        } catch (IdentityOAuth2Exception e) {
//            throw new RuntimeException(e);
//        }
        Set<String> authorizedAuthorizationDetailsTypes = new HashSet<>();
        authorizedAuthorizationDetailsTypes.add("payment_initiation");
        return authorizedAuthorizationDetailsTypes;
    }
}
