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

package org.wso2.carbon.identity.oauth2.rar.validator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProviderFactory;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;
import org.wso2.carbon.identity.oauth2.rar.model.ValidationResult;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Default implementation class responsible for validating {@link AuthorizationDetails} in different
 * OAuth2 message contexts.
 */
public class DefaultAuthorizationDetailsValidator implements AuthorizationDetailsValidator {

    private static final Log log = LogFactory.getLog(DefaultAuthorizationDetailsValidator.class);
    private final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory;
    private final AuthorizationDetailsService authorizationDetailsService;

    public DefaultAuthorizationDetailsValidator() {

        this(
                AuthorizationDetailsProviderFactory.getInstance(),
                OAuth2ServiceComponentHolder.getInstance().getAuthorizationDetailsService()
        );
    }

    public DefaultAuthorizationDetailsValidator(
            final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory,
            final AuthorizationDetailsService authorizationDetailsService) {

        this.authorizationDetailsProviderFactory = authorizationDetailsProviderFactory;
        this.authorizationDetailsService = authorizationDetailsService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationDetails getValidatedAuthorizationDetails(final OAuthAuthzReqMessageContext
                                                                         oAuthAuthzReqMessageContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        try {
            return this.getValidatedAuthorizationDetails(
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getConsumerKey(),
                    OAuth2Util.getTenantId(oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain()),
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getAuthorizationDetails(),
                    authorizationDetail ->
                            new AuthorizationDetailsContext(authorizationDetail, oAuthAuthzReqMessageContext)
            );
        } catch (IdentityOAuth2Exception e) {
            log.error("Unable find the tenant ID of the domain: " +
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain() + " Caused by, ", e);
            throw new AuthorizationDetailsProcessingException("Invalid tenant domain", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationDetails getValidatedAuthorizationDetails(final OAuthTokenReqMessageContext
                                                                         oAuthTokenReqMessageContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        final OAuth2AccessTokenReqDTO accessTokenReqDTO = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO();

        if (GrantType.AUTHORIZATION_CODE.toString().equals(accessTokenReqDTO.getGrantType())) {
            if (log.isDebugEnabled()) {
                log.debug("Skipping the authorization_details validation for authorization code flow " +
                        "as this validation has already happened in the authorize flow.");
            }
            return oAuthTokenReqMessageContext.getAuthorizationDetails();
        }

        if (!AuthorizationDetailsUtils.isRichAuthorizationRequest(accessTokenReqDTO.getAuthorizationDetails())) {
            if (log.isDebugEnabled()) {
                log.debug("Client application does not request new authorization details. " +
                        "Returning previously validated authorization details.");

            }
            return oAuthTokenReqMessageContext.getAuthorizationDetails();
        }

        return this.getValidatedAuthorizationDetails(
                accessTokenReqDTO.getClientId(),
                oAuthTokenReqMessageContext.getTenantID(),
                accessTokenReqDTO.getAuthorizationDetails(),
                authorizationDetail -> new AuthorizationDetailsContext(authorizationDetail, oAuthTokenReqMessageContext)
        );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationDetails getValidatedAuthorizationDetails(
            final OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        try {
            final AccessTokenDO accessTokenDO = (AccessTokenDO) oAuth2TokenValidationMessageContext
                    .getProperty(OAuthConstants.ACCESS_TOKEN_DO);

            final AuthorizationDetails accessTokenAuthorizationDetails = this.authorizationDetailsService
                    .getAccessTokenAuthorizationDetails(accessTokenDO.getTokenId(), accessTokenDO.getTenantID());

            if (AuthorizationDetailsUtils.isRichAuthorizationRequest(accessTokenAuthorizationDetails)) {
                final Set<AuthorizationDetail> authorizedAuthorizationDetails =
                        this.getAuthorizedAuthorizationDetails(
                                accessTokenDO.getConsumerKey(),
                                accessTokenDO.getTenantID(),
                                accessTokenAuthorizationDetails);
                return new AuthorizationDetails(authorizedAuthorizationDetails);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while retrieving access token authorization details. Caused by, ", e);
            throw new AuthorizationDetailsProcessingException("Unable to retrieve token authorization details", e);
        }
        return new AuthorizationDetails();
    }

    /**
     * Validates the authorization details for OAuthTokenReqMessageContext.
     *
     * @param clientId             The client ID.
     * @param tenantId             The tenant ID.
     * @param authorizationDetails The set of authorization details to validate.
     * @param contextProvider      A lambda function to create the AuthorizationDetailsContext.
     * @return An {@link AuthorizationDetails} object containing the validated authorization details.
     * @throws AuthorizationDetailsProcessingException if validation fails.
     */
    private AuthorizationDetails getValidatedAuthorizationDetails(
            final String clientId, final int tenantId, final AuthorizationDetails authorizationDetails,
            final Function<AuthorizationDetail, AuthorizationDetailsContext> contextProvider)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        final Set<AuthorizationDetail> validatedAuthorizationDetails = new HashSet<>();
        for (final AuthorizationDetail authorizationDetail :
                this.getAuthorizedAuthorizationDetails(clientId, tenantId, authorizationDetails)) {

            if (!isSupportedAuthorizationDetailType(authorizationDetail.getType())) {
                throw new AuthorizationDetailsProcessingException(String.format(AuthorizationDetailsConstants
                        .TYPE_NOT_SUPPORTED_ERR_MSG_FORMAT, authorizationDetail.getType()));
            }

            if (log.isDebugEnabled()) {
                log.debug("Validation started for authorization detail of type: " + authorizationDetail.getType());
            }

            final AuthorizationDetailsContext authorizationDetailsContext = contextProvider.apply(authorizationDetail);

            if (this.isValidAuthorizationDetail(authorizationDetailsContext)) {
                validatedAuthorizationDetails.add(getEnrichedAuthorizationDetail(authorizationDetailsContext));
            }
        }

        return new AuthorizationDetails(validatedAuthorizationDetails);
    }

    private Set<AuthorizationDetail> getAuthorizedAuthorizationDetails(
            final String clientId, final int tenantId, final AuthorizationDetails authorizationDetails) {

        final Set<String> authorizedAuthorizationDetailsTypes =
                this.getAuthorizedAuthorizationDetailsTypes(clientId, tenantId);

        return authorizationDetails.stream()
                .filter(authorizationDetail ->
                        authorizedAuthorizationDetailsTypes.contains(authorizationDetail.getType()))
                .collect(Collectors.toSet());
    }

    private boolean isSupportedAuthorizationDetailType(final String authorizationDetailType) {

        return this.authorizationDetailsProviderFactory.isSupportedAuthorizationDetailsType(authorizationDetailType);
    }

    /**
     * Checks if the provided authorization details context is valid.
     *
     * @param authorizationDetailsContext The context containing authorization details.
     * @return {@code true} if the authorization details are valid; {@code false} otherwise.
     */
    private boolean isValidAuthorizationDetail(final AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        Optional<AuthorizationDetailsProcessor> optionalProvider = this.authorizationDetailsProviderFactory
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
                .map(authorizationDetailsProcessor -> authorizationDetailsProcessor.enrich(authorizationDetailsContext))
                // If provider is missing, return the original authorization detail instance
                .orElse(authorizationDetailsContext.getAuthorizationDetail());
    }

    /**
     * Retrieves the set of authorized authorization types for the given client and tenant domain.
     *
     * @param clientId The client ID.
     * @param tenantId The tenant ID.
     * @return A set of strings representing the authorized authorization types.
     */
    private Set<String> getAuthorizedAuthorizationDetailsTypes(final String clientId, final int tenantId) {

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
