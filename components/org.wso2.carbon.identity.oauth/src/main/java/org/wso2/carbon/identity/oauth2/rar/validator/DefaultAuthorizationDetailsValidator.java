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

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AuthorizationDetailsType;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsSchemaValidator;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;
import org.wso2.carbon.identity.oauth2.rar.model.ValidationResult;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants.TYPE_NOT_SUPPORTED_ERR_FORMAT;
import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants.VALIDATION_FAILED_ERR_MSG;

/**
 * Default implementation class responsible for validating {@link AuthorizationDetails} in different
 * OAuth2 message contexts.
 */
public class DefaultAuthorizationDetailsValidator implements AuthorizationDetailsValidator {

    private static final Log log = LogFactory.getLog(DefaultAuthorizationDetailsValidator.class);
    private final AuthorizationDetailsProcessorFactory authorizationDetailsProcessorFactory;
    private final AuthorizationDetailsService authorizationDetailsService;
    private final AuthorizationDetailsSchemaValidator authorizationDetailsSchemaValidator;

    public DefaultAuthorizationDetailsValidator() {
        this(
                AuthorizationDetailsProcessorFactory.getInstance(),
                OAuth2ServiceComponentHolder.getInstance().getAuthorizationDetailsService(),
                AuthorizationDetailsSchemaValidator.getInstance()
        );
    }

    public DefaultAuthorizationDetailsValidator(
            final AuthorizationDetailsProcessorFactory authorizationDetailsProcessorFactory,
            final AuthorizationDetailsService authorizationDetailsService,
            final AuthorizationDetailsSchemaValidator authorizationDetailsSchemaValidator) {

        this.authorizationDetailsProcessorFactory = authorizationDetailsProcessorFactory;
        this.authorizationDetailsService = authorizationDetailsService;
        this.authorizationDetailsSchemaValidator = authorizationDetailsSchemaValidator;
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
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain(),
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getAuthorizationDetails(),
                    (detail, type) -> new AuthorizationDetailsContext(detail, type, oAuthAuthzReqMessageContext)
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

        if (!AuthorizationDetailsUtils.isRichAuthorizationRequest(accessTokenReqDTO.getAuthorizationDetails())) {
            if (log.isDebugEnabled()) {
                log.debug("Client application does not request new authorization details. " +
                        "Returning previously validated authorization details.");
            }
            return oAuthTokenReqMessageContext.getAuthorizationDetails();
        }

        if (GrantType.AUTHORIZATION_CODE.toString().equals(accessTokenReqDTO.getGrantType())) {
            if (log.isDebugEnabled()) {
                log.debug("Skipping the authorization_details validation for authorization code flow " +
                        "as this validation has already happened in the authorize flow.");
            }
            return oAuthTokenReqMessageContext.getAuthorizationDetails();
        }

        final AuthorizationDetails validatedAuthorizationDetails = this.getValidatedAuthorizationDetails(
                accessTokenReqDTO.getClientId(),
                accessTokenReqDTO.getTenantDomain(),
                accessTokenReqDTO.getAuthorizationDetails(),
                (detail, type) -> new AuthorizationDetailsContext(detail, type, oAuthTokenReqMessageContext)
        );

        if (GrantType.REFRESH_TOKEN.toString().equals(accessTokenReqDTO.getGrantType())) {
            return new AuthorizationDetails(this.filterConsentedAuthorizationDetails(validatedAuthorizationDetails,
                    oAuthTokenReqMessageContext.getAuthorizationDetails()));
        }

        return validatedAuthorizationDetails;
    }

    /**
     * Validates whether the user has consented to the requested authorization details.
     *
     * @param requestedAuthorizationDetails The requested authorization details.
     * @param consentedAuthorizationDetails The consented authorization details.
     * @throws AuthorizationDetailsProcessingException If validation fails.
     */
    private Set<AuthorizationDetail> filterConsentedAuthorizationDetails(
            final AuthorizationDetails requestedAuthorizationDetails,
            final AuthorizationDetails consentedAuthorizationDetails)
            throws AuthorizationDetailsProcessingException {

        final Set<AuthorizationDetail> validAuthorizationDetails = new HashSet<>();
        if (AuthorizationDetailsUtils.isEmpty(requestedAuthorizationDetails)) {
            log.debug("No authorization details requested. Using all consented authorization details.");
            validAuthorizationDetails.addAll(consentedAuthorizationDetails.getDetails());
            return validAuthorizationDetails;
        }

        if (AuthorizationDetailsUtils.isEmpty(consentedAuthorizationDetails)) {
            log.debug("Invalid request. No consented authorization details found.");
            throw new AuthorizationDetailsProcessingException(VALIDATION_FAILED_ERR_MSG);
        }

        // Map consented authorization details by type for quick lookup
        final Map<String, Set<AuthorizationDetail>> consentedAuthorizationDetailsByType =
                AuthorizationDetailsUtils.getAuthorizationDetailsTypesMap(consentedAuthorizationDetails);

        for (AuthorizationDetail requestedAuthorizationDetail : requestedAuthorizationDetails.getDetails()) {

            final String requestedType = requestedAuthorizationDetail.getType();
            if (!consentedAuthorizationDetailsByType.containsKey(requestedType)) {
                if (log.isDebugEnabled()) {
                    log.debug("User hasn't consented to the requested authorization details type: " + requestedType);
                }
                throw new AuthorizationDetailsProcessingException(VALIDATION_FAILED_ERR_MSG);
            }

            final Optional<AuthorizationDetailsProcessor> optProcessor =
                    this.authorizationDetailsProcessorFactory.getAuthorizationDetailsProcessorByType(requestedType);

            if (optProcessor.isPresent()) {
                if (log.isDebugEnabled()) {
                    log.debug("Validating equality of requested and existing authorization details using processor: "
                            + optProcessor.get().getClass().getSimpleName());
                }
                final AuthorizationDetails existingAuthorizationDetails =
                        new AuthorizationDetails(consentedAuthorizationDetailsByType.get(requestedType));

                // If the requested authorization details match the consented ones, add to the valid set
                if (optProcessor.get().isEqualOrSubset(requestedAuthorizationDetail, existingAuthorizationDetails)) {
                    validAuthorizationDetails.add(requestedAuthorizationDetail);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User hasn't consented to requested authorization details type: " + requestedType);
                    }
                    throw new AuthorizationDetailsProcessingException(VALIDATION_FAILED_ERR_MSG);
                }
            } else {
                // Cannot process, returning all consented authorization details
                if (CollectionUtils.isNotEmpty(consentedAuthorizationDetailsByType.get(requestedType))) {
                    validAuthorizationDetails.addAll(consentedAuthorizationDetailsByType.get(requestedType));
                }
                consentedAuthorizationDetailsByType.put(requestedType, Collections.emptySet());
            }
        }
        return validAuthorizationDetails;
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
                        this.getValidatedAuthorizationDetails(
                                accessTokenDO.getConsumerKey(),
                                IdentityTenantUtil.getTenantDomain(accessTokenDO.getTenantID()),
                                accessTokenAuthorizationDetails);
                return new AuthorizationDetails(authorizedAuthorizationDetails);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while retrieving access token authorization details. Caused by, ", e);
            throw new AuthorizationDetailsProcessingException("Unable to retrieve token authorization details", e);
        }
        return new AuthorizationDetails();
    }

    private Set<AuthorizationDetail> getValidatedAuthorizationDetails(
            final String clientId, final String tenantDomain, final AuthorizationDetails authorizationDetails)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        return this.getSchemaCompliantAuthorizationDetails(authorizationDetails,
                this.getAuthorizedAuthorizationDetailsTypes(clientId, tenantDomain));
    }

    /**
     * Validates the authorization details for OAuthTokenReqMessageContext.
     *
     * @param clientId             The client ID.
     * @param tenantDomain         The tenant domain.
     * @param authorizationDetails The set of authorization details to validate.
     * @param contextProvider      A lambda function to create the AuthorizationDetailsContext.
     * @return An {@link AuthorizationDetails} object containing the validated authorization details.
     * @throws AuthorizationDetailsProcessingException if validation fails.
     */
    private AuthorizationDetails getValidatedAuthorizationDetails(
            final String clientId, final String tenantDomain, final AuthorizationDetails authorizationDetails,
            BiFunction<AuthorizationDetail, AuthorizationDetailsType, AuthorizationDetailsContext> contextProvider)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        final Map<String, AuthorizationDetailsType> authorizedDetailsTypes =
                this.getAuthorizedAuthorizationDetailsTypes(clientId, tenantDomain);

        final Set<AuthorizationDetail> validatedAuthorizationDetails = new HashSet<>();
        for (final AuthorizationDetail authorizationDetail :
                this.getSchemaCompliantAuthorizationDetails(authorizationDetails, authorizedDetailsTypes)) {

            final AuthorizationDetailsContext authorizationDetailsContext = contextProvider
                    .apply(authorizationDetail, authorizedDetailsTypes.get(authorizationDetail.getType()));

            if (this.isValidAuthorizationDetail(authorizationDetailsContext)) {
                validatedAuthorizationDetails.add(this.getEnrichedAuthorizationDetail(authorizationDetailsContext));
            }
        }
        return new AuthorizationDetails(validatedAuthorizationDetails);
    }

    /**
     * Retrieves the set of authorized authorization types for the given client and tenant domain.
     *
     * @param clientId     The client ID.
     * @param tenantDomain The tenant domain.
     * @return A set of strings representing the authorized authorization types.
     */
    private Map<String, AuthorizationDetailsType> getAuthorizedAuthorizationDetailsTypes(final String clientId,
                                                                                         final String tenantDomain)
            throws IdentityOAuth2ServerException {

        try {
            final String appId = AuthorizationDetailsUtils.getApplicationResourceIdFromClientId(clientId);
            final List<AuthorizationDetailsType> authorizationDetailsTypes = OAuth2ServiceComponentHolder.getInstance()
                    .getAuthorizedAPIManagementService().getAuthorizedAuthorizationDetailsTypes(appId, tenantDomain);

            if (CollectionUtils.isNotEmpty(authorizationDetailsTypes)) {
                return authorizationDetailsTypes.stream()
                        .collect(Collectors.toMap(AuthorizationDetailsType::getType, Function.identity()));
            }
        } catch (IdentityOAuth2Exception | IdentityApplicationManagementException e) {
            log.error("Unable to retrieve authorized authorization details types. Caused by, ", e);
            throw new IdentityOAuth2ServerException("Unable to retrieve authorized authorization details types", e);
        }
        return Collections.emptyMap();
    }

    private Set<AuthorizationDetail> getSchemaCompliantAuthorizationDetails(
            final AuthorizationDetails authorizationDetails,
            final Map<String, AuthorizationDetailsType> authorizedDetailsTypes)
            throws AuthorizationDetailsProcessingException {

        final Set<AuthorizationDetail> schemaCompliantAuthorizationDetails = new HashSet<>();
        for (final AuthorizationDetail authorizationDetail : authorizationDetails.getDetails()) {

            if (log.isDebugEnabled()) {
                log.debug("Schema validation started for authorization details type: " + authorizationDetail.getType());
            }

            this.assertAuthorizationDetailTypeSupported(authorizationDetail.getType());

            if (this.isSchemaCompliant(authorizationDetail.getType(), authorizationDetail, authorizedDetailsTypes)) {
                schemaCompliantAuthorizationDetails.add(authorizationDetail);
            }
        }
        return schemaCompliantAuthorizationDetails;
    }

    /**
     * Checks if the provided authorization details context is valid.
     *
     * @param authorizationDetailsContext The context containing authorization details.
     * @return {@code true} if the authorization details are valid; {@code false} otherwise.
     */
    private boolean isValidAuthorizationDetail(final AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        final String type = authorizationDetailsContext.getAuthorizationDetail().getType();
        final Optional<AuthorizationDetailsProcessor> optProcessor =
                this.authorizationDetailsProcessorFactory.getAuthorizationDetailsProcessorByType(type);

        if (optProcessor.isPresent()) {

            final ValidationResult validationResult = optProcessor.get().validate(authorizationDetailsContext);
            if (validationResult.isInvalid()) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Authorization details validation failed for type: %s. Caused by, %s",
                            type, validationResult.getReason()));
                }
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("An authorization details processor implementation is not found for type: " + type);
            }
        }
        return true;
    }

    /**
     * Enriches the authorization details using the provided context.
     *
     * @param authorizationDetailsContext The context containing authorization details.
     * @return An enriched {@link AuthorizationDetail} object.
     */
    private AuthorizationDetail getEnrichedAuthorizationDetail(
            final AuthorizationDetailsContext authorizationDetailsContext) {

        return this.authorizationDetailsProcessorFactory
                .getAuthorizationDetailsProcessorByType(authorizationDetailsContext.getAuthorizationDetail().getType())
                .map(authorizationDetailsProcessor -> authorizationDetailsProcessor.enrich(authorizationDetailsContext))
                // If provider is missing, return the original authorization detail instance
                .orElse(authorizationDetailsContext.getAuthorizationDetail());
    }

    private void assertAuthorizationDetailTypeSupported(final String type)
            throws AuthorizationDetailsProcessingException {

        if (!this.authorizationDetailsProcessorFactory.isSupportedAuthorizationDetailsType(type)) {
            throw new AuthorizationDetailsProcessingException(String.format(TYPE_NOT_SUPPORTED_ERR_FORMAT, type));
        }
    }

    private boolean isSchemaCompliant(final String type, final AuthorizationDetail authorizationDetail,
                                      final Map<String, AuthorizationDetailsType> authorizedDetailsTypes)
            throws AuthorizationDetailsProcessingException {

        if (!authorizedDetailsTypes.containsKey(type)) {
            if (log.isDebugEnabled()) {
                log.debug("Request received for unauthorized authorization details type: " + type);
            }
            throw new AuthorizationDetailsProcessingException(VALIDATION_FAILED_ERR_MSG);
        }

        if (this.authorizationDetailsSchemaValidator
                .isSchemaCompliant(authorizedDetailsTypes.get(type).getSchema(), authorizationDetail)) {
            return true;
        }

        if (log.isDebugEnabled()) {
            log.debug("Ignoring non-schema-compliant authorization details type: " + type);
        }
        return false;
    }
}
