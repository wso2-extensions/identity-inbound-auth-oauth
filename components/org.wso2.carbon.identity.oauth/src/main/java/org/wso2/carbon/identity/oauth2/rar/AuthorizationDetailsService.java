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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.rar.dao.AuthorizationDetailsDAO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsCodeDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils.getAuthorizationDetailsConsentDTOs;
import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils.getAuthorizationDetailsTypesMap;
import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils.isRichAuthorizationRequest;

/**
 * AuthorizationDetailsService is responsible for managing and handling OAuth2 authorization details,
 * specifically in the context of rich authorization requests.
 * <p>
 * This class integrates with the {@link AuthorizationDetailsDAO} to persist these details in the underlying data store.
 * It also provides utility methods to check if a request contains rich authorization details.
 * </p>
 *
 * @see AuthorizationDetailsDAO
 * @see AuthorizationDetails
 */
public class AuthorizationDetailsService {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsService.class);
    private final AuthorizationDetailsDAO authorizationDetailsDAO;
    private final AuthorizationDetailsProcessorFactory authorizationDetailsProcessorFactory;

    /**
     * Default constructor that initializes the service with the default {@link AuthorizationDetailsDAO} and
     * {@link AuthorizationDetailsProcessorFactory}.
     * <p>
     * This constructor uses the default DAO provided by the {@link OAuthTokenPersistenceFactory}
     * to handle the persistence of authorization details.
     * </p>
     */
    public AuthorizationDetailsService() {

        this(
                AuthorizationDetailsProcessorFactory.getInstance(),
                OAuthTokenPersistenceFactory.getInstance().getAuthorizationDetailsDAO()
        );
    }

    /**
     * Constructor that initializes the service with a given {@link AuthorizationDetailsDAO}.
     *
     * @param authorizationDetailsProcessorFactory Factory instance for providing authorization details.
     * @param authorizationDetailsDAO              The {@link AuthorizationDetailsDAO} instance to be used for
     *                                             handling authorization details persistence. Must not be {@code null}.
     */
    public AuthorizationDetailsService(final AuthorizationDetailsProcessorFactory authorizationDetailsProcessorFactory,
                                       final AuthorizationDetailsDAO authorizationDetailsDAO) {

        this.authorizationDetailsDAO = Objects
                .requireNonNull(authorizationDetailsDAO, "AuthorizationDetailsDAO must not be null");
        this.authorizationDetailsProcessorFactory = Objects.requireNonNull(authorizationDetailsProcessorFactory,
                "AuthorizationDetailsProviderFactory must not be null");
    }

    /**
     * Stores user-consented authorization details.
     *
     * @param authenticatedUser                 The authenticated user.
     * @param clientId                          The client ID.
     * @param oAuth2Parameters                  Requested OAuth2 parameters.
     * @param userConsentedAuthorizationDetails User consented authorization details.
     * @throws OAuthSystemException if an error occurs while storing user consented authorization details.
     */
    public void storeUserConsentedAuthorizationDetails(final AuthenticatedUser authenticatedUser, final String clientId,
                                                       final OAuth2Parameters oAuth2Parameters,
                                                       final AuthorizationDetails userConsentedAuthorizationDetails)
            throws OAuthSystemException {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            log.debug("Request is not a rich authorization request. Skipping storage of authorization details.");
            return;
        }

        try {
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);

            if (consentId.isPresent()) {
                final AuthorizationDetails trimmedAuthorizationDetails = AuthorizationDetailsUtils
                        .getTrimmedAuthorizationDetails(userConsentedAuthorizationDetails);

                final Set<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs =
                        getAuthorizationDetailsConsentDTOs(consentId.get(), trimmedAuthorizationDetails, tenantId);

                this.authorizationDetailsDAO.addUserConsentedAuthorizationDetails(authorizationDetailsConsentDTOs);
                if (log.isDebugEnabled()) {
                    log.debug("User consented authorization details stored successfully. consentId: " +
                            consentId.get());
                }
            }
        } catch (SQLException | IdentityOAuth2Exception e) {
            log.error("Error occurred while storing user consented authorization details. Caused by, ", e);
            throw new OAuthSystemException("Error occurred while storing authorization details", e);
        }
    }

    /**
     * Deletes user-consented authorization details.
     *
     * @param authenticatedUser The authenticated user.
     * @param clientId          The client ID.
     * @param oAuth2Parameters  Requested OAuth2 parameters.
     * @throws OAuthSystemException if an error occurs while deleting authorization details.
     */
    public void deleteUserConsentedAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                        final String clientId, final OAuth2Parameters oAuth2Parameters)
            throws OAuthSystemException {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            log.debug("Request is not a rich authorization request. Skipping deletion of authorization details.");
            return;
        }

        try {
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);

            if (consentId.isPresent()) {

                this.authorizationDetailsDAO.deleteUserConsentedAuthorizationDetails(consentId.get(), tenantId);

                if (log.isDebugEnabled()) {
                    log.debug("User consented authorization details deleted successfully. consentId: " +
                            consentId.get());
                }
            }
        } catch (SQLException | IdentityOAuth2Exception e) {
            log.error("Error occurred while deleting user consented authorization details. Caused by, ", e);
            throw new OAuthSystemException("Error occurred while storing authorization details", e);
        }
    }

    /**
     * Replaces the user consented authorization details.
     *
     * @param authenticatedUser                 The authenticated user.
     * @param clientId                          The client ID.
     * @param oAuth2Parameters                  Requested OAuth2 parameters.
     * @param userConsentedAuthorizationDetails User consented authorization details.
     * @throws OAuthSystemException if an error occurs while storing or replacing authorization details.
     */
    public void replaceUserConsentedAuthorizationDetails(
            final AuthenticatedUser authenticatedUser, final String clientId, final OAuth2Parameters oAuth2Parameters,
            final AuthorizationDetails userConsentedAuthorizationDetails) throws OAuthSystemException {

        this.deleteUserConsentedAuthorizationDetails(authenticatedUser, clientId, oAuth2Parameters);
        this.storeUserConsentedAuthorizationDetails(authenticatedUser, clientId, oAuth2Parameters,
                userConsentedAuthorizationDetails);
    }

    /**
     * Check if the user has already given consent to requested authorization details.
     *
     * @param authenticatedUser Authenticated user.
     * @param oAuth2Parameters  OAuth2 parameters.
     * @return {@code true} if user has given consent to all the requested authorization details,
     * {@code false} otherwise.
     */
    public boolean isUserAlreadyConsentedForAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                                 final OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            return true;
        }

        return this.getConsentRequiredAuthorizationDetails(authenticatedUser, oAuth2Parameters).getDetails().isEmpty();
    }

    public AuthorizationDetails getConsentRequiredAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                                       final OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            log.debug("Request is not a rich authorization request. Skipping the authorization details retrieval.");
            return new AuthorizationDetails();
        }

        final Map<String, Set<AuthorizationDetail>> consentedAuthorizationDetailsByType =
                this.getUserConsentedAuthorizationDetailsByType(authenticatedUser, oAuth2Parameters);

        final Set<AuthorizationDetail> consentRequiredAuthorizationDetails = new HashSet<>();
        oAuth2Parameters.getAuthorizationDetails().stream()
                .filter(requestedDetail ->
                        !this.isUserConsentedAuthorizationDetail(requestedDetail, consentedAuthorizationDetailsByType))
                .forEach(consentRequiredAuthorizationDetails::add);

        return new AuthorizationDetails(consentRequiredAuthorizationDetails);
    }

    private Map<String, Set<AuthorizationDetail>> getUserConsentedAuthorizationDetailsByType(
            final AuthenticatedUser authenticatedUser, final OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        return getAuthorizationDetailsTypesMap(
                this.getUserConsentedAuthorizationDetails(authenticatedUser, oAuth2Parameters));
    }

    /**
     * Checks if the user has already consented to the requested authorization detail.
     *
     * <p>This method validates if the requested authorization detail is part of the consented authorization details.
     * It uses the appropriate provider to compare the requested detail with the existing consented details.</p>
     *
     * @param requestedAuthorizationDetail        the authorization detail to be checked
     * @param consentedAuthorizationDetailsByType a map of consented authorization details grouped by type
     * @return {@code true} if the user has consented to the requested authorization detail, {@code false} otherwise
     */
    private boolean isUserConsentedAuthorizationDetail(
            final AuthorizationDetail requestedAuthorizationDetail,
            final Map<String, Set<AuthorizationDetail>> consentedAuthorizationDetailsByType) {

        final String requestedType = requestedAuthorizationDetail.getType();
        if (!consentedAuthorizationDetailsByType.containsKey(requestedType)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User hasn't consented for the requested authorization details type '%s'.",
                        requestedType));
            }
            return false;
        }

        final Optional<AuthorizationDetailsProcessor> optProcessor =
                this.authorizationDetailsProcessorFactory.getAuthorizationDetailsProcessorByType(requestedType);

        if (optProcessor.isPresent()) {

            if (log.isDebugEnabled()) {
                log.debug("Validating equality of requested and existing authorization details " +
                        "using processor class: " + optProcessor.get().getClass().getSimpleName());
            }

            final AuthorizationDetails existingAuthorizationDetails =
                    new AuthorizationDetails(consentedAuthorizationDetailsByType.get(requestedType));
            boolean isEqualOrSubset = optProcessor.get()
                    .isEqualOrSubset(requestedAuthorizationDetail, existingAuthorizationDetails);

            if (log.isDebugEnabled()) {
                log.debug(String.format("Verifying if the user has already consented to the requested " +
                        "authorization details type: '%s'. Result: %b", requestedType, isEqualOrSubset));
            }
            return isEqualOrSubset;
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("No AuthorizationDetailsProcessor implementation found for type: %s. " +
                    "Proceeding with user consent.", requestedType));
        }
        return false;
    }

    /**
     * Retrieves the user consented authorization details for a given user and OAuth2 parameters.
     *
     * @param authenticatedUser The authenticated user.
     * @param oAuth2Parameters  The OAuth2 parameters.
     * @return The user consented authorization details.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the details.
     */
    public AuthorizationDetails getUserConsentedAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                                     final OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
        return this.getUserConsentedAuthorizationDetails(authenticatedUser, oAuth2Parameters.getClientId(), tenantId);
    }

    /**
     * Retrieves the user consented authorization details for a given user, client, and tenant.
     *
     * @param authenticatedUser The authenticated user.
     * @param clientId          The client ID.
     * @param tenantId          The tenant ID.
     * @return The user consented authorization details, or {@code null} if no consent is found.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the details.
     */
    public AuthorizationDetails getUserConsentedAuthorizationDetails(
            final AuthenticatedUser authenticatedUser, final String clientId, final int tenantId)
            throws IdentityOAuth2Exception {

        try {
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);
            if (consentId.isPresent()) {
                final Set<AuthorizationDetail> consentedAuthorizationDetails = new HashSet<>();
                this.authorizationDetailsDAO.getUserConsentedAuthorizationDetails(consentId.get(), tenantId)
                        .stream()
                        .filter(AuthorizationDetailsConsentDTO::isConsentActive)
                        .map(AuthorizationDetailsConsentDTO::getAuthorizationDetail)
                        .forEach(consentedAuthorizationDetails::add);
                return new AuthorizationDetails(consentedAuthorizationDetails);
            }
        } catch (SQLException e) {
            log.error("Error occurred while retrieving user consented authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Unable to retrieve user consented authorization details", e);
        }
        return null;
    }

    /**
     * Retrieves the consent ID for the given user, client, and tenant.
     *
     * @param authenticatedUser The authenticated user.
     * @param clientId          The client ID.
     * @param tenantId          The tenant ID.
     * @return An {@link Optional} containing the consent ID if present.
     * @throws IdentityOAuth2Exception if an error occurs related to OAuth2 identity.
     */
    private Optional<String> getConsentId(final AuthenticatedUser authenticatedUser, final String clientId,
                                          final int tenantId)
            throws IdentityOAuth2Exception {

        final String userId = AuthorizationDetailsUtils.getIdFromAuthenticatedUser(authenticatedUser);
        final String appId = AuthorizationDetailsUtils.getApplicationResourceIdFromClientId(clientId);

        return this.getConsentIdByUserIdAndAppId(userId, appId, tenantId);
    }

    /**
     * Retrieves the consent ID by user ID and application ID.
     *
     * @param userId   The user ID.
     * @param appId    The application ID.
     * @param tenantId The tenant ID.
     * @return An {@link Optional} containing the consent ID if present.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving the consent ID.
     */
    public Optional<String> getConsentIdByUserIdAndAppId(final String userId, final String appId, final int tenantId)
            throws IdentityOAuth2Exception {

        try {
            return Optional
                    .ofNullable(this.authorizationDetailsDAO.getConsentIdByUserIdAndAppId(userId, appId, tenantId));
        } catch (SQLException e) {
            log.error(String.format("Error occurred while retrieving user consent by " +
                    "userId: %s and appId: %s. Caused by, ", userId, appId), e);
            throw new IdentityOAuth2Exception("Error occurred while retrieving user consent", e);
        }
    }

    /**
     * Retrieves the authorization details associated with a given access token.
     *
     * @param accessTokenId The access token ID.
     * @param tenantId      The tenant ID.
     * @return The access token authorization details.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the details.
     */
    public AuthorizationDetails getAccessTokenAuthorizationDetails(final String accessTokenId, final int tenantId)
            throws IdentityOAuth2Exception {

        try {
            final Set<AuthorizationDetailsTokenDTO> authorizationDetailsTokenDTOs =
                    this.authorizationDetailsDAO.getAccessTokenAuthorizationDetails(accessTokenId, tenantId);

            final Set<AuthorizationDetail> accessTokenAuthorizationDetails = new HashSet<>();
            authorizationDetailsTokenDTOs
                    .stream()
                    .map(AuthorizationDetailsTokenDTO::getAuthorizationDetail)
                    .forEach(accessTokenAuthorizationDetails::add);

            return new AuthorizationDetails(accessTokenAuthorizationDetails);
        } catch (SQLException e) {
            log.error("Error occurred while retrieving access token authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Unable to retrieve access token authorization details", e);
        }
    }

    /**
     * Stores the authorization details for a given access token and OAuth authorization request context.
     *
     * @param accessTokenDO               The access token data object.
     * @param oAuthAuthzReqMessageContext The OAuth authorization request message context.
     * @throws IdentityOAuth2Exception If an error occurs while storing the details.
     */
    public void storeAccessTokenAuthorizationDetails(final AccessTokenDO accessTokenDO,
                                                     final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuthAuthzReqMessageContext)) {
            log.debug("Request is not a rich authorization request. Skipping storage of token authorization details.");
            return;
        }

        this.storeAccessTokenAuthorizationDetails(accessTokenDO, oAuthAuthzReqMessageContext.getAuthorizationDetails());
    }

    /**
     * Stores the authorization details for a given access token and authorization details.
     *
     * @param accessTokenDO        The access token data object.
     * @param authorizationDetails The authorization details.
     * @throws IdentityOAuth2Exception If an error occurs while storing the details.
     */
    public void storeAccessTokenAuthorizationDetails(final AccessTokenDO accessTokenDO,
                                                     final AuthorizationDetails authorizationDetails)
            throws IdentityOAuth2Exception {

        try {
            final AuthorizationDetails trimmedAuthorizationDetails = AuthorizationDetailsUtils
                    .getTrimmedAuthorizationDetails(authorizationDetails);

            final Set<AuthorizationDetailsTokenDTO> authorizationDetailsTokenDTOs = AuthorizationDetailsUtils
                    .getAccessTokenAuthorizationDetailsDTOs(accessTokenDO, trimmedAuthorizationDetails);

            // Storing the authorization details.
            this.authorizationDetailsDAO.addAccessTokenAuthorizationDetails(authorizationDetailsTokenDTOs);

            if (log.isDebugEnabled()) {
                log.debug("Successfully stored access token authorization details for tokenId: " +
                        accessTokenDO.getTokenId());
            }
        } catch (SQLException e) {
            log.error("Error occurred while storing access token authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Error occurred while storing access token authorization details", e);
        }
    }

    /**
     * Stores or replaces the authorization details for a new access token and
     * optionally deletes the old token's details.
     *
     * @param newAccessTokenDO            The new access token data object.
     * @param oldAccessTokenDO            The old access token data object.
     * @param oAuthTokenReqMessageContext The OAuth token request message context.
     * @throws IdentityOAuth2Exception If an error occurs while storing or replacing the details.
     */
    public void storeOrReplaceAccessTokenAuthorizationDetails(
            final AccessTokenDO newAccessTokenDO, final AccessTokenDO oldAccessTokenDO,
            final OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuthTokenReqMessageContext)) {
            log.debug("Request is not a rich authorization request. Skipping storage of token authorization details.");
            return;
        }

        if (Objects.nonNull(oldAccessTokenDO)) {
            this.deleteAccessTokenAuthorizationDetails(oldAccessTokenDO.getTokenId(), oldAccessTokenDO.getTenantID());
        }

        this.storeAccessTokenAuthorizationDetails(newAccessTokenDO,
                oAuthTokenReqMessageContext.getAuthorizationDetails());
    }

    /**
     * Deletes the authorization details associated with a given access token.
     *
     * @param accessTokenId The access token ID.
     * @param tenantId      The tenant ID.
     * @throws IdentityOAuth2Exception If an error occurs while deleting the details.
     */
    public void deleteAccessTokenAuthorizationDetails(final String accessTokenId, final int tenantId)
            throws IdentityOAuth2Exception {

        try {
            this.authorizationDetailsDAO.deleteAccessTokenAuthorizationDetails(accessTokenId, tenantId);
            if (log.isDebugEnabled()) {
                log.debug("Access token authorization details deleted successfully. accessTokenId: " + accessTokenId);
            }
        } catch (SQLException e) {
            log.error("Error occurred while deleting access token authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Error occurred while deleting access token authorization details", e);
        }
    }

    /**
     * Replaces the authorization details for an old access token with the details of a new access token.
     *
     * @param oldAccessTokenId            The old access token ID.
     * @param newAccessTokenDO            The new access token data object.
     * @param oAuthTokenReqMessageContext The OAuth token request message context.
     * @throws IdentityOAuth2Exception If an error occurs while replacing the details.
     */
    public void replaceAccessTokenAuthorizationDetails(final String oldAccessTokenId,
                                                       final AccessTokenDO newAccessTokenDO,
                                                       final OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuthTokenReqMessageContext)) {
            log.debug("Request is not a rich authorization request. Skipping replacement of authorization details.");
            return;
        }
        this.deleteAccessTokenAuthorizationDetails(oldAccessTokenId, newAccessTokenDO.getTenantID());
        this.storeAccessTokenAuthorizationDetails(newAccessTokenDO, oAuthTokenReqMessageContext);
    }

    /**
     * Stores the authorization details for a given access token and OAuth token request context.
     *
     * @param accessTokenDO               The access token data object.
     * @param oAuthTokenReqMessageContext The OAuth token request message context.
     * @throws IdentityOAuth2Exception If an error occurs while storing the details.
     */
    public void storeAccessTokenAuthorizationDetails(final AccessTokenDO accessTokenDO,
                                                     final OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuthTokenReqMessageContext)) {
            log.debug("Request is not a rich authorization request. Skipping storage of token authorization details.");
            return;
        }

        this.storeAccessTokenAuthorizationDetails(accessTokenDO, oAuthTokenReqMessageContext.getAuthorizationDetails());
    }

    /**
     * Stores the authorization details for a given authorization code and OAuth authorization request context.
     *
     * @param authzCodeDO                 The authorization code data object.
     * @param oAuthAuthzReqMessageContext The OAuth authorization request message context.
     * @throws IdentityOAuth2Exception If an error occurs while storing the details.
     */
    public void storeAuthorizationCodeAuthorizationDetails(
            final AuthzCodeDO authzCodeDO, final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuthAuthzReqMessageContext)) {
            log.debug("Request is not a rich authorization request. Skipping storage of code authorization details.");
            return;
        }

        try {
            final int tenantId =
                    OAuth2Util.getTenantId(oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain());

            final Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs =
                    AuthorizationDetailsUtils.getCodeAuthorizationDetailsDTOs(authzCodeDO,
                            oAuthAuthzReqMessageContext.getAuthorizationDetails(), tenantId);

            // Storing the authorization details.
            this.authorizationDetailsDAO.addOAuth2CodeAuthorizationDetails(authorizationDetailsCodeDTOs);

            if (log.isDebugEnabled()) {
                log.debug("Successfully stored authorization code authorization details for code ID: " +
                        authzCodeDO.getAuthzCodeId());
            }
        } catch (SQLException e) {
            log.error("Error occurred while storing authorization code authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Error occurred while storing authz code authorization details", e);
        }
    }

    /**
     * Retrieves the authorization details associated with a given authorization code Id.
     *
     * @param codeId   The authorization code ID.
     * @param tenantId The tenant ID.
     * @return The authorization code authorization details.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the details.
     */
    public AuthorizationDetails getAuthorizationCodeAuthorizationDetails(final String codeId, final int tenantId)
            throws IdentityOAuth2Exception {

        try {
            final Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs =
                    this.authorizationDetailsDAO.getOAuth2CodeAuthorizationDetails(codeId, tenantId);

            final Set<AuthorizationDetail> codeAuthorizationDetails = new HashSet<>();
            authorizationDetailsCodeDTOs
                    .stream()
                    .map(AuthorizationDetailsCodeDTO::getAuthorizationDetail)
                    .forEach(codeAuthorizationDetails::add);

            return new AuthorizationDetails(codeAuthorizationDetails);
        } catch (SQLException e) {
            log.error("Error occurred while retrieving authz code authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Unable to retrieve authz code authorization details", e);
        }
    }
}
