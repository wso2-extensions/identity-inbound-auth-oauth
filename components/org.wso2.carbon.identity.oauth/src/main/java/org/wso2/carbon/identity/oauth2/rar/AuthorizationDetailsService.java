package org.wso2.carbon.identity.oauth2.rar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProviderFactory;
import org.wso2.carbon.identity.oauth2.rar.dao.AuthorizationDetailsDAO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils.getAuthorizationDetailsConsentDTOs;
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
    private final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory;

    /**
     * Default constructor that initializes the service with the default {@link AuthorizationDetailsDAO} and
     * {@link AuthorizationDetailsProviderFactory}.
     * <p>
     * This constructor uses the default DAO provided by the {@link OAuthTokenPersistenceFactory}
     * to handle the persistence of authorization details.
     * </p>
     */
    public AuthorizationDetailsService() {

        this(
                AuthorizationDetailsProviderFactory.getInstance(),
                OAuthTokenPersistenceFactory.getInstance().getAuthorizationDetailsDAO()
        );
    }

    /**
     * Constructor that initializes the service with a given {@link AuthorizationDetailsDAO}.
     *
     * @param authorizationDetailsProviderFactory Factory instance for providing authorization details.
     * @param authorizationDetailsDAO             The {@link AuthorizationDetailsDAO} instance to be used for
     *                                            handling authorization details persistence. Must not be {@code null}.
     */
    public AuthorizationDetailsService(final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory,
                                       final AuthorizationDetailsDAO authorizationDetailsDAO) {

        this.authorizationDetailsDAO = Objects
                .requireNonNull(authorizationDetailsDAO, "AuthorizationDetailsDAO must not be null");
        this.authorizationDetailsProviderFactory = Objects.requireNonNull(authorizationDetailsProviderFactory,
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

                final List<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs =
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

    public void updateUserConsentedAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                        final String clientId, final OAuth2Parameters oAuth2Parameters,
                                                        final AuthorizationDetails userConsentedAuthorizationDetails)
            throws OAuthSystemException {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            return;
        }

        try {
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);

            if (consentId.isPresent()) {

                final List<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs =
                        getAuthorizationDetailsConsentDTOs(consentId.get(),
                                userConsentedAuthorizationDetails, tenantId);

                this.authorizationDetailsDAO.updateUserConsentedAuthorizationDetails(authorizationDetailsConsentDTOs);
            }
        } catch (SQLException | IdentityOAuth2Exception e) {
            log.error("Error occurred while updating user consented authorization details. Caused by, ", e);
            throw new OAuthSystemException("Error occurred while updating authorization details", e);
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

    /**
     * Retrieves the user consented authorization details for a given user, client, and tenant.
     *
     * @param authenticatedUser The authenticated user.
     * @param clientId          The client ID.
     * @param tenantId          The tenant ID.
     * @return The user consented authorization details.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the details.
     */
    public AuthorizationDetails getUserConsentedAuthorizationDetails(
            final AuthenticatedUser authenticatedUser, final String clientId, final int tenantId)
            throws IdentityOAuth2Exception {

        try {
            final Set<AuthorizationDetail> consentedAuthorizationDetails = new HashSet<>();
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);
            if (consentId.isPresent()) {
                final Set<AuthorizationDetailsConsentDTO> consentedAuthorizationDetailsDTOs =
                        this.authorizationDetailsDAO.getUserConsentedAuthorizationDetails(consentId.get(), tenantId);

                consentedAuthorizationDetailsDTOs
                        .stream()
                        .filter(AuthorizationDetailsConsentDTO::isConsentActive)
                        .map(AuthorizationDetailsConsentDTO::getAuthorizationDetail)
                        .forEach(consentedAuthorizationDetails::add);
            }
            return new AuthorizationDetails(consentedAuthorizationDetails);
        } catch (SQLException e) {
            log.error("Error occurred while retrieving user consented authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Unable to retrieve user consented authorization details", e);
        }
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

            final List<AuthorizationDetailsTokenDTO> authorizationDetailsTokenDTOs = AuthorizationDetailsUtils
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

    public AuthorizationDetails getConsentRequiredAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                                       final OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            log.debug("Request is not a rich authorization request. Skipping the authorization details retrieval.");
            return new AuthorizationDetails();
        }

        final Map<String, Set<AuthorizationDetail>> consentedAuthorizationDetailsByType =
                getUserConsentedAuthorizationDetailsByType(authenticatedUser, oAuth2Parameters);

        final Set<AuthorizationDetail> consentRequiredAuthorizationDetails = new HashSet<>();
        oAuth2Parameters.getAuthorizationDetails().stream()
                .filter(requestedDetail ->
                        !this.isUserConsentedAuthorizationDetail(consentedAuthorizationDetailsByType, requestedDetail))
                .forEach(consentRequiredAuthorizationDetails::add);

        return new AuthorizationDetails(consentRequiredAuthorizationDetails);
    }

    private Map<String, Set<AuthorizationDetail>> getUserConsentedAuthorizationDetailsByType(
            final AuthenticatedUser authenticatedUser, final OAuth2Parameters oAuth2Parameters)
            throws IdentityOAuth2Exception {

        return this.getUserConsentedAuthorizationDetails(authenticatedUser, oAuth2Parameters)
                .stream()
                .collect(Collectors.groupingBy(AuthorizationDetail::getType,
                        Collectors.mapping(Function.identity(), Collectors.toSet())));
    }

    /**
     * Checks if the user has already consented to the requested authorization detail.
     *
     * <p>This method validates if the requested authorization detail is part of the consented authorization details.
     * It uses the appropriate provider to compare the requested detail with the existing consented details.</p>
     *
     * @param consentedAuthorizationDetailsByType a map of consented authorization details grouped by type
     * @param requestedAuthorizationDetail the authorization detail to be checked
     * @return {@code true} if the user has consented to the requested authorization detail, {@code false} otherwise
     */
    public boolean isUserConsentedAuthorizationDetail(
            final Map<String, Set<AuthorizationDetail>> consentedAuthorizationDetailsByType,
            final AuthorizationDetail requestedAuthorizationDetail) {

        if (!consentedAuthorizationDetailsByType.containsKey(requestedAuthorizationDetail.getType())) {
            log.debug("Request is not a rich authorization request. Skipping the validation.");
            return false;
        }

        final Optional<AuthorizationDetailsProcessor> provider = this.authorizationDetailsProviderFactory
                .getProviderByType(requestedAuthorizationDetail.getType());
        if (provider.isPresent()) {

            if (log.isDebugEnabled()) {
                log.debug("Validating equality of requested and existing authorization details " +
                        "using provider class: " + provider.get().getClass().getSimpleName());
            }

            final AuthorizationDetails existingAuthorizationDetails = new AuthorizationDetails(
                    consentedAuthorizationDetailsByType.get(requestedAuthorizationDetail.getType()));
            boolean isEqualOrSubset = provider.get()
                    .isEqualOrSubset(requestedAuthorizationDetail, existingAuthorizationDetails);

            if (log.isDebugEnabled() && isEqualOrSubset) {
                log.debug("User has already consented for the requested authorization details type: "
                        + requestedAuthorizationDetail.getType());
            }
            return isEqualOrSubset;
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Ignores unsupported authorization details type: %s",
                    requestedAuthorizationDetail.getType()));
        }
        return true;
    }
}
