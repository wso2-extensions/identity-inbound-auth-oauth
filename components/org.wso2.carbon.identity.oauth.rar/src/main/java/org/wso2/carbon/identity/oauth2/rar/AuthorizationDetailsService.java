package org.wso2.carbon.identity.oauth2.rar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.common.dao.AuthorizationDetailsDAO;
import org.wso2.carbon.identity.oauth2.rar.common.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProvider;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProviderFactory;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.rar.common.util.AuthorizationDetailsConstants.AUTHORIZATION_DETAILS_ID_PREFIX;

/**
 *
 */
public class AuthorizationDetailsService extends IdentityOAuth2AuthorizationDetailsService {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsService.class);
    private final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory;

    public AuthorizationDetailsService() {

        this(OAuthTokenPersistenceFactory.getInstance().getAuthorizationDetailsDAO(),
                AuthorizationDetailsProviderFactory.getInstance());
    }

    public AuthorizationDetailsService(final AuthorizationDetailsDAO authorizationDetailsDAO,
                                       final AuthorizationDetailsProviderFactory authorizationDetailsProviderFactory) {

        super(authorizationDetailsDAO);
        this.authorizationDetailsProviderFactory = authorizationDetailsProviderFactory;
    }

    public void storeUserConsentedAuthorizationDetails(final AuthenticatedUser authenticatedUser, final String clientId,
                                                       final OAuth2Parameters oAuth2Parameters,
                                                       final AuthorizationDetails userConsentedAuthorizationDetails)
            throws OAuthSystemException {

        if (!AuthorizationDetailsService.isRichAuthorizationRequest(oAuth2Parameters)) {
            return;
        }

        try {
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);

            if (consentId.isPresent()) {

                super.authorizationDetailsDAO.addUserConsentedAuthorizationDetails(
                        generateAuthorizationDetailsConsentDTOs(consentId.get(),
                                userConsentedAuthorizationDetails, tenantId));
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

        if (!AuthorizationDetailsService.isRichAuthorizationRequest(oAuth2Parameters)) {
            return;
        }

        try {
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);

            if (consentId.isPresent()) {

                super.authorizationDetailsDAO.updateUserConsentedAuthorizationDetails(
                        generateAuthorizationDetailsConsentDTOs(consentId.get(),
                                userConsentedAuthorizationDetails, tenantId));
            }
        } catch (SQLException | IdentityOAuth2Exception e) {
            log.error("Error occurred while updating user consented authorization details. Caused by, ", e);
            throw new OAuthSystemException("Error occurred while updating authorization details", e);
        }
    }

    public void deleteUserConsentedAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                        final String clientId, final OAuth2Parameters oAuth2Parameters)
            throws OAuthSystemException {

        if (!AuthorizationDetailsService.isRichAuthorizationRequest(oAuth2Parameters)) {
            return;
        }

        try {
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentId(authenticatedUser, clientId, tenantId);

            if (consentId.isPresent()) {

                super.authorizationDetailsDAO.deleteUserConsentedAuthorizationDetails(consentId.get(), tenantId);
            }
        } catch (SQLException | IdentityOAuth2Exception e) {
            log.error("Error occurred while deleting user consented authorization details. Caused by, ", e);
            throw new OAuthSystemException("Error occurred while storing authorization details", e);
        }
    }

    public void storeOrReplaceUserConsentedAuthorizationDetails(
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
     * @return True if user has given consent to all the requested  authorization details.
     */
    public boolean isUserAlreadyConsentedForAuthorizationDetails(final AuthenticatedUser authenticatedUser,
                                                                 final OAuth2Parameters oAuth2Parameters)
            throws OAuthSystemException {

        try {
            final String userId = this.getUserId(authenticatedUser);
            final String appId = this.getApplicationResourceIdFromClientId(oAuth2Parameters.getClientId());
            final int tenantId = OAuth2Util.getTenantId(oAuth2Parameters.getTenantDomain());
            final Optional<String> consentId = this.getConsentIdByUserIdAndAppId(userId, appId, tenantId);

            if (consentId.isPresent()) {
                final Set<AuthorizationDetailsConsentDTO> consentedAuthorizationDetailsDTOs =
                        super.authorizationDetailsDAO.getUserConsentedAuthorizationDetails(consentId.get(), tenantId);

                final Map<String, Set<AuthorizationDetail>> consentedAuthorizationDetailsByType =
                        consentedAuthorizationDetailsDTOs
                                .stream()
                                .filter(AuthorizationDetailsConsentDTO::isConsentActive)
                                .map(AuthorizationDetailsConsentDTO::getAuthorizationDetail)
                                .collect(Collectors.groupingBy(AuthorizationDetail::getType,
                                        Collectors.mapping(Function.identity(), Collectors.toSet())));

                for (final AuthorizationDetail requestedAuthorizationDetail :
                        oAuth2Parameters.getAuthorizationDetails().getDetails()) {

                    if (consentedAuthorizationDetailsByType.containsKey(requestedAuthorizationDetail.getType())) {

                        final Optional<AuthorizationDetailsProvider> provider = authorizationDetailsProviderFactory
                                .getProviderByType(requestedAuthorizationDetail.getType());
                        if (provider.isPresent()) {

                            final AuthorizationDetails existingAuthorizationDetails = new AuthorizationDetails(
                                    consentedAuthorizationDetailsByType.get(requestedAuthorizationDetail.getType()));
                            if (!provider.get()
                                    .isEqualOrSubset(requestedAuthorizationDetail, existingAuthorizationDetails)) {

                                if (log.isDebugEnabled()) {
                                    log.debug("User has not consented for the requested authorization details type: "
                                            + requestedAuthorizationDetail.getType());

                                }
                                return false;
                            }
                        }
                    }
                }
                return true;
            }
            return false;
        } catch (IdentityOAuth2Exception | SQLException e) {
            log.error("Error occurred while extracting user consented authorization details. Caused by, ", e);
            throw new OAuthSystemException("Error occurred while extracting user consented authorization details", e);
        }
    }

    /**
     * Retrieves the user-consented authorization details based on the provided parameter map and OAuth2 parameters.
     * <p>
     * This method is used to extract and return the authorization details that the user has consented to,
     * filtering them based on a provided authorization details in the parameter map.
     * </p>
     *
     * @param parameterMap     A map of query parameters.
     * @param oAuth2Parameters The OAuth2 parameters that include the details of the authorization request.
     * @return The {@link AuthorizationDetails} object containing the details the user has consented to.
     */
    public AuthorizationDetails getUserConsentedAuthorizationDetails(
            final Map<String, String[]> parameterMap, final OAuth2Parameters oAuth2Parameters) {

        if (!isRichAuthorizationRequest(oAuth2Parameters)) {
            return new AuthorizationDetails();
        }

        // Extract consented authorization detail IDs from the parameter map
        final Set<String> consentedAuthorizationDetailIDs = parameterMap.keySet().stream()
                .filter(parameterName -> parameterName.startsWith(AUTHORIZATION_DETAILS_ID_PREFIX))
                .map(parameterName -> parameterName.substring(AUTHORIZATION_DETAILS_ID_PREFIX.length()))
                .collect(Collectors.toSet());

        // Filter and collect the consented authorization details
        final Set<AuthorizationDetail> consentedAuthorizationDetails = oAuth2Parameters.getAuthorizationDetails()
                .stream()
                .filter(authorizationDetail -> consentedAuthorizationDetailIDs.contains(authorizationDetail.getId()))
                .collect(Collectors.toSet());

        return new AuthorizationDetails(consentedAuthorizationDetails);
    }

    public Optional<String> getConsentIdByUserIdAndAppId(final String userId, final String appId, final int tenantId)
            throws OAuthSystemException {

        try {
            return Optional
                    .ofNullable(super.authorizationDetailsDAO.getConsentIdByUserIdAndAppId(userId, appId, tenantId));
        } catch (SQLException e) {
            log.error(String.format("Error occurred while retrieving user consent by " +
                    "userId: %s and appId: %s. Caused by, ", userId, appId), e);
            throw new OAuthSystemException("Error occurred while retrieving user consent", e);
        }
    }

    private String getApplicationResourceIdFromClientId(final String clientId) throws IdentityOAuth2Exception {

        final ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
        if (serviceProvider != null) {
            return serviceProvider.getApplicationResourceId();
        }
        throw new IdentityOAuth2Exception("Unable to find a service provider for client Id: " + clientId);
    }

    private String getUserId(final AuthenticatedUser authenticatedUser) throws OAuthSystemException {
        try {
            return authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            log.error("Error occurred while extracting userId from authenticated user. Caused by, ", e);
            throw new OAuthSystemException(
                    "User id is not found for user: " + authenticatedUser.getLoggableMaskedUserId(), e);
        }
    }

    private List<AuthorizationDetailsConsentDTO> generateAuthorizationDetailsConsentDTOs(
            final String consentId, final AuthorizationDetails userConsentedAuthorizationDetails, final int tenantId) {

        return userConsentedAuthorizationDetails.stream()
                .map(authorizationDetail ->
                        new AuthorizationDetailsConsentDTO(consentId, authorizationDetail, true, tenantId))
                .collect(Collectors.toList());
    }

    private Optional<String> getConsentId(final AuthenticatedUser authenticatedUser, final String clientId,
                                          final int tenantId)
            throws OAuthSystemException, IdentityOAuth2Exception {

        final String userId = this.getUserId(authenticatedUser);
        final String appId = this.getApplicationResourceIdFromClientId(clientId);

        return this.getConsentIdByUserIdAndAppId(userId, appId, tenantId);
    }
}
