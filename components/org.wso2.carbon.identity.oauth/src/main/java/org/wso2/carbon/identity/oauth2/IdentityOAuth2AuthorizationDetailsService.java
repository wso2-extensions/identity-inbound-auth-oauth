package org.wso2.carbon.identity.oauth2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.common.dao.AuthorizationDetailsDAO;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.SQLException;
import java.util.Objects;

/**
 * IdentityOAuth2AuthorizationDetailsService is responsible for managing and handling OAuth2 authorization details,
 * specifically in the context of rich authorization requests.
 * <p>
 * This class integrates with the {@link AuthorizationDetailsDAO} to persist these details in the underlying data store.
 * It also provides utility methods to check if a request contains rich authorization details.
 * </p>
 *
 * @see AuthorizationDetailsDAO
 * @see AuthorizationDetails
 */
public class IdentityOAuth2AuthorizationDetailsService {

    private static final Log log = LogFactory.getLog(IdentityOAuth2AuthorizationDetailsService.class);
    protected final AuthorizationDetailsDAO authorizationDetailsDAO;

    /**
     * Default constructor that initializes the service with the default {@link AuthorizationDetailsDAO}.
     * <p>
     * This constructor uses the default DAO provided by the {@link OAuthTokenPersistenceFactory}
     * to handle the persistence of authorization details.
     * </p>
     */
    public IdentityOAuth2AuthorizationDetailsService() {

        this(OAuthTokenPersistenceFactory.getInstance().getAuthorizationDetailsDAO());
    }

    /**
     * Constructor that initializes the service with a given {@link AuthorizationDetailsDAO}.
     *
     * @param authorizationDetailsDAO The {@link AuthorizationDetailsDAO} instance to be used for
     *                                handling authorization details persistence. Must not be {@code null}.
     */
    public IdentityOAuth2AuthorizationDetailsService(final AuthorizationDetailsDAO authorizationDetailsDAO) {

        this.authorizationDetailsDAO = Objects
                .requireNonNull(authorizationDetailsDAO, "AuthorizationDetailsDAO must not be null");
    }

    /**
     * Determines if the given {@link OAuthAuthzReqMessageContext} object contains {@link AuthorizationDetails}.
     *
     * @param oAuthAuthzReqMessageContext The requested OAuthAuthzReqMessageContext to check.
     * @return {@code true} if the OAuthAuthzReqMessageContext contains non-empty authorization details set,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        return isRichAuthorizationRequest(oAuthAuthzReqMessageContext.getAuthorizationDetails());
    }

    /**
     * Determines if the request is a rich authorization request using provided {@link AuthorizationDetails} object.
     * <p>
     * This method checks if the specified {@link AuthorizationDetails} instance is not {@code null}
     * and has a non-empty details set.
     *
     * @param authorizationDetails The {@link AuthorizationDetails} to check.
     * @return {@code true} if the {@link AuthorizationDetails} is not {@code null} and has a non-empty details set,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final AuthorizationDetails authorizationDetails) {

        return authorizationDetails != null && !authorizationDetails.getDetails().isEmpty();
    }

    /**
     * Determines if the given {@link OAuth2Parameters} object contains {@link AuthorizationDetails}.
     *
     * @param oAuth2Parameters The requested OAuth2Parameters to check.
     * @return {@code true} if the OAuth2Parameters contains non-empty authorization details set,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuth2Parameters oAuth2Parameters) {

        return isRichAuthorizationRequest(oAuth2Parameters.getAuthorizationDetails());
    }

    /**
     * Stores the OAuth2 code authorization details if the request is a rich authorization request.
     * <p>
     * This method checks whether the given {@link OAuthAuthzReqMessageContext} contains {@link AuthorizationDetails}.
     * If it does, it retrieves the tenant ID from the request context and stores the authorization
     * details using the {@link AuthorizationDetailsDAO}.
     * </p>
     *
     * @param authzCodeDO                 The {@link AuthzCodeDO} object containing the authorization code details.
     * @param oAuthAuthzReqMessageContext The {@link OAuthAuthzReqMessageContext} containing the request context.
     * @throws IdentityOAuth2Exception If an error occurs while storing the authorization details.
     */
    public void storeOAuth2CodeAuthorizationDetails(final AuthzCodeDO authzCodeDO,
                                                    final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (!isRichAuthorizationRequest(oAuthAuthzReqMessageContext)) {
            log.debug("Request is not a rich authorization request. Skipping storage of code authorization details.");
            return;
        }

        try {
            final int tenantID = OAuth2Util.getTenantId(
                    oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain());
            // Storing the authorization details.
            this.authorizationDetailsDAO.addOAuth2CodeAuthorizationDetails(
                    authzCodeDO.getAuthzCodeId(),
                    oAuthAuthzReqMessageContext.getAuthorizationDetails(),
                    tenantID);

            if (log.isDebugEnabled()) {
                log.debug("Successfully stored OAuth2 Code authorization details for code Id: " +
                        authzCodeDO.getAuthzCodeId());
            }
        } catch (SQLException e) {
            log.error("Error occurred while storing OAuth2 Code authorization details. Caused by, ", e);
            throw new IdentityOAuth2Exception("Error occurred while storing authorization details", e);
        }
    }
}
