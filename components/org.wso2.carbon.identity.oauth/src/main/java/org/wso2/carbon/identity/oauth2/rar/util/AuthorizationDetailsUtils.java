package org.wso2.carbon.identity.oauth2.rar.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthTokenRequest;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsCodeDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import static java.util.function.Function.identity;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toSet;
import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants.AUTHORIZATION_DETAILS_ID_PREFIX;

/**
 * Utility class for handling and validating authorization details in OAuth2 requests.
 */
public class AuthorizationDetailsUtils {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsUtils.class);

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

        return !isEmpty(authorizationDetails);
    }

    /**
     * Determines if the provided {@link AuthorizationDetails} object is empty or not.
     * <p>
     * This method checks if the specified {@link AuthorizationDetails} instance is not {@code null}
     * and has a non-empty details set.
     *
     * @param authorizationDetails The {@link AuthorizationDetails} to check.
     * @return {@code true} if the {@link AuthorizationDetails} is not {@code null} and has a non-empty details set,
     * {@code false} otherwise.
     */
    public static boolean isEmpty(final AuthorizationDetails authorizationDetails) {

        return authorizationDetails == null || authorizationDetails.getDetails().isEmpty();
    }

    /**
     * Determines if the given {@link OAuthAuthzRequest} object contains {@code authorization_details}.
     *
     * @param oauthRequest The OAuth Authorization Request to check.
     * @return {@code true} if the OAuth authorization request contains a non-blank authorization details parameter,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuthAuthzRequest oauthRequest) {

        return StringUtils.isNotBlank(oauthRequest.getParam(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS));
    }

    /**
     * Determines if the given {@link CarbonOAuthTokenRequest} object contains {@code authorization_details}.
     *
     * @param carbonOAuthTokenRequest The OAuth Token Request to check.
     * @return {@code true} if the OAuth token request contains a non-blank authorization details parameter,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final CarbonOAuthTokenRequest carbonOAuthTokenRequest) {

        return StringUtils
                .isNotBlank(carbonOAuthTokenRequest.getParam(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS));
    }

    /**
     * Determines if the given {@link OAuthTokenReqMessageContext} object or the
     * {@link OAuthTokenReqMessageContext#getOauth2AccessTokenReqDTO} contains {@link AuthorizationDetails}.
     *
     * @param oAuthTokenReqMessageContext The requested oAuthTokenReqMessageContext to check.
     * @return {@code true} if the oAuthTokenReqMessageContext contains non-empty authorization details set,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuthTokenReqMessageContext oAuthTokenReqMessageContext) {

        return isRichAuthorizationRequest(oAuthTokenReqMessageContext.getAuthorizationDetails()) ||
                isRichAuthorizationRequest(oAuthTokenReqMessageContext
                        .getOauth2AccessTokenReqDTO().getAuthorizationDetails());
    }

    /**
     * Retrieves the application resource ID from the client ID.
     *
     * @param clientId The client ID.
     * @return The application resource ID.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving the application resource ID.
     */
    public static String getApplicationResourceIdFromClientId(final String clientId) throws IdentityOAuth2Exception {

        final ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
        if (serviceProvider != null) {
            return serviceProvider.getApplicationResourceId();
        }
        throw new IdentityOAuth2Exception("Unable to find a service provider for client Id: " + clientId);
    }

    /**
     * Retrieves the user ID from the authenticated user.
     *
     * @param authenticatedUser The authenticated user.
     * @return The user ID.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving the user ID.
     */
    public static String getIdFromAuthenticatedUser(final AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        try {
            return authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            log.error("Error occurred while extracting userId from authenticated user. Caused by, ", e);
            throw new IdentityOAuth2Exception(
                    "User id is not found for user: " + authenticatedUser.getLoggableMaskedUserId(), e);
        }
    }

    /**
     * Generates a set of {@link AuthorizationDetailsConsentDTO} from the provided consent ID,
     * authorization details, and tenant ID.
     *
     * @param consentId                         The consent ID.
     * @param userConsentedAuthorizationDetails The user-consented authorization details.
     * @param tenantId                          The tenant ID.
     * @return A list of {@link AuthorizationDetailsConsentDTO}.
     */
    public static Set<AuthorizationDetailsConsentDTO> getAuthorizationDetailsConsentDTOs(
            final String consentId, final AuthorizationDetails userConsentedAuthorizationDetails, final int tenantId) {

        return userConsentedAuthorizationDetails.stream()
                .map(detail -> new AuthorizationDetailsConsentDTO(consentId, detail, true, tenantId))
                .collect(toSet());
    }

    /**
     * Generates a set of {@link AuthorizationDetailsTokenDTO} from the provided access token and
     * authorization details.
     *
     * @param accessTokenDO        The access token data object.
     * @param authorizationDetails The user-consented authorization details.
     * @return A list of {@link AuthorizationDetailsTokenDTO}.
     */
    public static Set<AuthorizationDetailsTokenDTO> getAccessTokenAuthorizationDetailsDTOs(
            final AccessTokenDO accessTokenDO, final AuthorizationDetails authorizationDetails) {

        return authorizationDetails
                .stream()
                .map(authorizationDetail -> new AuthorizationDetailsTokenDTO(
                        accessTokenDO.getTokenId(), authorizationDetail, accessTokenDO.getTenantID()))
                .collect(toSet());
    }

    /**
     * Generates a set of {@link AuthorizationDetailsCodeDTO} from the provided access token and
     * authorization details.
     *
     * @param authzCodeDO          The authorization code data object.
     * @param authorizationDetails The user-consented authorization details.
     * @return A list of {@link AuthorizationDetailsTokenDTO}.
     */
    public static Set<AuthorizationDetailsCodeDTO> getCodeAuthorizationDetailsDTOs(
            final AuthzCodeDO authzCodeDO, final AuthorizationDetails authorizationDetails, final int tenantId) {

        return authorizationDetails
                .stream()
                .map(authorizationDetail ->
                        new AuthorizationDetailsCodeDTO(authzCodeDO.getAuthzCodeId(), authorizationDetail, tenantId))
                .collect(toSet());
    }

    /**
     * Extracts the user-consented authorization details from the request parameters and OAuth2 parameters.
     *
     * @param httpServletRequest The HTTP servlet request containing the authorization details.
     * @param oAuth2Parameters   The OAuth2 parameters that include the authorization details.
     * @return The {@link AuthorizationDetails} containing the user-consented authorization details.
     */
    public static AuthorizationDetails extractAuthorizationDetailsFromRequest(
            final HttpServletRequest httpServletRequest, final OAuth2Parameters oAuth2Parameters) {

        if (!AuthorizationDetailsUtils.isRichAuthorizationRequest(oAuth2Parameters)) {
            log.debug("Request is not a rich authorization request. Returning empty authorization details.");
            return new AuthorizationDetails();
        }

        // Extract consented authorization detail IDs from the parameter map
        final Set<String> consentedAuthorizationDetailIDs = httpServletRequest.getParameterMap().keySet().stream()
                .filter(parameterName -> parameterName.startsWith(AUTHORIZATION_DETAILS_ID_PREFIX))
                .map(parameterName -> parameterName.substring(AUTHORIZATION_DETAILS_ID_PREFIX.length()))
                .collect(toSet());

        // Filter and collect the consented authorization details
        final AuthorizationDetails consentedAuthorizationDetails = new AuthorizationDetails(oAuth2Parameters
                .getAuthorizationDetails()
                .stream()
                .filter(authorizationDetail -> consentedAuthorizationDetailIDs.contains(authorizationDetail.getId()))
                .collect(toSet()));

        log.debug("User consented authorization details extracted successfully.");

        oAuth2Parameters.setAuthorizationDetails(consentedAuthorizationDetails);
        return consentedAuthorizationDetails;
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
     * Transforms the given {@link AuthorizationDetails} by creating a new set of {@link AuthorizationDetail} objects
     * with only the displayable fields ({@code type}, {@code id}, {@code description}) copied over.
     *
     * @param authorizationDetails The original AuthorizationDetails to be transformed.
     * @return A new {@link AuthorizationDetails} object containing the displayable authorization details.
     */
    public static AuthorizationDetails getDisplayableAuthorizationDetails(
            final AuthorizationDetails authorizationDetails) {

        final Set<AuthorizationDetail> displayableAuthorizationDetails = authorizationDetails.stream()
                .map(protectedAuthorizationDetail -> {
                    final AuthorizationDetail authorizationDetail = new AuthorizationDetail();
                    authorizationDetail.setId(protectedAuthorizationDetail.getId());
                    authorizationDetail.setType(protectedAuthorizationDetail.getType());
                    authorizationDetail.setDescription(protectedAuthorizationDetail.getDescription());
                    return authorizationDetail;
                }).collect(toSet());

        return new AuthorizationDetails(displayableAuthorizationDetails);
    }

    /**
     * Trims the given {@link AuthorizationDetails} by setting the temporary {@code id} and {@code consentDescription}
     * fields to null for each {@link AuthorizationDetail}.
     *
     * @param authorizationDetails The original AuthorizationDetails to be trimmed.
     * @return The same AuthorizationDetails object with trimmed fields.
     */
    public static AuthorizationDetails getTrimmedAuthorizationDetails(final AuthorizationDetails authorizationDetails) {

        if (authorizationDetails != null) {
            authorizationDetails.stream().forEach(authorizationDetail -> {
                authorizationDetail.setId(null);
                authorizationDetail.setDescription(null);
            });
        }
        return authorizationDetails;
    }

    /**
     * Generates unique IDs for each {@link AuthorizationDetail} within the given {@link AuthorizationDetails} object.
     *
     * @param authorizationDetails The AuthorizationDetails object containing a set of AuthorizationDetail objects.
     * @return The AuthorizationDetails object with unique IDs assigned to each AuthorizationDetail.
     */
    public static AuthorizationDetails assignUniqueIDsToAuthorizationDetails(
            final AuthorizationDetails authorizationDetails) {

        authorizationDetails.stream().filter(Objects::nonNull)
                .forEach(authorizationDetail -> authorizationDetail.setId(UUID.randomUUID().toString()));
        return authorizationDetails;
    }

    /**
     * Encodes the given AuthorizationDetails object to a URL-encoded JSON string.
     *
     * @param authorizationDetails The AuthorizationDetails object to be encoded.
     * @return A URL-encoded JSON string representing the authorization details.
     */
    public static String getUrlEncodedAuthorizationDetails(final AuthorizationDetails authorizationDetails) {

        if (log.isDebugEnabled()) {
            log.debug("Starts URL encoding authorization details: " + authorizationDetails.toJsonString());
        }
        if (isRichAuthorizationRequest(authorizationDetails)) {
            return URLEncoder.encode(authorizationDetails.toJsonString(), StandardCharsets.UTF_8);
        }
        return StringUtils.EMPTY;
    }

    /**
     * Decodes the given URL-encoded AuthorizationDetails JSON String.
     *
     * @param encodedAuthorizationDetails The encoded AuthorizationDetails String to be decoded.
     * @return A URL-decoded JSON string representing the authorization details.
     */
    public static String getUrlDecodedAuthorizationDetails(final String encodedAuthorizationDetails) {

        if (log.isDebugEnabled()) {
            log.debug("Starts decoding URL encoded authorization details JSON: " + encodedAuthorizationDetails);
        }
        if (StringUtils.isNotEmpty(encodedAuthorizationDetails)) {
            return URLDecoder.decode(encodedAuthorizationDetails, StandardCharsets.UTF_8);
        }
        return StringUtils.EMPTY;
    }

    public static void setRARPropertiesToAuthzRequestContext(
            final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = oAuthAuthzReqMessageContext.getAuthorizationReqDTO();
        if (!AuthorizationDetailsUtils.isRichAuthorizationRequest(oAuth2AuthorizeReqDTO)) {
            if (log.isDebugEnabled()) {
                log.debug("Request is not a rich authorization request. " +
                        "Skips adding authorization details to OAuthAuthzReqMessageContext");
            }
            return;
        }

        final AuthorizationDetails authorizationDetails = OAuth2ServiceComponentHolder.getInstance()
                .getAuthorizationDetailsService()
                .getUserConsentedAuthorizationDetails(
                        oAuth2AuthorizeReqDTO.getUser(),
                        oAuth2AuthorizeReqDTO.getConsumerKey(),
                        IdentityTenantUtil.getTenantId(oAuth2AuthorizeReqDTO.getTenantDomain())
                );

        if (authorizationDetails != null) {
            oAuthAuthzReqMessageContext.setAuthorizationDetails(authorizationDetails);
        }
    }

    /**
     * Determines if the given {@link OAuth2AuthorizeReqDTO} object contains {@link AuthorizationDetails}.
     *
     * @param oAuth2AuthorizeReqDTO The requested oAuth2AuthorizeReqDTO to check.
     * @return {@code true} if the oAuth2AuthorizeReqDTO contains non-empty authorization details set,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO) {

        return isRichAuthorizationRequest(oAuth2AuthorizeReqDTO.getAuthorizationDetails());
    }

    /**
     * Converts a list of AuthorizationDetails into a map with the type as the key.
     *
     * @param authorizationDetails {@link AuthorizationDetails} instance to be converted.
     * @return A map where the key is the type and the value is the corresponding AuthorizationDetails object.
     */
    public static Map<String, Set<AuthorizationDetail>> getAuthorizationDetailsTypesMap(
            final AuthorizationDetails authorizationDetails) {

        return authorizationDetails == null ? Collections.emptyMap()
                : authorizationDetails.stream()
                .collect(groupingBy(AuthorizationDetail::getType, mapping(identity(), toSet())));
    }
}
