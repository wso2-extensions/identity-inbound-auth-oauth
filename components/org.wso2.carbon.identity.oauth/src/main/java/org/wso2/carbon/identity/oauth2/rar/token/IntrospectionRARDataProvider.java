package org.wso2.carbon.identity.oauth2.rar.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.rar.validator.AuthorizationDetailsValidator;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants.AUTHORIZATION_DETAILS;

/**
 * Class responsible for modifying the introspection response to include user-consented authorization details.
 *
 * <p>This class enhances the introspection response by appending user-consented authorization details.
 * It is invoked by the /introspect endpoint of the oauth.endpoint webapp during the token introspection process.</p>
 */
public class IntrospectionRARDataProvider implements IntrospectionDataProvider {

    private static final Log log = LogFactory.getLog(IntrospectionRARDataProvider.class);
    private final AuthorizationDetailsValidator authorizationDetailsValidator;

    public IntrospectionRARDataProvider() {

        this(OAuth2ServiceComponentHolder.getInstance().getAuthorizationDetailsValidator());
    }

    public IntrospectionRARDataProvider(final AuthorizationDetailsValidator authorizationDetailsValidator) {

        this.authorizationDetailsValidator = authorizationDetailsValidator;
    }

    /**
     * Provides additional Rich Authorization Requests data for OAuth token introspection.
     *
     * @param tokenValidationRequestDTO Token validation request DTO.
     * @param introspectionResponseDTO  Token introspection response DTO.
     * @return Map of additional data to be added to the introspection response.
     * @throws IdentityOAuth2Exception If an error occurs while setting additional introspection data.
     */
    @Override
    public Map<String, Object> getIntrospectionData(
            final OAuth2TokenValidationRequestDTO tokenValidationRequestDTO,
            final OAuth2IntrospectionResponseDTO introspectionResponseDTO) throws IdentityOAuth2Exception {

        final Map<String, Object> introspectionData = new HashMap<>();
        final OAuth2TokenValidationMessageContext tokenValidationMessageContext =
                generateOAuth2TokenValidationMessageContext(tokenValidationRequestDTO, introspectionResponseDTO);

        if (Objects.nonNull(tokenValidationMessageContext)) {

            final AuthorizationDetails validatedAuthorizationDetails = this.authorizationDetailsValidator
                    .getValidatedAuthorizationDetails(tokenValidationMessageContext);
            if (AuthorizationDetailsUtils.isRichAuthorizationRequest(validatedAuthorizationDetails)) {

                introspectionData.put(AUTHORIZATION_DETAILS, validatedAuthorizationDetails.toSet());
            }
        }
        return introspectionData;
    }

    /**
     * Generates an OAuth2TokenValidationMessageContext based on the token validation request and
     * introspection response.
     *
     * @param tokenValidationRequestDTO The OAuth2 token validation request DTO.
     * @param introspectionResponseDTO  The OAuth2 introspection response DTO.
     * @return The generated OAuth2TokenValidationMessageContext.
     * @throws IdentityOAuth2Exception If an error occurs during the generation of the context.
     */
    private OAuth2TokenValidationMessageContext generateOAuth2TokenValidationMessageContext(
            final OAuth2TokenValidationRequestDTO tokenValidationRequestDTO,
            final OAuth2IntrospectionResponseDTO introspectionResponseDTO) throws IdentityOAuth2Exception {

        // Check if the introspection response contains a validation message context
        if (introspectionResponseDTO.getProperties().containsKey(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT)) {
            log.debug("Introspection response contains a validation message context.");

            final Object oAuth2TokenValidationMessageContext = introspectionResponseDTO.getProperties()
                    .get(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT);

            if (oAuth2TokenValidationMessageContext instanceof OAuth2TokenValidationMessageContext) {
                return (OAuth2TokenValidationMessageContext) oAuth2TokenValidationMessageContext;
            }
        } else {
            // Create a new validation message context
            final OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext =
                    new OAuth2TokenValidationMessageContext(tokenValidationRequestDTO,
                            generateOAuth2TokenValidationResponseDTO(introspectionResponseDTO));

            final AccessTokenDO accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(tokenValidationRequestDTO.getAccessToken().getIdentifier(), false);

            oAuth2TokenValidationMessageContext.addProperty(OAuthConstants.ACCESS_TOKEN_DO, accessTokenDO);

            return oAuth2TokenValidationMessageContext;
        }

        log.debug("OAuth2TokenValidationMessageContext could not be generated. returning null");
        return null;
    }

    private OAuth2TokenValidationResponseDTO generateOAuth2TokenValidationResponseDTO(
            final OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO) {

        final OAuth2TokenValidationResponseDTO tokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        tokenValidationResponseDTO.setValid(oAuth2IntrospectionResponseDTO.isActive());
        tokenValidationResponseDTO.setErrorMsg(oAuth2IntrospectionResponseDTO.getError());
        tokenValidationResponseDTO.setScope(OAuth2Util.buildScopeArray(oAuth2IntrospectionResponseDTO.getScope()));
        tokenValidationResponseDTO.setExpiryTime(oAuth2IntrospectionResponseDTO.getExp());

        return tokenValidationResponseDTO;
    }
}
