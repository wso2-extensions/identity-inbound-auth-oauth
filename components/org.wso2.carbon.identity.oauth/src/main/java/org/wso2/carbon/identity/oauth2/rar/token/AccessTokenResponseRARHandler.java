package org.wso2.carbon.identity.oauth2.rar.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.response.AccessTokenResponseHandler;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils.isRichAuthorizationRequest;

/**
 * Class responsible for modifying the access token response to include user-consented authorization details.
 *
 * <p>This class enhances the access token response by appending user-consented authorization details.
 * It is invoked by the {@link org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer#issue} method during
 * the OAuth 2.0 token issuance process.</p>
 */
public class AccessTokenResponseRARHandler implements AccessTokenResponseHandler {

    private static final Log log = LogFactory.getLog(AccessTokenResponseRARHandler.class);

    /**
     * Returns Rich Authorization Request attributes to be added to the access token response.
     *
     * @param oAuthTokenReqMessageContext {@link OAuthTokenReqMessageContext} token request message context.
     * @return Map of additional attributes to be added to the token response.
     * @throws IdentityOAuth2Exception Error while constructing additional token response attributes.
     */
    @Override
    public Map<String, Object> getAdditionalTokenResponseAttributes(
            final OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

        Map<String, Object> additionalAttributes = new HashMap<>();
        if (isRichAuthorizationRequest(oAuthTokenReqMessageContext.getAuthorizationDetails())) {

            if (log.isDebugEnabled()) {
                log.debug("Adding authorization details into the token response: " + oAuthTokenReqMessageContext
                        .getAuthorizationDetails().toReadableText());
            }
            additionalAttributes.put(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS,
                    oAuthTokenReqMessageContext.getAuthorizationDetails().toSet());
        }
        return additionalAttributes;
    }
}
