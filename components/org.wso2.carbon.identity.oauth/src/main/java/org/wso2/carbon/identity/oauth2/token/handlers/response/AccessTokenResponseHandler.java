package org.wso2.carbon.identity.oauth2.token.handlers.response;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

/**
 * This interface needs to be implemented if there are access token response modification requirements.
 */
public interface AccessTokenResponseHandler {

    /**
     * Returns additional token response attributes to be added to the access token response.
     *
     * @param tokReqMsgCtx {@link OAuthTokenReqMessageContext} token request message context
     * @return Map of additional attributes to be added
     * @throws IdentityOAuth2Exception Error while constructing additional token response attributes
     */
    Map<String, String> getAdditionalTokenResponseAttributes(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception;
}
