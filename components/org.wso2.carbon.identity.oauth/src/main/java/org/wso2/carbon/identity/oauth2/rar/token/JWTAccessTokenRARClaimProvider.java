package org.wso2.carbon.identity.oauth2.rar.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Provides additional claims related to Rich Authorization Requests to be included in JWT Access Tokens.
 * This implementation supports both the OAuth2 authorization and token flows.
 */
public class JWTAccessTokenRARClaimProvider implements JWTAccessTokenClaimProvider {

    private static final Log log = LogFactory.getLog(JWTAccessTokenRARClaimProvider.class);

    /**
     * Returns a map of additional claims related to Rich Authorization Requests to be included in
     * JWT Access Tokens issued in the OAuth2 authorize flow.
     *
     * @param oAuthAuthzReqMessageContext The OAuth authorization request message context.
     * @return A map of additional claims.
     * @throws IdentityOAuth2Exception If an error occurs during claim retrieval.
     */
    @Override
    public Map<String, Object> getAdditionalClaims(final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {

        final Map<String, Object> additionalClaims = new HashMap<>();
        if (AuthorizationDetailsUtils.isRichAuthorizationRequest(oAuthAuthzReqMessageContext)) {
            if (log.isDebugEnabled()) {
                log.debug("Processing Rich Authorization Request in authorization flow. authorization_details: " +
                        oAuthAuthzReqMessageContext.getAuthorizationDetails().toJsonString());
            }
            additionalClaims.put(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS,
                    oAuthAuthzReqMessageContext.getAuthorizationDetails().toSet());
        }
        return additionalClaims;
    }

    /**
     * Returns a map of additional claims related to Rich Authorization Requests to be included in
     * JWT Access Tokens issued in the OAuth2 token flow.
     *
     * @param oAuthTokenReqMessageContext The OAuth token request message context.
     * @return A map of additional claims.
     * @throws IdentityOAuth2Exception If an error occurs during claim retrieval.
     */
    @Override
    public Map<String, Object> getAdditionalClaims(final OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        final Map<String, Object> additionalClaims = new HashMap<>();
        if (AuthorizationDetailsUtils.isRichAuthorizationRequest(oAuthTokenReqMessageContext)) {
            if (log.isDebugEnabled()) {
                log.debug("Processing Rich Authorization Request in token flow.authorization_details: " +
                        oAuthTokenReqMessageContext.getAuthorizationDetails().toJsonString());
            }
            additionalClaims.put(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS,
                    oAuthTokenReqMessageContext.getAuthorizationDetails().toSet());
        }
        return additionalClaims;
    }
}
