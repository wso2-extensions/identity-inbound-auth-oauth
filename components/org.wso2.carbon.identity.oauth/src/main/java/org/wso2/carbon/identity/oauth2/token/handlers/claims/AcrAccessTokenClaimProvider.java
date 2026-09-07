package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * A class that provides the ACR claim for JWT access tokens in authorization code and refresh token grant flows.
 */
public class AcrAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

    private static final String AUTHORIZATION_CODE = "AuthorizationCode";

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context) throws IdentityOAuth2Exception {

        String grantType = context.getOauth2AccessTokenReqDTO().getGrantType();
        String acrValue = null;

        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            String authCode = (String) context.getProperty(AUTHORIZATION_CODE);
            if (StringUtils.isNotEmpty(authCode)) {
                AuthorizationGrantCacheEntry entry = AuthorizationGrantCache.getInstance()
                        .getValueFromCacheByCode(new AuthorizationGrantCacheKey(authCode));
                if (entry != null) {
                    acrValue = entry.getSelectedAcrValue();
                }
            }
        } else if (OAuthConstants.GrantTypes.REFRESH_TOKEN.equalsIgnoreCase(grantType)) {
            RefreshTokenValidationDataDO prevToken =
                    (RefreshTokenValidationDataDO) context.getProperty(RefreshGrantHandler.PREV_ACCESS_TOKEN);
            if (prevToken != null) {
                AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(prevToken.getAccessToken());
                AuthorizationGrantCacheEntry entry = AuthorizationGrantCache.getInstance()
                        .getValueFromCacheByTokenId(key, prevToken.getTokenId());
                if (entry != null) {
                    acrValue = entry.getSelectedAcrValue();
                }
            }
        }

        if (StringUtils.isNotEmpty(acrValue)) {
            Map<String, Object> claims = new HashMap<>();
            claims.put(OAuthConstants.ACR, acrValue);
            return claims;
        }
        return null;
    }
}