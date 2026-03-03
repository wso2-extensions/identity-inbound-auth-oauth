/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.RevokedTokenPersistenceDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;

/**
 * Refresh token grant processor to handle jwt refresh tokens during in memory token persistence scenarios. Works with
 * both migrated Opaque refresh tokens and JWTs. When issuing new access token, this does not update the
 * AuthorizationGrantCache, since old access token cannot be invalidated.
 */
public class HybridRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log LOG = LogFactory.getLog(HybridRefreshTokenGrantProcessor.class);
    private final DefaultRefreshTokenGrantProcessor defaultRefreshTokenGrantProcessor =
            new DefaultRefreshTokenGrantProcessor();
    private final RevokedTokenPersistenceDAO revokedTokenDao =
            OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO();

    /**
     * Validate the refresh token and return the validation data.
     *
     * @param tokenReqMessageContext The OAuth token request message context.
     * @return RefreshTokenValidationDataDO containing the validation data of the refresh token.
     * @throws IdentityOAuth2Exception If an error occurs while validating the refresh token.
     */
    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        HybridPersistenceTokenProvider hybridPersistenceTokenProvider = new HybridPersistenceTokenProvider();
        RefreshTokenValidationDataDO validationBean = hybridPersistenceTokenProvider.getVerifiedRefreshToken
                (tokenReq.getRefreshToken(), tokenReq.getClientId());
        if (validationBean == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Invalid Refresh Token provided for Client with Client Id : %s",
                        tokenReq.getClientId()));
            }
            throw new IdentityOAuth2Exception("Valid refresh token data not found");
        }
        return validationBean;
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                                String userStoreDomain, String clientId) throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO oldRefreshToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(OAuth2Constants.PREV_ACCESS_TOKEN);
        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                LOG.debug(String.format("Invalidating previous refresh token (hashed): %s",
                        DigestUtils.sha256Hex(oldRefreshToken.getRefreshToken())));
            } else {
                LOG.debug("Invalidating previous refresh token.");
            }
        }
        // Retrieve the OAuth application configuration. This will internally check the cache first.
        Optional<OAuthAppDO> oAuthAppDO = getOAuthApp(tokenReq.getClientId());

        if (oAuthAppDO.isPresent()) {
            // Check if the application is configured to renew the refresh token during token rotation.
            if (isRenewRefreshToken(oAuthAppDO.get().getRenewRefreshTokenEnabled())) {

                if (OAuth2Util.isRefreshTokenPersistenceEnabled()) {
                    // Invalidate the old refresh token and create a new one within a single DB operation.
                    new RefreshTokenDAOImpl().invalidateAndCreateNewRefreshToken(
                            oldRefreshToken.getTokenId(),                        // Old refresh token ID
                            OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE,    // Mark old token as INACTIVE
                            clientId,                                            // Client ID
                            accessTokenBean,                                     // New access token details
                            userStoreDomain                                      // Associated user store domain
                    );
                } else {
                    revokedTokenDao.addRevokedToken(oldRefreshToken.getRefreshToken(), clientId,
                            oAuthAppDO.get().getRefreshTokenExpiryTime());
                }
            }
        } else {
            // Log debug message if OAuth app is not found, and throw an exception.
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("OAuth App not found for Client Id: %s", tokenReq.getClientId()));
            }
            throw new IdentityOAuth2Exception("OAuth App not found for Client Id: " + tokenReq.getClientId());
        }
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean, String tokenType)
            throws IdentityOAuth2Exception {

        String tokenId = UUID.randomUUID().toString();

        // Retrieve the OAuth application configuration. This will internally check the cache first.
        Optional<OAuthAppDO> oAuthAppDO = getOAuthApp(tokenReq.getClientId());

        if (oAuthAppDO.isPresent()) {
            // Check if the application is configured to renew the refresh token during token rotation.
            if (!isRenewRefreshToken(oAuthAppDO.get().getRenewRefreshTokenEnabled())) {
                tokenId = validationBean.getTokenId();
            }
        } else {
            // Log debug message if OAuth app is not found, and throw an exception.
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("OAuth App not found for Client Id: %s", tokenReq.getClientId()));
            }
            throw new IdentityOAuth2Exception("OAuth App not found for Client Id: " + tokenReq.getClientId());
        }

        Timestamp timestamp = new Timestamp(new Date().getTime());
        tokReqMsgCtx.setTokenId(tokenId);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(tokenType);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());
        accessTokenDO.setNotPersisted(true);

        String previousGrantType = validationBean.getGrantType();
        // Check if the previous grant type is consent refresh token type or not.
        if (!StringUtils.equals(OAuthConstants.GrantTypes.REFRESH_TOKEN, previousGrantType)) {
            // If the previous grant type is not a refresh token, then check if it's a consent token or not.
            if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(previousGrantType)) {
                accessTokenDO.setIsConsentedToken(true);
                tokReqMsgCtx.setConsentedToken(true);
            }
        } else {
            if (validationBean.isConsented()) {
                tokReqMsgCtx.setConsentedToken(true);
                accessTokenDO.setIsConsentedToken(true);
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting access token extended attributes for token request in refresh token flow for client: "
                    + tokenReq.getClientId() + " with token id: " + tokenId);
        }
        if (tokenReq.getAccessTokenExtendedAttributes() != null &&
                tokenReq.getAccessTokenExtendedAttributes().getParameters() != null) {
            accessTokenDO.setAccessTokenExtendedAttributes(
                    new AccessTokenExtendedAttributes(
                            new HashMap<>(tokenReq.getAccessTokenExtendedAttributes().getParameters())));
        }
        return accessTokenDO;
    }

    @Override
    public boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
                                        String userStoreDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Checking if the provided refresh token is the latest one in non-persistence scenario. " +
                    "There can be only one refresh token active per user + client + scope combination.");
        }
        return true;
    }

    /**
     * Evaluate if renew refresh token.
     *
     * @param renewRefreshToken Renew refresh token config value from OAuthApp.
     * @return Evaluated refresh token state
     */
    private boolean isRenewRefreshToken(String renewRefreshToken) {

        if (StringUtils.isNotBlank(renewRefreshToken)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Reading the Oauth application specific renew refresh token value as " + renewRefreshToken
                        + " from the IDN_OIDC_PROPERTY table.");
            }
            return Boolean.parseBoolean(renewRefreshToken);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Reading the global renew refresh token value from the identity.xml");
            }
            return OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();
        }
    }

    @Override
    public void addUserAttributesToCache(AccessTokenDO accessTokenBean, OAuthTokenReqMessageContext msgCtx)
            throws IdentityOAuth2Exception {

        // Default refresh token grant processor used to add user attributes to cache, because it can handle
        // non-persistence scenarios also.
        defaultRefreshTokenGrantProcessor.addUserAttributesToCache(accessTokenBean, msgCtx);
    }

    /**
     * Get the OAuthAppDO for the provided client id. Assumes that client id is unique across tenants.
     *
     * @param clientId Client Id
     * @return OAuthAppDO for the provided client id. Null if the client id is not found.
     * @throws IdentityOAuth2Exception Error while retrieving the OAuthAppDO.
     */
    private Optional<OAuthAppDO> getOAuthApp(String clientId) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Retrieved OAuth application : " + clientId + ". Authorized user : "
                        + oAuthAppDO.getAppOwner().toString());
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " + clientId,
                    e);
        }
        return Optional.ofNullable(oAuthAppDO);
    }
}
