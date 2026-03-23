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

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Non-persistent implementation of AccessTokenDAO.
 * This implementation does not persist any access token data to the database.
 * All methods are no-op and return null or empty collections where applicable.
 */
public class NonPersistentAccessTokenDAOImpl implements AccessTokenDAO {

    private static final Log LOG = LogFactory.getLog(NonPersistentAccessTokenDAOImpl.class);
    private final RefreshTokenDAO refreshTokenDAO = new RefreshTokenDAOImpl();

    @Override
    public void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                  String userStoreDomain) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Inserting access token for consumer key: " + consumerKey
                    + " and user store domain: " + userStoreDomain);
        }
        if (OAuthServerConfiguration.getInstance().getValueForIsRefreshTokenAllowed(accessTokenDO.getGrantType())) {
            refreshTokenDAO.insertRefreshToken(accessToken, consumerKey, accessTokenDO, userStoreDomain);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Refresh token is not allowed for the grant type: " + accessTokenDO.getGrantType());
            }
        }
    }

    @Override
    public boolean insertAccessToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO,
                                     AccessTokenDO existingAccessTokenDO, String rawUserStoreDomain)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Inserting access token with existing token check for "
                    + "consumer key: " + consumerKey + " and user store domain: " + rawUserStoreDomain);
        }
        if (OAuthServerConfiguration.getInstance().getValueForIsRefreshTokenAllowed(newAccessTokenDO.getGrantType())) {
            return refreshTokenDAO.insertRefreshToken(accessToken, consumerKey, newAccessTokenDO, existingAccessTokenDO,
                    rawUserStoreDomain);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Refresh token is not allowed for the grant type: " + newAccessTokenDO.getGrantType());
            }
            return true; // No refresh token to insert, hence returning true.
        }
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, boolean includeExpiredTokens)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting latest access token for consumer key: "
                    + consumerKey
                    + ", user store domain: " + userStoreDomain + ", scope: " + scope
                    + ", include expired tokens: " + includeExpiredTokens);
        }
        // do nothing
        return null;
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, String tokenBindingReference, boolean includeExpiredTokens)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting latest access token for consumer key: "
                    + consumerKey
                    + ", user store domain: " + userStoreDomain + ", scope: " + scope
                    + ", token binding reference: " + tokenBindingReference
                    + ", include expired tokens: " + includeExpiredTokens);
        }
        // do nothing
        return null;
    }

    @Override
    public Set<String> getTokenIdBySessionIdentifier(String bindingRef) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting token ID by session identifier: " + bindingRef);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public void storeTokenToSessionMapping(String sessionIdentifier, String tokenId, int tenantId)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Storing token to session mapping for session: "
                    + sessionIdentifier + " and token ID: " + tokenId);
        }
        // do nothing
    }

    @Override
    public String getSessionIdentifierByTokenId(String tokenId) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting session identifier by token ID: " + tokenId);
        }
        // do nothing
        return null;
    }

    @Override
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName, String userStoreDomain,
                                              boolean includeExpired) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens for consumer key: " + consumerKey
                    + ", user store domain: " + userStoreDomain + ", include expired: " + includeExpired);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access token by identifier, include expired: "
                    + includeExpired);
        }
        // do nothing
        return null;
    }

    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by user");
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by user for openid scope");
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser,
                              boolean includeExpiredAccessTokensWithActiveRefreshToken)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by user for openid scope"
                    + ", include expired with active refresh token: "
                    + includeExpiredAccessTokensWithActiveRefreshToken);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting active tokens by consumer key: " + consumerKey);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting active access token data by consumer key: "
                    + consumerKey);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by tenant ID: " + tenantId);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByAuthorizedOrg(String organizationId) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by authorized organization: "
                    + organizationId);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens of user store for tenant ID: "
                    + tenantId + " and user store domain: " + userStoreDomain);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access tokens, count: "
                    + (tokens != null ? tokens.length : 0));
        }
        // do nothing
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access tokens in batch, count: "
                    + (tokens != null ? tokens.length : 0));
        }
        // do nothing
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access tokens individually, count: "
                    + (tokens != null ? tokens.length : 0));
        }
        // do nothing
    }

    @Override
    public void revokeAccessTokens(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access tokens with hashed token flag: "
                    + isHashedToken + ", count: " + (tokens != null ? tokens.length : 0));
        }
        // do nothing
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access tokens in batch with hashed token flag: "
                    + isHashedToken + ", count: " + (tokens != null ? tokens.length : 0));
        }
        // do nothing
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access tokens individually with hashed token flag: "
                    + isHashedToken + ", count: " + (tokens != null ? tokens.length : 0));
        }
        // do nothing
    }

    @Override
    public void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access token with token ID: " + tokenId);
        }
        // do nothing
    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Invalidating and creating new access token for "
                    + "old token ID: " + oldAccessTokenId + ", consumer key: " + consumerKey
                    + ", token state: " + tokenState + ", user store domain: " + userStoreDomain);
        }
        // do nothing
    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Invalidating and creating new access token for "
                    + "old token ID: " + oldAccessTokenId + ", consumer key: " + consumerKey
                    + ", token state: " + tokenState + ", user store domain: " + userStoreDomain
                    + ", grant type: " + grantType);
        }
        // do nothing
    }

    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String newUserStoreDomain)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Updating user store domain for tenant ID: " + tenantId
                    + " from: " + currentUserStoreDomain + " to: " + newUserStoreDomain);
        }
        // do nothing
    }

    @Override
    public String getTokenIdByAccessToken(String token) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting token ID by access token");
        }
        // do nothing
        return null;
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope,
                                                     boolean includeExpiredTokens, int limit)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting latest access tokens for consumer key: " + consumerKey
                    + ", user store domain: " + userStoreDomain + ", scope: " + scope
                    + ", include expired tokens: " + includeExpiredTokens + ", limit: " + limit);
        }
        // do nothing
        return Collections.emptyList();
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope,
                                                     String tokenBindingReference, boolean includeExpiredTokens,
                                                     int limit) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting latest access tokens for consumer key: "
                    + consumerKey
                    + ", user store domain: " + userStoreDomain + ", scope: " + scope
                    + ", token binding reference: " + tokenBindingReference
                    + ", include expired tokens: " + includeExpiredTokens + ", limit: " + limit);
        }
        // do nothing
        return Collections.emptyList();
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Updating access token state for token ID: " + tokenId
                    + " to state: " + tokenState);
        }
        // do nothing
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState, String grantType)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Updating access token state for token ID: " + tokenId
                    + " to state: " + tokenState + ", grant type: " + grantType);
        }
        // do nothing
    }

    @Override
    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(String consumerKey)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting active token set with token ID by consumer key "
                    + "for openid scope: " + consumerKey);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyAndScope(String consumerKey, List<String> scopes)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting active token set with token ID by consumer key: "
                    + consumerKey + " and scopes: " + scopes);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(AuthenticatedUser user, String bindingRef)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by binding reference for user");
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(String bindingRef) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access tokens by binding reference: " + bindingRef);
        }
        // do nothing
        return Collections.emptySet();
    }

    @Override
    public String getAccessTokenByTokenId(String tokenId) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Getting access token by token ID: " + tokenId);
        }
        // do nothing
        return null;
    }

    @Override
    public void updateTokenIsConsented(String tokenId, boolean isConsentedGrant) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Updating token is consented for token ID: " + tokenId
                    + " to: " + isConsentedGrant);
        }
        // do nothing
    }
}
