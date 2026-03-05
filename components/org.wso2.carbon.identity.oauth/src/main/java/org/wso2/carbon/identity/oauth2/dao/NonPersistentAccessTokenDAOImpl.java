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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * An extension for AccessTokenDAOImpl when handling non-persistent access/refresh tokens.
 */
public class NonPersistentAccessTokenDAOImpl extends AbstractOAuthDAO implements AccessTokenDAO {

    private static final Log LOG = LogFactory.getLog(NonPersistentAccessTokenDAOImpl.class);

    @Override
    public void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                  String userStoreDomain) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Inserting access token for consumer key: " + consumerKey +
                    " and user store domain: " + userStoreDomain);
        }
    }

    @Override
    public boolean insertAccessToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO,
                                     AccessTokenDO existingAccessTokenDO, String rawUserStoreDomain)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Inserting access token for consumer key: " + consumerKey +
                    " and user store domain: " + rawUserStoreDomain);
        }
        return true;
    }

    @Override
    public Set<String> getTokenIdBySessionIdentifier(String sessionId) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl" + " - Retrieving token ID by session identifier: "
                    + sessionId);
        }
        return new HashSet<>();
    }

    @Override
    public void storeTokenToSessionMapping(String sessionContextIdentifier, String tokenId, int tenantId) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Storing token to session mapping for session: "
                    + sessionContextIdentifier + " and token ID: " + tokenId);
        }
        //do nothing
    }

    @Override
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName, String userStoreDomain,
                                              boolean includeExpired) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for consumer key: "
                    + consumerKey + ", user store domain: " + userStoreDomain);
        }
        return new HashSet<>();
    }

    @Override
    public AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access token for identifier: "
                    + accessTokenIdentifier);
        }
        return null;
    }

    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for user");
        }
        //nothing to return, hence best option to return empty set
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for user with OpenID scope");
        }
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for user with OpenID scope");
        }
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for tenant: "
                    + tenantId + " and user store domain: " + userStoreDomain);
        }
        return new HashSet<>();
    }

    @Override
    public void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoke access tokens");
        }
        //do nothing
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoke access tokens in batch.");
        }
        //do nothing
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoke access tokens individually.");
        }
        //do nothing
    }

    @Override
    public void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Revoking access token for token ID: "
                    + tokenId + " and user ID: " + userId);
        }
        //do nothing
    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Invalidating and creating new access token for " +
                    "consumer key: " + consumerKey + " and user store domain: " + userStoreDomain);
        }
        //do nothing
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(AuthenticatedUser user, String bindingRef) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for user with binding reference");
        }
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(String bindingRef) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access tokens for binding reference");
        }
        return new HashSet<>();
    }

    @Override
    public String getAccessTokenByTokenId(String tokenId) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access token by token ID: " + tokenId);
        }
        return null;
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving active access token by consumer key: "
                    + consumerKey);
        }
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving active access token by consumer key: "
                    + consumerKey);
        }
        return Collections.emptySet();
    }

    @Override
    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(String consumerKey) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving active access token set with token ID " +
                    "by consumer key for OpenID scope: " + consumerKey);
        }
        return new HashSet<>();
    }

    @Override
    public String getTokenIdByAccessToken(String token) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving access token id by token");
        }
        return null;
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, boolean includeExpiredTokens) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving latest access token for consumer key: "
                    + consumerKey + ", user store domain: " + userStoreDomain);
        }
        return null;
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope, boolean includeExpiredTokens,
                                                     int limit) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving latest access tokens for consumer key: "
                    + consumerKey + ", user store domain: " + userStoreDomain);
        }
        return new ArrayList<>();
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                              String userStoreDomain, String scope, String tokenBindingReference,
                                              boolean includeExpiredTokens) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving latest access tokens for consumer key: "
                    + consumerKey + ", with binding reference and user store domain: " + userStoreDomain);
        }
        return null;
    }

    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String newUserStoreDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - update user store domain");
        }
        //do nothing
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - update access token state for token ID: " + tokenId +
                    " to state: " + tokenState);
        }
        //do nothing
    }

    @Override
    public void revokeAccessTokens(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - revoke Access Tokens.");
        }
        //do nothing
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - revoke Access Tokens in batch.");
        }
        //do nothing
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - revoke Access Tokens individually.");
        }
        //do nothing
    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState,
                                                  String consumerKey, String tokenStateId,
                                                  AccessTokenDO accessTokenDO, String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Invalidating and creating new access token for " +
                    "consumer key: " + consumerKey + " and user store domain: " + userStoreDomain);
        }
        //do nothing
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope, String tokenBindingReference,
                                                     boolean includeExpiredTokens, int limit)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Retrieving latest access tokens for consumer key: "
                    + consumerKey + ", user store domain: " + userStoreDomain);
        }
        return new ArrayList<>();
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState, String grantType)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - Update access token state token id: " + tokenId +
                    " to state: " + tokenState + " for grant type: " + grantType);
        }
        //do nothing
    }

    @Override
    public void updateTokenIsConsented(String tokenId, boolean isConsentedGrant)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("NonPersistentAccessTokenDAOImpl - update token is consented for token id: " + tokenId +
                    " to : " + isConsentedGrant);
        }
        //do nothing
    }
}
