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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_USER_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.Scope.OAUTH2;

/**
 * This class provides the implementation for revoking access tokens and refresh tokens in the context of InMemory
 * token persistence. It is designed to handle token revocation requests and perform the necessary actions to mark
 * tokens as revoked. The class implements the OAuth2RevocationProcessor interface to offer the following
 * functionality:
 * - Revoking access tokens, marking them as revoked in the persistence layer.
 * - Revoking refresh tokens, marking them as revoked in the persistence layer.
 * - Handling both JWT and opaque token formats for refresh token revocation.
 * This class also handles token hashing, token state updates, and interaction with the invalid token persistence
 * service.
 */
public class HybridOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    private static final Log LOG = LogFactory.getLog(HybridOAuth2RevocationProcessor.class);
    private final DefaultOAuth2RevocationProcessor defaultOAuth2RevocationProcessor
            = new DefaultOAuth2RevocationProcessor();
    private final RefreshTokenDAOImpl refreshTokenDAO = new RefreshTokenDAOImpl();

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {

        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            // If token persistence is enabled, we should not use this processor.
            // Instead, we should use the DefaultOAuth2RevocationProcessor.
            return;
        }

        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                LOG.debug(String.format("Revoking access token(hashed): %s",
                        DigestUtils.sha256Hex(accessTokenDO.getAccessToken())));
            } else {
                LOG.debug("Revoking access token.");
            }
        }

        if (accessTokenDO.isNotPersisted()) {
            // Token is non-persistent: update state and store in invalid token registry
            accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);

            long expiryTime = accessTokenDO.getIssuedTime().getTime() + accessTokenDO.getValidityPeriodInMillis();

            OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                    .addRevokedToken(
                            accessTokenDO.getAccessToken(),
                            accessTokenDO.getConsumerKey(),
                            expiryTime);
        } else {
            // Persistent token: revoke via default implementation.
            defaultOAuth2RevocationProcessor.revokeAccessToken(revokeRequestDTO, accessTokenDO);
        }
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            // If token persistence is enabled, we should not use this processor.
            // Instead, we should use the DefaultOAuth2RevocationProcessor.
            return;
        }
        String refreshTokenIdentifier = refreshTokenDO.getRefreshToken();
        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                LOG.debug(String.format("Revoking refresh token(hashed): %s",
                        DigestUtils.sha256Hex(refreshTokenIdentifier)));
            } else {
                LOG.debug("Revoking refresh token.");
            }
        }
        if (refreshTokenDO.isWithNotPersistedAT()) {
            refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            if (OAuth2Util.isRefreshTokenPersistenceEnabled()) {
                refreshTokenDAO.revokeToken(refreshTokenDO.getRefreshToken());
            } else {

                long expiryTime = refreshTokenDO.getIssuedTime().getTime() + refreshTokenDO.getValidityPeriodInMillis();

                OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                        .addRevokedToken(
                                refreshTokenDO.getRefreshToken(),
                                revokeRequestDTO.getConsumerKey(),
                                expiryTime);
            }
        } else {
            defaultOAuth2RevocationProcessor.revokeRefreshToken(revokeRequestDTO, refreshTokenDO);
        }
    }

    /**
     * Revokes all access and refresh tokens issued to a given user in a non-persistent token scenario.
     *
     * @param username          The username whose tokens should be revoked.
     * @param userStoreManager  The user store manager for retrieving user-specific metadata.
     * @return true if the revocation was successful, false otherwise.
     * @throws UserStoreException if an error occurs while interacting with the user store.
     */
    public boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

        // If token persistence is enabled, this processor should not be used.
        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            return true;
        }

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        long revocationTime = System.currentTimeMillis();

        Map<String, Object> params = new HashMap<>();
        params.put(NonPersistenceConstants.REVOCATION_TIME, revocationTime);
        params.put(NonPersistenceConstants.TENANT_DOMAIN, tenantDomain);
        params.put(NonPersistenceConstants.TENANT_ID, tenantId);
        params.put(NonPersistenceConstants.USERNAME, username);

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(username, tenantDomain, userStoreManager);
        boolean isUniqueUserIdEnabled = ((AbstractUserStoreManager) userStoreManager).isUniqueUserIdEnabled();

        String entityId;
        String entityType;

        if (isUniqueUserIdEnabled) {
            entityId = ((AbstractUserStoreManager) userStoreManager).getUserIDFromUserName(username);
            entityType = ENTITY_ID_TYPE_USER_ID;
        } else {
            entityId = authenticatedUser.toFullQualifiedUsername();
            entityType = ENTITY_ID_TYPE_USER_NAME;
        }

        params.put(NonPersistenceConstants.ENTITY_ID, entityId);
        params.put(NonPersistenceConstants.ENTITY_TYPE, entityType);

        // Invoke pre-revocation listeners
        OAuthUtil.invokePreRevocationBySystemListeners(entityId, params);

        try {
            // Revoke tokens for the user by storing revocation metadata
            OAuthTokenPersistenceFactory.getInstance()
                    .getRevokedTokenPersistenceDAO()
                    .revokeTokensBySubjectEvent(entityId, entityType, revocationTime, tenantId);

            // Revoke refresh tokens and application tokens
            revokeRefreshTokenOfUser(authenticatedUser, tenantId, userStoreManager);
            revokeAppTokensOfUser(username, tenantDomain, tenantId, revocationTime);

        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while persisting revocation rules for user tokens.", e);
            return false;
        }

        // Invoke post-revocation listeners
        OAuthUtil.invokePostRevocationBySystemListeners(entityId, params);

        return true;
    }

    /**
     * Revokes all access and refresh tokens issued to a given user under a specific role in a non-persistent token
     * scenario.
     * <p>
     * If the role has APPLICATION audience, only tokens for the specific client application associated with the role
     * are revoked. If the role has ORGANIZATION audience, a blanket user-level revocation is performed since
     * non-persistent tokens cannot be queried by authorized client IDs.
     *
     * @param username          The username whose tokens should be revoked.
     * @param userStoreManager  The user store manager for retrieving user-specific metadata.
     * @param roleId            The role ID that triggered the revocation.
     * @return true if the revocation was successful, false otherwise.
     * @throws UserStoreException if an error occurs while interacting with the user store.
     */
    @Override
    public boolean revokeTokens(String username, UserStoreManager userStoreManager, String roleId)
            throws UserStoreException {

        // If token persistence is enabled, this processor should not be used.
        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            return true;
        }

        // If roleId is null, delegate to the 2-arg method.
        if (roleId == null) {
            return revokeTokens(username, userStoreManager);
        }

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        long revocationTime = System.currentTimeMillis();

        // Get role basic info to determine audience and associated application.
        RoleBasicInfo role;
        try {
            role = OAuthComponentServiceHolder.getInstance().getRoleV2ManagementService()
                    .getRoleBasicInfoById(roleId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new UserStoreException("Error occurred while retrieving basic role info of id : " + roleId, e);
        }

        if (role == null) {
            // Role not found; fall back to blanket user-level revocation.
            return revokeTokens(username, userStoreManager);
        }

        if (RoleConstants.APPLICATION.equals(role.getAudience())) {
            // Application-audience role: revoke tokens only for the specific client application.
            String clientId;
            try {
                clientId = getClientIdFromAppResourceId(role.getAudienceId(), tenantDomain);
            } catch (IdentityOAuth2Exception e) {
                throw new UserStoreException(
                        "Error occurred while retrieving client id for app : " + role.getAudienceId(), e);
            }

            if (clientId == null) {
                LOG.warn("No OAuth2 client found for application resource ID: " + role.getAudienceId()
                        + ". Skipping token revocation.");
                return true;
            }

            try {
                revokeTokensForClientId(clientId, tenantDomain, tenantId, revocationTime);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while revoking tokens for client id: " + clientId, e);
                return false;
            }
        } else {
            // Organization-audience role: fall back to blanket user-level revocation since non-persistent tokens
            // cannot be queried by authorized client IDs to identify only org-audience app tokens.
            return revokeTokens(username, userStoreManager);
        }

        return true;
    }

    /**
     * Revokes all access and refresh tokens associated with a given application when its permitted API scopes are
     * updated, in a non-persistent token scenario.
     * <p>
     * Since non-persistent tokens cannot be queried by scope, this performs a client-level revocation (more
     * aggressive than the Default processor which revokes only tokens with the specific removed scopes).
     *
     * @param appId           The resource ID of the application.
     * @param apiId           The ID of the API whose scopes were updated.
     * @param removedScopes   The list of removed scopes.
     * @param tenantDomain    The tenant domain.
     * @throws IdentityOAuth2Exception if an error occurs while revoking tokens.
     */
    @Override
    public void revokeTokens(String appId, String apiId, List<String> removedScopes, String tenantDomain)
            throws IdentityOAuth2Exception {

        // If token persistence is enabled, delegate to the default processor.
        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            defaultOAuth2RevocationProcessor.revokeTokens(appId, apiId, removedScopes, tenantDomain);
            return;
        }

        String clientId;
        try {
            clientId = getClientIdFromAppResourceId(appId, tenantDomain);
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error occurred while retrieving app by app ID : " + appId, e);
            throw new IdentityOAuth2Exception("Error occurred while retrieving app by app ID : " + appId, e);
        }

        if (clientId == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No OAuth2 client found for application resource ID: " + appId
                        + ". Skipping token revocation.");
            }
            return;
        }

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        long revocationTime = System.currentTimeMillis();

        // Store a client-level revocation event. Non-persistent tokens cannot be queried by scope, so we revoke
        // all tokens for this client rather than filtering by removed scopes.
        OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                .revokeTokensBySubjectEvent(clientId, ENTITY_ID_TYPE_CLIENT_ID, revocationTime, tenantId);

        refreshTokenDAO.revokeTokensForApp(clientId);

        AccessTokenEventUtil.publishTokenRevokeEvent(appId, clientId, tenantDomain);
    }

    private AuthenticatedUser getAuthenticatedUser(String username, String tenantDomain,
                                                   UserStoreManager userStoreManager) {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);
        return authenticatedUser;
    }

    private void revokeRefreshTokenOfUser(AuthenticatedUser authenticatedUser,
                                          int tenantId, UserStoreManager userStoreManager)
            throws IdentityOAuth2Exception {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        refreshTokenDAO.revokeTokensByUser(authenticatedUser, tenantId, userStoreDomain);
    }

    /**
     * Retrieves the OAuth2 client ID for the given application resource ID.
     *
     * @param appResourceId The resource ID of the application.
     * @param tenantDomain  The tenant domain of the application.
     * @return The OAuth2 client ID, or null if the application has no OAuth2 inbound configuration.
     * @throws IdentityOAuth2Exception if an error occurs while retrieving the application.
     */
    private String getClientIdFromAppResourceId(String appResourceId, String tenantDomain)
            throws IdentityOAuth2Exception {

        ApplicationManagementService applicationManagementService =
                OAuthComponentServiceHolder.getInstance().getApplicationManagementService();
        try {
            ServiceProvider application =
                    applicationManagementService.getApplicationByResourceId(appResourceId, tenantDomain);
            if (application == null ||
                    application.getInboundAuthenticationConfig() == null ||
                    application.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() == null) {
                return null;
            }
            for (InboundAuthenticationRequestConfig config :
                    application.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(OAUTH2, config.getInboundAuthType())) {
                    return config.getInboundAuthKey();
                }
            }
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while retrieving application for resource ID : " + appResourceId, e);
        }
        return null;
    }

    /**
     * Stores a revocation event for the given client ID and invokes pre/post revocation listeners.
     * Also revokes any associated refresh tokens.
     *
     * @param clientId       The OAuth2 client ID whose tokens should be revoked.
     * @param tenantDomain   The tenant domain.
     * @param tenantId       The tenant ID.
     * @param revocationTime The time at which the revocation is performed.
     * @throws IdentityOAuth2Exception if an error occurs while persisting the revocation event.
     */
    private void revokeTokensForClientId(String clientId, String tenantDomain, int tenantId, long revocationTime)
            throws IdentityOAuth2Exception {

        Map<String, Object> params = new HashMap<>();
        params.put(NonPersistenceConstants.ENTITY_ID, clientId);
        params.put(NonPersistenceConstants.ENTITY_TYPE, ENTITY_ID_TYPE_CLIENT_ID);
        params.put(NonPersistenceConstants.REVOCATION_TIME, revocationTime);
        params.put(NonPersistenceConstants.TENANT_DOMAIN, tenantDomain);
        params.put(NonPersistenceConstants.TENANT_ID, tenantId);

        OAuthUtil.invokePreRevocationBySystemListeners(clientId, params);
        OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                .revokeTokensBySubjectEvent(clientId, ENTITY_ID_TYPE_CLIENT_ID, revocationTime, tenantId);
        refreshTokenDAO.revokeTokensForApp(clientId);
        OAuthUtil.invokePostRevocationBySystemListeners(clientId, params);
    }

    /**
     * Revokes all application tokens owned by the user in a non-persistent token scenario.
     *
     * @param username       The username whose application tokens should be revoked.
     * @param tenantDomain   The tenant domain of the user.
     * @param tenantId       The tenant ID of the user.
     * @param revocationTime The time at which the revocation is performed.
     */
    private void revokeAppTokensOfUser(String username, String tenantDomain, int tenantId, long revocationTime) {

        // Get client ids for the apps owned by user since the 'sub' claim for these are the consumer key.
        // The app tokens for those consumer keys should also be revoked.
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            OAuthAppDO[] oAuthAppDOs = oAuthAppDAO
                    .getOAuthConsumerAppsOfUser(username, tenantId);
            for (OAuthAppDO oAuthAppDO : oAuthAppDOs) {
                String consumerKey = oAuthAppDO.getOauthConsumerKey();
                Map<String, Object> revokeAppTokenParams = new HashMap<>();
                revokeAppTokenParams.put(NonPersistenceConstants.ENTITY_ID, consumerKey);
                revokeAppTokenParams.put(NonPersistenceConstants.ENTITY_TYPE,
                        ENTITY_ID_TYPE_CLIENT_ID);
                revokeAppTokenParams.put(NonPersistenceConstants.REVOCATION_TIME, revocationTime);
                revokeAppTokenParams.put(NonPersistenceConstants.TENANT_DOMAIN, tenantDomain);
                revokeAppTokenParams.put(NonPersistenceConstants.TENANT_ID, tenantId);
                OAuthUtil.invokePreRevocationBySystemListeners(consumerKey, revokeAppTokenParams);
                OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO().revokeTokensBySubjectEvent
                        (consumerKey, ENTITY_ID_TYPE_CLIENT_ID,
                                revocationTime, tenantId);
                OAuthUtil.invokePostRevocationBySystemListeners(consumerKey, revokeAppTokenParams);
            }
        } catch (IdentityOAuthAdminException | IdentityOAuth2Exception e) {
            LOG.error("Error while persisting revoke rules for app tokens by user event.", e);
        }
    }
}
