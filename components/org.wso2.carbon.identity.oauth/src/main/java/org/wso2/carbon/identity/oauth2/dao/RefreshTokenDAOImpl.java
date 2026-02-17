/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries.RefreshTokenPersistenceSQLQueries;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.DataTruncation;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.UserType.APPLICATION_USER;

/**
 * Data Access Object for handling refresh tokens in the OAuth2 framework for Non-Persistence Access token scenarios.
 * This class provides methods to insert, retrieve, validate, and revoke refresh tokens.
 */
public class RefreshTokenDAOImpl extends AbstractOAuthDAO implements RefreshTokenDAO {

    private static final Log LOG = LogFactory.getLog(RefreshTokenDAOImpl.class);
    private final boolean isTokenCleanupFeatureEnabled
            = OAuthServerConfiguration.getInstance().isTokenCleanupEnabled();
    OldTokensCleanDAO oldTokenCleanupObject = new OldTokensCleanDAO();

    /**
     * Inserts a refresh token into the database.
     *
     * @param accessToken     The access token associated with the refresh token.
     * @param consumerKey     The consumer key associated with the refresh token.
     * @param accessTokenDO   The access token data object to be inserted.
     * @param userStoreDomain The user store domain of the user.
     * @throws IdentityOAuth2Exception If an error occurs while inserting the refresh token.
     */
    @Override
    public void insertRefreshToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                   String userStoreDomain) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }
        try (Connection connection = getConnection()) {
            insertRefreshToken(consumerKey, accessTokenDO, connection, userStoreDomain);
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting access token.", e);
        }
    }

    /**
     * Inserts a refresh token into the database.
     *
     * @param accessToken            The access token associated with the refresh token.
     * @param consumerKey            The consumer key associated with the refresh token.
     * @param newAccessTokenDO       The new access token data object to be inserted.
     * @param existingAccessTokenDO  The existing access token data object, if any.
     * @param rawUserStoreDomain     The user store domain of the user.
     * @return                       True if the refresh token was successfully inserted, false otherwise.
     * @throws IdentityOAuth2Exception If an error occurs while inserting the refresh token.
     */
    @Override
    public boolean insertRefreshToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO,
                                      AccessTokenDO existingAccessTokenDO, String rawUserStoreDomain)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return false;
        }

        // Log debug information if logging is enabled
        if (LOG.isDebugEnabled()) {
            String logMessage = String.format("Persisting refresh token for client: %s, scope: %s",
                    consumerKey, Arrays.toString(newAccessTokenDO.getScope()));
            LOG.debug(logMessage);
        }

        // Attempt to insert the refresh token into the database
        try (Connection connection = getConnection()) {
            String userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(rawUserStoreDomain);
            insertRefreshToken(consumerKey, newAccessTokenDO, connection, userStoreDomain);
            return true;
        } catch (SQLException e) {
            // Log and throw exception if persistence fails
            String errorMessage = String.format("Error occurred while persisting refresh token for consumer key: %s",
                    consumerKey);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
    }

    /**
     * Retrieves the latest active refresh token for a given consumer key, authenticated user, user store domain,
     * and scope.
     *
     * @param consumerKey      The consumer key of the application.
     * @param authzUser        The authenticated user.
     * @param userStoreDomain  The user store domain of the authenticated user.
     * @param scope            The scope of the access token.
     * @return An AccessTokenDO object representing the latest active refresh token, or null if not found.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the refresh token.
     */
    @Override
    public AccessTokenDO getActiveRefreshToken(String consumerKey, AuthenticatedUser authzUser,
                                               String userStoreDomain, String scope) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return null;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving latest active refresh token for client: %s, scope: %s",
                    consumerKey, scope));
        }

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        String tenantAwareUsername = authzUser.getUserName();
        String userDomain = OAuth2Util.getUserStoreDomain(authzUser);
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authzUser);

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = createPreparedStatementGetActiveRefreshToken(connection, consumerKey,
                     tenantAwareUsername,
                     tenantId, userDomain, scope, authenticatedIDP, isUsernameCaseSensitive);
             ResultSet resultSet = prepStmt.executeQuery()) {

            if (resultSet.next()) {
                return buildAccessTokenDO(resultSet, consumerKey, tenantAwareUsername, userDomain, tenantDomain,
                        scope, authzUser);
            }
            return null;

        } catch (SQLException e) {
            String errorMsg = String.format("Error occurred while trying to retrieve latest 'ACTIVE' access token " +
                    "for Client ID: %s, Scope: %s", consumerKey, scope);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Builds an AccessTokenDO object from the ResultSet.
     *
     * @param resultSet           The ResultSet containing the token data.
     * @param consumerKey         The consumer key of the application.
     * @param tenantAwareUsername The tenant-aware username of the authenticated user.
     * @param userDomain          The user domain of the authenticated user.
     * @param tenantDomain        The tenant domain of the authenticated user.
     * @param scope               The scope of the access token.
     * @param authzUser           The authenticated user.
     * @return An AccessTokenDO object containing the token data.
     * @throws SQLException If an error occurs while accessing the ResultSet.
     * @throws IdentityOAuth2Exception If an error occurs while creating the AccessTokenDO object.
     */
    private AccessTokenDO buildAccessTokenDO(ResultSet resultSet, String consumerKey, String tenantAwareUsername,
                                             String userDomain, String tenantDomain, String scope,
                                             AuthenticatedUser authzUser) throws SQLException, IdentityOAuth2Exception {

        String refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(1));
        long refreshTokenIssuedTime = resultSet.getTimestamp(2,
                Calendar.getInstance(TimeZone.getTimeZone(UTC))).getTime();
        long refreshTokenValidityPeriodInMillis = resultSet.getLong(3);
        String tokenId = resultSet.getString(4);
        String subjectIdentifier = resultSet.getString(5);
        String isConsentedToken = resultSet.getString(6);
        String authorizedOrganization = resultSet.getString(7);

        AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsername, userDomain, tenantDomain,
                OAuth2Util.getAuthenticatedIDP(authzUser));
        user.setAuthenticatedSubjectIdentifier(subjectIdentifier);

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(consumerKey);
        accessTokenDO.setAuthzUser(user);
        accessTokenDO.setScope(OAuth2Util.buildScopeArray(scope));
        accessTokenDO.setRefreshTokenIssuedTime(new Timestamp(refreshTokenIssuedTime));
        accessTokenDO.setRefreshTokenValidityPeriodInMillis(refreshTokenValidityPeriodInMillis);
        accessTokenDO.setTokenType(APPLICATION_USER);
        accessTokenDO.setNotPersisted(true);
        accessTokenDO.setRefreshToken(refreshToken);
        accessTokenDO.setTokenId(tokenId);
        if (StringUtils.isNotEmpty(isConsentedToken)) {
            accessTokenDO.setIsConsentedToken(Boolean.parseBoolean(isConsentedToken));
        }
        if (StringUtils.isNotEmpty(authorizedOrganization)) {
            accessTokenDO.setAuthorizedOrganizationId(authorizedOrganization);
        }

        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
            LOG.debug(String.format("Retrieved latest access token (hashed): %s for client: %s, scope: %s",
                    DigestUtils.sha256Hex(refreshToken), consumerKey, scope));
        }
        return accessTokenDO;
    }

    /**
     * Creates a PreparedStatement to retrieve the latest active refresh token for a given consumer key, user,
     * and scope.
     *
     * @param connection           The database connection.
     * @param consumerKey          The consumer key of the application.
     * @param tenantAwareUsername  The tenant-aware username of the authenticated user.
     * @param tenantId             The tenant ID of the authenticated user.
     * @param userDomain           The user domain of the authenticated user.
     * @param scope                The scope of the access token.
     * @param authenticatedIDP     The authenticated IDP of the user.
     * @param isUsernameCaseSensitive Whether the username is case-sensitive.
     * @return A PreparedStatement to execute the query.
     * @throws SQLException If an error occurs while creating the PreparedStatement.
     */
    private PreparedStatement createPreparedStatementGetActiveRefreshToken(Connection connection, String consumerKey,
                                                                           String tenantAwareUsername, int tenantId,
                                                                           String userDomain,
                                                                           String scope, String authenticatedIDP,
                                                                           boolean isUsernameCaseSensitive)
            throws SQLException, IdentityOAuth2Exception {

        String sql = RefreshTokenPersistenceSQLQueries.RETRIEVE_LATEST_ACTIVE_REFRESH_TOKEN_BY_CLIENT_ID_USER_SCOPE;
        if (!isUsernameCaseSensitive) {
            sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
        }

        String hashedScope = OAuth2Util.hashScopes(scope);
        if (hashedScope == null) {
            sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH IS NULL");
        }

        PreparedStatement prepStmt = connection.prepareStatement(sql);
        prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
        prepStmt.setString(2, isUsernameCaseSensitive ? tenantAwareUsername : tenantAwareUsername.toLowerCase());
        prepStmt.setInt(3, tenantId);
        prepStmt.setString(4, userDomain);
        if (hashedScope == null) {
            prepStmt.setString(5, authenticatedIDP);
        } else {
            prepStmt.setString(5, hashedScope);
            prepStmt.setString(6, authenticatedIDP);
        }
        return prepStmt;
    }

    @Override
    public void invalidateAndCreateNewRefreshToken(String tokenId, String state, String clientId,
                                                   AccessTokenDO accessTokenBean, String rawUserStoreDomain)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }
        String userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(rawUserStoreDomain);

        // Using try-with-resources to ensure proper resource management
        try (Connection connection = getConnection()) {
            // Update the state of the existing refresh token
            updateRefreshTokenState(connection, tokenId, state, userStoreDomain);
            // Insert the new refresh token into the database
            insertRefreshToken(clientId, accessTokenBean, connection, userStoreDomain);
        } catch (SQLException e) {
            String errorMsg = String.format("Error occurred while persisting access token for client: %s, token ID: %s",
                    clientId, tokenId);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    @Override
    public void revokeToken(String refreshToken) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }

        // Declare connection outside the try-with-resources block to manage rollback/commit
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            // Prepare the SQL statement inside the second try-with-resources block
            try (PreparedStatement ps = connection.prepareStatement(
                    RefreshTokenPersistenceSQLQueries.REVOKE_REFRESH_TOKEN)) {
                // Set parameters for revoking the refresh token
                String processedToken = getHashingPersistenceProcessor()
                        .getProcessedAccessTokenIdentifier(refreshToken);
                ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                ps.setString(2, processedToken);
                ps.executeUpdate();
                // Clean up the refresh token if token cleanup feature is enabled
                if (isTokenCleanupFeatureEnabled) {
                    oldTokenCleanupObject.cleanupRefreshTokenByTokenValue(processedToken, connection);
                }
                // Commit the transaction
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                // Rollback transaction in case of an error
                IdentityDatabaseUtil.rollbackTransaction(connection);
                String errorMsg = String.format("Error occurred while revoking refresh token: %s", refreshToken);
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        } catch (SQLException e) {
            // Handle connection-related errors
            throw new IdentityOAuth2Exception("Error while establishing database connection.", e);
        }
    }

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(String consumerKey, String refreshToken)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return null;
        }
        // Log token validation details
        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                LOG.debug(String.format("Validating refresh token (hashed): %s for client: %s",
                        DigestUtils.sha256Hex(refreshToken), consumerKey));
            } else {
                LOG.debug(String.format("Validating refresh token for client: %s", consumerKey));
            }
        }
        // Validate the input token
        if (refreshToken == null) {
            throw new IdentityOAuth2Exception("Refresh token is null, cannot validate.");
        }
        String sql = RefreshTokenPersistenceSQLQueries.RETRIEVE_REFRESH_TOKEN_VALIDATION_DATA;
        RefreshTokenValidationDataDO validationDataDO = null;
        List<String> scopes = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(sql)) {
            // Set query parameters
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            prepStmt.setString(2, getHashingPersistenceProcessor().getProcessedRefreshToken(refreshToken));

            // Execute query and process results
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                int iterateId = 0;

                while (resultSet.next()) {
                    // If it's the first row, create the validation data object
                    if (iterateId == 0) {
                        validationDataDO = buildValidationDataDO(resultSet, refreshToken);
                    } else {
                        // Collect additional scopes for the token
                        scopes.add(resultSet.getString(5));
                    }
                    iterateId++;
                }
                // Add additional scopes if any
                if (validationDataDO != null && !scopes.isEmpty()) {
                    validationDataDO.setScope((String[]) ArrayUtils.addAll(validationDataDO.getScope(),
                            scopes.toArray(new String[0])));
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error occurred while validating the refresh token", e);
        }
        return validationDataDO;
    }

    private RefreshTokenValidationDataDO buildValidationDataDO(ResultSet resultSet, String refreshToken)
            throws SQLException, IdentityOAuth2Exception {

        // Extract data from ResultSet and build the validation data object
        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();

        String tokenId = resultSet.getString(1);
        String userName = resultSet.getString(2);
        int tenantId = resultSet.getInt(3);
        String userDomain = resultSet.getString(4);
        String tenantDomain = OAuth2Util.getTenantDomain(tenantId);

        validationDataDO.setTokenId(tokenId);
        validationDataDO.setScope(OAuth2Util.buildScopeArray(resultSet.getString(5)));
        validationDataDO.setGrantType(resultSet.getString(6));
        validationDataDO.setIssuedTime(resultSet.getTimestamp(7,
                Calendar.getInstance(TimeZone.getTimeZone(UTC))));
        validationDataDO.setValidityPeriodInMillis(resultSet.getLong(8));
        validationDataDO.setRefreshTokenState(resultSet.getString(9));

        String subjectIdentifier = resultSet.getString(10);
        String authenticatedIDP = resultSet.getString(11);
        String isConsentedToken = resultSet.getString(12);
        String authorizedOrganization = resultSet.getString(13);

        AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(userName, userDomain, tenantDomain,
                authenticatedIDP);
        user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
        validationDataDO.setAuthorizedUser(user);
        validationDataDO.setWithNotPersistedAT(true);
        validationDataDO.setRefreshToken(refreshToken);
        if (StringUtils.isNotEmpty(isConsentedToken)) {
            validationDataDO.setConsented(Boolean.parseBoolean(isConsentedToken));
        }
        if (StringUtils.isNotEmpty(authorizedOrganization)) {
            validationDataDO.setAuthorizedOrganizationId(authorizedOrganization);
        }
        // Default value for token binding reference
        validationDataDO.setTokenBindingReference(OAuthConstants.TokenBindings.NONE);
        return validationDataDO;
    }

    @Override
    public AccessTokenDO getRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return null;
        }
        // Log the hashed refresh token for debugging, if loggable
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
            LOG.debug(String.format("Validating refresh token (hashed): %s", DigestUtils.sha256Hex(refreshToken)));
        }
        AccessTokenDO validationDataDO = null;
        List<String> scopes = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt =
                     connection.prepareStatement(RefreshTokenPersistenceSQLQueries.RETRIEVE_REFRESH_TOKEN)) {

            // Set parameters for the query
            prepStmt.setString(1, getHashingPersistenceProcessor().getProcessedRefreshToken(refreshToken));
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                // Iterate over the result set to build validation data object
                int iterateId = 0;
                while (resultSet.next()) {
                    if (iterateId == 0) {
                        // First iteration, create the validation data object
                        validationDataDO = buildValidationDataDO(resultSet);
                        validationDataDO.setRefreshToken(refreshToken);
                    } else {
                        // Subsequent iterations, collect scopes
                        scopes.add(resultSet.getString(5));
                    }
                    iterateId++;
                }

                // Add additional scopes if available
                if (!scopes.isEmpty() && validationDataDO != null) {
                    validationDataDO.setScope((String[]) ArrayUtils.addAll(validationDataDO.getScope(),
                            scopes.toArray(new String[0])));
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving Refresh Token", e);
        }
        return validationDataDO;
    }

    /**
     * Helper method to build the RefreshTokenValidationDataDO object from the ResultSet.
     */
    private AccessTokenDO buildValidationDataDO(ResultSet resultSet) throws SQLException, IdentityOAuth2Exception {

        String consumerKey = getPersistenceProcessor().getPreprocessedClientId(resultSet.getString(1));
        String authorizedUser = resultSet.getString(2);
        int tenantId = resultSet.getInt(3);
        String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
        String userDomain = resultSet.getString(4);
        String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(5));
        Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(6,
                Calendar.getInstance(TimeZone.getTimeZone(UTC)));
        long refreshTokenValidityPeriodMillis = resultSet.getLong(7);
        String tokenId = resultSet.getString(8);
        String grantType = resultSet.getString(9);
        String subjectIdentifier = resultSet.getString(10);
        String authenticatedIDP = resultSet.getString(11);
        String isConsentedToken = resultSet.getString(12);
        String authorizedOrganization = resultSet.getString(13);

        // Create user object
        AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authorizedUser, userDomain, tenantDomain,
                authenticatedIDP);

        // Get service provider for OAuth2 application data
        ServiceProvider serviceProvider = getServiceProvider(consumerKey, tenantDomain);
        user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
        // Create AccessTokenDO and populate fields
        AccessTokenDO validationDataDO = new AccessTokenDO();
        validationDataDO.setConsumerKey(consumerKey);
        validationDataDO.setAuthzUser(user);
        validationDataDO.setScope(scope);
        validationDataDO.setAccessToken(null); // Refresh token validation doesn’t require the access token
        validationDataDO.setNotPersisted(true); // Non-persisted for refresh tokens
        validationDataDO.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
        validationDataDO.setRefreshTokenValidityPeriodInMillis(refreshTokenValidityPeriodMillis);
        validationDataDO.setTokenId(tokenId);
        validationDataDO.setGrantType(grantType);
        validationDataDO.setTokenType(APPLICATION_USER);
        validationDataDO.setTenantID(tenantId);
        validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        if (StringUtils.isNotEmpty(isConsentedToken)) {
            validationDataDO.setIsConsentedToken(Boolean.parseBoolean(isConsentedToken));
        }
        validationDataDO.setAuthorizedOrganizationId(authorizedOrganization);
        return validationDataDO;
    }

    /**
     * Helper method to retrieve the service provider for the consumer key.
     */
    private ServiceProvider getServiceProvider(String consumerKey, String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getApplicationMgtService()
                    .getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id "
                    + consumerKey, e);
        }
    }

    private void insertRefreshToken(String consumerKey, AccessTokenDO accessTokenDO,
                                    Connection connection, String userStoreDomain) throws IdentityOAuth2Exception {

        if (accessTokenDO == null) {
            throw new IdentityOAuth2Exception("Access token data object should be available for further execution.");
        }
        if (accessTokenDO.getAuthzUser() == null) {
            throw new IdentityOAuth2Exception("Authorized user should be available for further execution.");
        }
        // Check if the refresh token is null and throw an exception
        if (accessTokenDO.getRefreshToken() == null) {
            throw new IdentityOAuth2Exception("Refresh token is null. Cannot insert a refresh token without a valid " +
                    "refresh token.");
        }
        String userDomain = OAuth2Util.getUserStoreDomain(accessTokenDO.getAuthzUser());
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(accessTokenDO.getAuthzUser());
        String insertTokenSQL = RefreshTokenPersistenceSQLQueries.INSERT_OAUTH2_REFRESH_TOKEN;
        String insertScopeSQL = RefreshTokenPersistenceSQLQueries.INSERT_OAUTH2_REFRESH_TOKEN_SCOPE;

        try (PreparedStatement insertTokenStmt = connection.prepareStatement(insertTokenSQL);
             PreparedStatement addScopeStmt = connection.prepareStatement(insertScopeSQL)) {

            // Set parameters for inserting the refresh token
            setInsertTokenParameters(insertTokenStmt, accessTokenDO, consumerKey, userDomain, authenticatedIDP);
            // Execute the refresh token insertion
            insertTokenStmt.executeUpdate();
            // Insert token scopes if available
            insertScopesForToken(addScopeStmt, accessTokenDO);
        } catch (SQLIntegrityConstraintViolationException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
        } catch (DataTruncation e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Invalid request", e);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing the access token for consumer key: "
                    + consumerKey, e);
        }
    }

    /**
     * Sets the parameters for inserting a refresh token into the database.
     *
     * @param stmt               The PreparedStatement to set parameters on.
     * @param accessTokenDO      The AccessTokenDO object containing the token data.
     * @param consumerKey        The consumer key associated with the access token.
     * @param userDomain         The user store domain of the authenticated user.
     * @param authenticatedIDP   The authenticated IDP of the user.
     * @throws SQLException If an error occurs while setting parameters on the PreparedStatement.
     * @throws IdentityOAuth2Exception If an error occurs while processing the access token.
     */
    private void setInsertTokenParameters(PreparedStatement stmt, AccessTokenDO accessTokenDO,
                                          String consumerKey, String userDomain, String authenticatedIDP)
            throws SQLException, IdentityOAuth2Exception {

        int tenantId = OAuth2Util.getTenantId(accessTokenDO.getAuthzUser().getTenantDomain());

        stmt.setString(1, accessTokenDO.getTokenId());
        stmt.setString(2, getPersistenceProcessor().getProcessedRefreshToken
                (accessTokenDO.getRefreshToken()));
        stmt.setString(3, accessTokenDO.getAuthzUser().getUserName());
        stmt.setInt(4, tenantId);
        stmt.setString(5, OAuth2Util.getSanitizedUserStoreDomain(userDomain));
        stmt.setString(6, accessTokenDO.getGrantType());
        stmt.setTimestamp(7,
                accessTokenDO.getRefreshTokenIssuedTime(), Calendar.getInstance(TimeZone.getTimeZone(UTC)));
        stmt.setLong(8, accessTokenDO.getRefreshTokenValidityPeriodInMillis());
        stmt.setString(9, OAuth2Util.hashScopes(accessTokenDO.getScope()));
        stmt.setString(10, accessTokenDO.getTokenState());
        stmt.setString(11, accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier());
        stmt.setString(12,
                getHashingPersistenceProcessor().getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
        stmt.setString(13, Boolean.toString(accessTokenDO.isConsentedToken()));
        String authorizedOrganization = accessTokenDO.getAuthzUser().getAccessingOrganization();
        if (StringUtils.isBlank(authorizedOrganization)) {
            authorizedOrganization = OAuthConstants.AuthorizedOrganization.NONE;
        }
        stmt.setString(14, authorizedOrganization);
        stmt.setString(15, getPersistenceProcessor().getProcessedClientId(consumerKey));
        stmt.setString(16, authenticatedIDP);
        stmt.setInt(17, tenantId);
    }

    /**
     * Inserts scopes for the given access token into the database.
     *
     * @param stmt            The PreparedStatement to execute the insert operation.
     * @param accessTokenDO   The AccessTokenDO object containing the scopes to be inserted.
     * @throws SQLException If an error occurs while executing the SQL statement.
     * @throws IdentityOAuth2Exception If an error occurs while processing the access token.
     */
    private void insertScopesForToken(PreparedStatement stmt, AccessTokenDO accessTokenDO)
            throws SQLException, IdentityOAuth2Exception {

        if (accessTokenDO.getScope() != null && ArrayUtils.isNotEmpty(accessTokenDO.getScope())) {
            for (String scope : accessTokenDO.getScope()) {
                stmt.setString(1, accessTokenDO.getTokenId());
                stmt.setString(2, scope);
                stmt.setInt(3, OAuth2Util.getTenantId(accessTokenDO.getAuthzUser().getTenantDomain()));
                stmt.executeUpdate();
            }
        }
    }

    @Override
    public void revokeTokensForApp(String consumerKey) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }

        // Log debug message about revoking tokens for the specified client
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Revoking all access tokens and authorization codes for client: %s", consumerKey));
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement revokeActiveTokensStatement = connection.prepareStatement(
                     RefreshTokenPersistenceSQLQueries.REVOKE_APP_REFRESH_TOKEN)) {

            // Set SQL query parameters
            revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            revokeActiveTokensStatement.setString(2, consumerKey);
            revokeActiveTokensStatement.setString(3, TOKEN_STATE_ACTIVE);
            // Execute the update statement
            revokeActiveTokensStatement.executeUpdate();
            // Perform token cleanup if enabled
            if (isTokenCleanupFeatureEnabled) {
                oldTokenCleanupObject.cleanupRefreshTokenByApp(consumerKey, connection);
            }
            // Commit the transaction
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            // Rollback the transaction if an error occurs
            IdentityDatabaseUtil.rollbackTransaction(null);
            String errorMsg = String.format("Error while revoking tokens for client: %s", consumerKey);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }


    @Override
    public void revokeTokensByUser(AuthenticatedUser authenticatedUser, int tenantId, String userStoreDomain)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }

        // Log debug message about token revocation operation
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Revoking all access tokens and authorization codes for user." +
                    " Tenant ID: %d, User Store Domain: %s", tenantId, userStoreDomain));
        }

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        String tenantAwareUsername = authenticatedUser.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(authenticatedUser.getUserStoreDomain());
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            // Prepare SQL query for revoking tokens
            String sqlQuery = RefreshTokenPersistenceSQLQueries.REVOKE_USER_REFRESH_TOKEN;
            // Modify SQL if the user store is not case-sensitive
            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            // Prepare the statement
            try (PreparedStatement revokeActiveTokensStatement = connection.prepareStatement(sqlQuery)) {

                // Set the SQL parameters
                revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                String authorizedUser = isUsernameCaseSensitive ? tenantAwareUsername :
                        tenantAwareUsername.toLowerCase();
                revokeActiveTokensStatement.setString(2, authorizedUser);
                revokeActiveTokensStatement.setInt(3, tenantId);
                revokeActiveTokensStatement.setString(4, userDomain);
                // Execute the statement
                revokeActiveTokensStatement.executeUpdate();
                // Perform token cleanup if enabled
                if (isTokenCleanupFeatureEnabled) {
                    oldTokenCleanupObject.cleanupRefreshTokenByUser(authorizedUser, tenantId, userDomain, connection);
                }
                // Commit the transaction
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                // Rollback transaction in case of an error
                IdentityDatabaseUtil.rollbackTransaction(connection);
                String errorMsg = String.format("Error while revoking tokens for user, tenant: %d", tenantId);
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        } catch (SQLException e) {
            // Handle connection-related errors
            throw new IdentityOAuth2Exception("Error while establishing database connection.", e);
        }
    }

    /**
     * Updates the state of a refresh token in the database.
     *
     * @param connection       The database connection.
     * @param tokenId          The ID of the refresh token to update.
     * @param tokenState       The new state to set for the refresh token.
     * @param userStoreDomain  The user store domain of the authenticated user.
     * @throws IdentityOAuth2Exception If an error occurs while updating the refresh token state.
     */
    private void updateRefreshTokenState(Connection connection, String tokenId, String tokenState,
                                         String userStoreDomain) throws IdentityOAuth2Exception {

        PreparedStatement prepStmt = null;
        try {
            // Log debug message with details about the operation
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Changing status of refresh token with ID: %s to: %s, userStoreDomain: %s",
                        tokenId, tokenState, userStoreDomain));
            }
            prepStmt = connection.prepareStatement(RefreshTokenPersistenceSQLQueries.UPDATE_REFRESH_TOKEN_STATE);
            // Set the parameters for the SQL query
            prepStmt.setString(1, tokenState);
            prepStmt.setString(2, tokenId);
            // Execute the update query
            prepStmt.executeUpdate();
            // If token cleanup is enabled, perform the cleanup
            if (isTokenCleanupFeatureEnabled) {
                oldTokenCleanupObject.cleanupRefreshTokenByTokenId(tokenId, connection);
            }
        } catch (SQLException e) {
            // Rollback transaction in case of an error
            IdentityDatabaseUtil.rollbackTransaction(connection);
            // Log and throw a detailed exception
            String errorMsg = String.format("Error occurred while updating refresh token state for token ID: %s to: %s",
                    tokenId, tokenState);
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            // Ensure the prepared statement is closed
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    @Override
    public Set<AccessTokenDO> getRefreshTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving refresh tokens with openid scope of authenticated user");
        }

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        Set<AccessTokenDO> accessTokens;

        // Build SQL query based on case sensitivity
        String sqlQuery = RefreshTokenPersistenceSQLQueries.GET_OPEN_ID_REFRESH_TOKEN_DATA_BY_AUTHZUSER;
        if (!isUsernameCaseSensitive) {
            sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
        }

        // Use try-with-resources for Connection, PreparedStatement, and ResultSet
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(sqlQuery)) {

            // Set query parameters
            if (isUsernameCaseSensitive) {
                ps.setString(1, authenticatedUser.getUserName());
            } else {
                ps.setString(1, authenticatedUser.getUserName().toLowerCase());
            }
            ps.setInt(2, OAuth2Util.getTenantId(authenticatedUser.getTenantDomain()));
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            ps.setString(4, authenticatedUser.getUserStoreDomain());
            ps.setString(5, OAuthConstants.Scope.OPENID);

            try (ResultSet rs = ps.executeQuery()) {
                Map<String, AccessTokenDO> tokenMap = getAccessTokenDOMapFromResultSet(authenticatedUser, rs);
                accessTokens = new HashSet<>(tokenMap.values());
            }

        } catch (SQLException e) {
            // In case of exception, rollback
            throw new IdentityOAuth2Exception(
                    "Error occurred while retrieving openid refresh tokens for user.  tenant ID: " +
                            OAuth2Util.getTenantId(authenticatedUser.getTenantDomain()), e);
        }
        return accessTokens;
    }

    private Map<String, AccessTokenDO> getAccessTokenDOMapFromResultSet(AuthenticatedUser authenticatedUser,
                                                                        ResultSet rs) throws SQLException,
            IdentityOAuth2Exception {

        Map<String, AccessTokenDO> tokenMap = new HashMap<>();
        while (rs.next()) {
            String tokenId = rs.getString(2);
            Timestamp refreshTokenTimeCreated = rs.getTimestamp(3,
                    Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            long issuedTimeInMillis = refreshTokenTimeCreated.getTime();
            long refreshTokenValidityPeriodInMillis = rs.getLong(4);
            String consumerKey = rs.getString(5);
            String grantType = rs.getString(6);
            String isConsentedToken = rs.getString(7);
            String authorizedOrganization = rs.getString(8);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAuthzUser(authenticatedUser);
            accessTokenDO.setTenantID(OAuth2Util.getTenantId(authenticatedUser.getTenantDomain()));
            accessTokenDO.setTokenId(tokenId);
            accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            accessTokenDO.setRefreshTokenIssuedTime(refreshTokenTimeCreated);
            accessTokenDO.setRefreshTokenValidityPeriodInMillis(refreshTokenValidityPeriodInMillis);
            accessTokenDO.setConsumerKey(consumerKey);
            accessTokenDO.setGrantType(grantType);
            if (StringUtils.isNotEmpty(isConsentedToken)) {
                accessTokenDO.setIsConsentedToken(Boolean.parseBoolean(isConsentedToken));
            }
            accessTokenDO.setAuthorizedOrganizationId(authorizedOrganization);

            /*
             * Tokens returned by this method will be used to clear claims cached against the tokens.
             * We will only return tokens that would contain such cached clams in order to improve
             * performance.
             * Tokens issued for openid scope can contain cached claims against them.
             * Tokens that are in ACTIVE state and not expired should be removed from the cache.
             */
            if (!isRefreshTokenExpired(issuedTimeInMillis, refreshTokenValidityPeriodInMillis)) {
                tokenMap.put(tokenId, accessTokenDO);
            }
        }
        return tokenMap;
    }

    /**
     * Checks if the access token is expired based on the issued time and validity period.
     *
     * @param issuedTimeInMillis The time when the token was issued in milliseconds.
     * @param validityPeriodMillis The validity period of the token in milliseconds.
     * @return true if the token is expired, false otherwise.
     */
    private boolean isRefreshTokenExpired(long issuedTimeInMillis, long validityPeriodMillis) {

        return OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodMillis, true) < 0;
    }

    /**
     * Check whether the refresh token persistence is enabled.
     *
     * @return true if the refresh token persistence is enabled, false otherwise.
     */
    private boolean isEnabled() {

        return !OAuth2Util.isAccessTokenPersistenceEnabled() && OAuth2Util.isRefreshTokenPersistenceEnabled();
    }
}
