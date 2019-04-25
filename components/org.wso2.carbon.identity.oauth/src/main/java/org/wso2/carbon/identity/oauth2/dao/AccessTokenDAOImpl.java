/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
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
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import static org.wso2.carbon.identity.core.util.IdentityUtil.getProperty;

/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public class AccessTokenDAOImpl extends AbstractOAuthDAO implements AccessTokenDAO {

    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";
    private static final int DEFAULT_TOKEN_PERSIST_RETRY_COUNT = 5;
    private static final String IDN_OAUTH2_ACCESS_TOKEN = "IDN_OAUTH2_ACCESS_TOKEN";
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();
    private boolean isTokenCleanupFeatureEnabled=OAuthServerConfiguration.getInstance().isTokenCleanupEnabled();

    private Log log = LogFactory.getLog(AccessTokenDAOImpl.class);
    OldTokensCleanDAO oldTokenCleanupObject = new OldTokensCleanDAO();

    @Override
    public void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                  String userStoreDomain) throws IdentityOAuth2Exception {

        try (Connection connection = getConnection()) {
            insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain);
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting access token.", e);
        }
    }

    private void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                   Connection connection, String userStoreDomain) throws IdentityOAuth2Exception {
        // Start inserting access token with retryAttemptCounter set to 0.
        insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain, 0);
    }

    private void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                   Connection connection, String userStoreDomain, int retryAttemptCounter)
            throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        if (accessTokenDO == null) {
            throw new IdentityOAuth2Exception(
                    "Access token data object should be available for further execution.");
        }

        if (accessTokenDO.getAuthzUser() == null) {
            throw new IdentityOAuth2Exception(
                    "Authorized user should be available for further execution.");
        }

        try {
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
            //check for persist alias for the token type
            if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                accessToken = oauthTokenIssuer.getAccessTokenHash(accessToken);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Error while getting access token hash for token(hashed): " + DigestUtils
                        .sha256Hex(accessToken));
            }
            throw new IdentityOAuth2Exception("Error while getting access token hash.");
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
        }

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Persisting access token(hashed): " + DigestUtils.sha256Hex(accessToken) + " for client: " +
                        consumerKey + " user: " + accessTokenDO.getAuthzUser().toString() + " scope: "
                        + Arrays.toString(accessTokenDO.getScope()));
            } else {
                log.debug("Persisting access token for client: " + consumerKey + " user: " +
                        accessTokenDO.getAuthzUser().toString() + " scope: "
                        + Arrays.toString(accessTokenDO.getScope()));
            }
        }
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        String userDomain = accessTokenDO.getAuthzUser().getUserStoreDomain();
        String authenticatedIDP = accessTokenDO.getAuthzUser().getFederatedIdPName();
        PreparedStatement insertTokenPrepStmt = null;
        PreparedStatement addScopePrepStmt = null;

        if (isFederatedUser(accessTokenDO)) {
            if (log.isDebugEnabled()) {
                log.debug("Adding federated domain to user store domain to user " + accessTokenDO.getAuthzUser()
                        .getAuthenticatedSubjectIdentifier());
            }
            userDomain = OAuth2Util.getFederatedUserDomain(authenticatedIDP);
        }

        if (log.isDebugEnabled()) {
            String username;
            if (isFederatedUser(accessTokenDO)) {
                username = accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier();
            } else {
                username = accessTokenDO.getAuthzUser().toFullQualifiedUsername();
            }
            log.debug("Userstore domain for user: " + username + " is " + userDomain);
        }

        String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN, userDomain);
        String sqlAddScopes = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.INSERT_OAUTH2_TOKEN_SCOPE,
                userDomain);

        try {
            insertTokenPrepStmt = connection.prepareStatement(sql);
            insertTokenPrepStmt.setString(1, getPersistenceProcessor().getProcessedAccessTokenIdentifier(accessToken));

            if (accessTokenDO.getRefreshToken() != null) {
                insertTokenPrepStmt.setString(2, getPersistenceProcessor().getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
            } else {
                insertTokenPrepStmt.setString(2, accessTokenDO.getRefreshToken());
            }

            insertTokenPrepStmt.setString(3, accessTokenDO.getAuthzUser().getUserName());
            int tenantId = OAuth2Util.getTenantId(accessTokenDO.getAuthzUser().getTenantDomain());
            insertTokenPrepStmt.setInt(4, tenantId);
            insertTokenPrepStmt.setString(5, OAuth2Util.getSanitizedUserStoreDomain(userDomain));
            insertTokenPrepStmt.setTimestamp(6, accessTokenDO.getIssuedTime(), Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            insertTokenPrepStmt.setTimestamp(7, accessTokenDO.getRefreshTokenIssuedTime(), Calendar.getInstance(TimeZone
                    .getTimeZone(UTC)));
            insertTokenPrepStmt.setLong(8, accessTokenDO.getValidityPeriodInMillis());
            insertTokenPrepStmt.setLong(9, accessTokenDO.getRefreshTokenValidityPeriodInMillis());
            insertTokenPrepStmt.setString(10, OAuth2Util.hashScopes(accessTokenDO.getScope()));
            insertTokenPrepStmt.setString(11, accessTokenDO.getTokenState());
            insertTokenPrepStmt.setString(12, accessTokenDO.getTokenType());
            insertTokenPrepStmt.setString(13, accessTokenDO.getTokenId());
            insertTokenPrepStmt.setString(14, accessTokenDO.getGrantType());
            insertTokenPrepStmt.setString(15, accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier());
            insertTokenPrepStmt
                    .setString(16, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(accessToken));
            if (accessTokenDO.getRefreshToken() != null) {
                insertTokenPrepStmt.setString(17,
                        getHashingPersistenceProcessor().getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
            } else {
                insertTokenPrepStmt.setString(17, accessTokenDO.getRefreshToken());
            }
            insertTokenPrepStmt.setString(18, getPersistenceProcessor().getProcessedClientId(consumerKey));
            insertTokenPrepStmt.execute();

            String accessTokenId = accessTokenDO.getTokenId();
            addScopePrepStmt = connection.prepareStatement(sqlAddScopes);

            if (accessTokenDO.getScope() != null && accessTokenDO.getScope().length > 0) {
                for (String scope : accessTokenDO.getScope()) {
                    addScopePrepStmt.setString(1, accessTokenId);
                    addScopePrepStmt.setString(2, scope);
                    addScopePrepStmt.setInt(3, tenantId);
                    addScopePrepStmt.execute();
                }
            }
            if (retryAttemptCounter > 0) {
                log.info("Successfully recovered 'CON_APP_KEY' constraint violation with the attempt : " +
                        retryAttemptCounter);
            }
        } catch (SQLIntegrityConstraintViolationException e) {
            IdentityDatabaseUtil.rollBack(connection);
            if (retryAttemptCounter >= getTokenPersistRetryCount()) {
                log.error("'CON_APP_KEY' constrain violation retry count exceeds above the maximum count - " +
                        getTokenPersistRetryCount());
                String errorMsg = "Access Token for consumer key : " + consumerKey + ", user : " +
                        accessTokenDO.getAuthzUser() + " and scope : " +
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()) + "already exists";
                throw new IdentityOAuth2Exception(errorMsg, e);
            }

            recoverFromConAppKeyConstraintViolation(accessToken, consumerKey, accessTokenDO, connection,
                    userStoreDomain, retryAttemptCounter + 1);
        } catch (DataTruncation e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Invalid request", e);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            // Handle constrain violation issue in JDBC drivers which does not throw
            // SQLIntegrityConstraintViolationException
            if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_APP_KEY")) {
                if (retryAttemptCounter >= getTokenPersistRetryCount()) {
                    log.error("'CON_APP_KEY' constrain violation retry count exceeds above the maximum count - " +
                            getTokenPersistRetryCount());
                    String errorMsg = "Access Token for consumer key : " + consumerKey + ", user : " +
                            accessTokenDO.getAuthzUser() + " and scope : " +
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()) + "already exists";
                    throw new IdentityOAuth2Exception(errorMsg, e);
                }

                recoverFromConAppKeyConstraintViolation(accessToken, consumerKey, accessTokenDO,
                        connection, userStoreDomain, retryAttemptCounter + 1);
            } else {
                throw new IdentityOAuth2Exception(
                        "Error when storing the access token for consumer key : " + consumerKey, e);
            }
        } finally {
            IdentityDatabaseUtil.closeStatement(addScopePrepStmt);
            IdentityDatabaseUtil.closeStatement(insertTokenPrepStmt);
        }

    }

    @Override
    public boolean insertAccessToken(String accessToken, String consumerKey,
                                     AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO,
                                     String rawUserStoreDomain) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return false;
        }

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Persisting access token(hashed): " + DigestUtils.sha256Hex(accessToken) + " for client: " +
                        consumerKey + " user: " + newAccessTokenDO.getAuthzUser().toString() + " scope: " + Arrays
                        .toString(newAccessTokenDO.getScope()));
            } else {
                log.debug("Persisting access token for client: " + consumerKey + " user: " + newAccessTokenDO
                        .getAuthzUser().toString() + " scope: " + Arrays.toString(newAccessTokenDO.getScope()));
            }
        }

        String userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(rawUserStoreDomain);

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            connection.setAutoCommit(false);
            if (existingAccessTokenDO != null) {
                //  Mark the existing access token as expired on database if a token exist for the user
                updateAccessTokenState(connection, existingAccessTokenDO.getTokenId(), OAuthConstants.TokenStates
                        .TOKEN_STATE_EXPIRED, UUID.randomUUID().toString(), userStoreDomain);
            }
            insertAccessToken(accessToken, consumerKey, newAccessTokenDO, connection, userStoreDomain);

            if (isTokenCleanupFeatureEnabled && existingAccessTokenDO != null) {
                oldTokenCleanupObject.cleanupTokenByTokenId(existingAccessTokenDO.getTokenId(), connection);
            }
            connection.commit();
            return true;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error occurred while persisting access token", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                              String userStoreDomain, String scope,
                                              boolean includeExpiredTokens)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest access token for client: " + consumerKey + " user: " + authzUser.toString()
                    + " scope: " + scope);
        }
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();

        String userDomain;
        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && authzUser.isFederatedUser()) {
            if (log.isDebugEnabled()) {
                log.debug("User is federated and not mapped to local users. Hence adding federated domain as domain");
            }
            userDomain = OAuth2Util.getFederatedUserDomain(authzUser.getFederatedIdPName());
        } else {
            userDomain = OAuth2Util.getSanitizedUserStoreDomain(authzUser.getUserStoreDomain());
        }
        if (log.isDebugEnabled()) {
            log.debug("User domain is set to :" + userDomain);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {

            String sql;
            if (connection.getMetaData().getDriverName().contains("MySQL")
                    || connection.getMetaData().getDriverName().contains("H2")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
            } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
            } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
            } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;

            } else {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
            }

            if (!includeExpiredTokens) {
                sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH=? AND TOKEN_STATE='ACTIVE'");
            }

            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userDomain);

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            String hashedScope = OAuth2Util.hashScopes(scope);
            if (hashedScope == null) {
                sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            if (isUsernameCaseSensitive) {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userDomain);

            if (hashedScope != null) {
                prepStmt.setString(5, hashedScope);
            }

            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                boolean returnToken = false;
                String tokenState = resultSet.getString(7);
                if (includeExpiredTokens) {
                    if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState) ||
                            OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(tokenState)) {
                        returnToken = true;
                    }
                } else {
                    if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState)) {
                        returnToken = true;
                    }
                }
                if (returnToken) {
                    String accessToken = null;
                    if (isHashDisabled) {
                        accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(
                                resultSet.getString(1));
                    } else {
                        accessToken = resultSet.getString(1);
                    }
                    String refreshToken = null;
                    if (resultSet.getString(2) != null) {
                        if (isHashDisabled) {
                            refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                        } else {
                            refreshToken = resultSet.getString(2);
                        }
                    }
                    long issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)))
                            .getTime();
                    long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone
                            (UTC))).getTime();
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodInMillis = resultSet.getLong(6);

                    String userType = resultSet.getString(8);
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);
                    // data loss at dividing the validity period but can be neglected
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                            userDomain, tenantDomain);

                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                    AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, user, OAuth2Util.buildScopeArray
                            (scope), new Timestamp(issuedTime), new Timestamp(refreshTokenIssuedTime)
                            , validityPeriodInMillis, refreshTokenValidityPeriodInMillis, userType);
                    accessTokenDO.setAccessToken(accessToken);
                    accessTokenDO.setRefreshToken(refreshToken);
                    accessTokenDO.setTokenState(tokenState);
                    accessTokenDO.setTokenId(tokenId);
                    if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens
                            .ACCESS_TOKEN)) {
                        log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex(accessToken) +
                                " for client: " + consumerKey + " user: " + authzUser.toString() + " scope: " + scope);
                    }
                    return accessTokenDO;
                }
            }
            return null;
        } catch (SQLException e) {
            String errorMsg = "Error occurred while trying to retrieve latest 'ACTIVE' " +
                    "access token for Client ID : " + consumerKey + ", User ID : " + authzUser +
                    " and  Scope : " + scope;
            if (includeExpiredTokens) {
                errorMsg = errorMsg.replace("ACTIVE", "ACTIVE or EXPIRED");
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    private AccessTokenDO getLatestAccessTokenByState(Connection connection, String consumerKey, AuthenticatedUser
            authzUser,
                                                      String userStoreDomain, String scope, boolean active)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest " + (active ? " active" : " non active") + " access token for user: " +
                    authzUser.toString() + " client: " + consumerKey + " scope: " + scope);
        }
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();

        String userDomain;
        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && authzUser.isFederatedUser()) {
            userDomain = OAuth2Util.getFederatedUserDomain(authzUser.getFederatedIdPName());
        } else {
            userDomain = OAuth2Util.getSanitizedUserStoreDomain(authzUser.getUserStoreDomain());
        }

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {

            String sql;
            if (active) {
                if (connection.getMetaData().getDriverName().contains("MySQL")
                        || connection.getMetaData().getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL")
                        || connection.getMetaData().getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;

                } else {
                    sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                }
            } else {
                if (connection.getMetaData().getDriverName().contains("MySQL")
                        || connection.getMetaData().getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL")
                        || connection.getMetaData().getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;

                } else {
                    sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                }
            }

            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userDomain);

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            String hashedScope = OAuth2Util.hashScopes(scope);
            if (hashedScope == null) {
                sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            if (isUsernameCaseSensitive) {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userDomain);

            if (hashedScope != null) {
                prepStmt.setString(5, hashedScope);
            }

            resultSet = prepStmt.executeQuery();
            AccessTokenDO accessTokenDO = null;

            if (resultSet.next()) {
                String accessToken;
                if (isHashDisabled) {
                    accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(
                            resultSet.getString(1));
                } else {
                    accessToken = resultSet.getString(1);
                }
                String refreshToken = null;
                if (resultSet.getString(2) != null) {
                    if (isHashDisabled) {
                        refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    } else {
                        refreshToken = resultSet.getString(2);
                    }
                }
                long issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone("UTC")))
                        .getTime();
                long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone
                        ("UTC"))).getTime();
                long validityPeriodInMillis = resultSet.getLong(5);
                long refreshTokenValidityPeriodInMillis = resultSet.getLong(6);

                String userType = resultSet.getString(7);
                String tokenId = resultSet.getString(8);
                String subjectIdentifier = resultSet.getString(9);
                // data loss at dividing the validity period but can be neglected
                AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                        userDomain, tenantDomain);
                ServiceProvider serviceProvider;
                try {
                    serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                            getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                } catch (IdentityApplicationManagementException e) {
                    throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                            "client id " + consumerKey, e);
                }
                user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                accessTokenDO = new AccessTokenDO(consumerKey, user, OAuth2Util.buildScopeArray(scope),
                        new Timestamp(issuedTime), new Timestamp(refreshTokenIssuedTime),
                        validityPeriodInMillis, refreshTokenValidityPeriodInMillis, userType);
                accessTokenDO.setAccessToken(accessToken);
                accessTokenDO.setRefreshToken(refreshToken);
                accessTokenDO.setTokenId(tokenId);
            }
            connection.commit();
            return accessTokenDO;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            String errorMsg = "Error occurred while trying to retrieve latest 'ACTIVE' " +
                    "access token for Client ID : " + consumerKey + ", User ID : " + authzUser +
                    " and  Scope : " + scope;
            if (!active) {
                errorMsg = errorMsg.replace("ACTIVE", "NON ACTIVE");
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(null, resultSet, prepStmt);
        }
    }

    @Override
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName,
                                              String userStoreDomain, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens for client: " + consumerKey + " user: " + userName.toString());
        }

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(userName.toString());
        String tenantDomain = userName.getTenantDomain();
        String tenantAwareUsernameWithNoUserDomain = userName.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(userName.getUserStoreDomain());
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            int tenantId = OAuth2Util.getTenantId(tenantDomain);
            String sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER;
            if (includeExpired) {
                sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN_BY_CLIENT_ID_USER;
            }

            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            if (isUsernameCaseSensitive) {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userDomain);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = null;
                if (isHashDisabled) {
                    accessToken = getPersistenceProcessor().
                            getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                }
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = null;
                    if (isHashDisabled) {
                        refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    }
                    Timestamp issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                            .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                    String tokenType = resultSet.getString(7);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                            userDomain, tenantDomain);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                                "client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    AccessTokenDO dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime,
                            refreshTokenIssuedTime, validityPeriodInMillis,
                            refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessToken);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    accessTokenDOMap.put(accessToken, dataDO);
                } else {
                    String scope = resultSet.getString(8).trim();
                    AccessTokenDO accessTokenDO = accessTokenDOMap.get(accessToken);
                    accessTokenDO.setScope((String[]) ArrayUtils.add(accessTokenDO.getScope(), scope));
                }
            }
            connection.commit();
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE' access tokens for " +
                    "Client ID : " + consumerKey + " and User ID : " + userName;
            if (includeExpired) {
                errorMsg = errorMsg.replace("ACTIVE", "ACTIVE or EXPIRED");
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return new HashSet<>(accessTokenDOMap.values());
    }

    @Override
    public AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
            log.debug("Retrieving information of access token(hashed): " + DigestUtils.sha256Hex
                    (accessTokenIdentifier));
        }
        AccessTokenDO dataDO = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            String sql;

            if (includeExpired) {
                sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN;
            } else {
                sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN;
            }

            sql = OAuth2Util.getTokenPartitionedSqlByToken(sql, accessTokenIdentifier);

            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(accessTokenIdentifier));
            resultSet = prepStmt.executeQuery();

            int iterateId = 0;
            List<String> scopes = new ArrayList<>();
            while (resultSet.next()) {

                if (iterateId == 0) {

                    String consumerKey = getPersistenceProcessor().getPreprocessedClientId(resultSet.getString(1));
                    String authorizedUser = resultSet.getString(2);
                    int tenantId = resultSet.getInt(3);
                    String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                    String userDomain = resultSet.getString(4);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(5));
                    Timestamp issuedTime = resultSet.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(7,
                            Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(8);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(9);
                    String tokenType = resultSet.getString(10);
                    String refreshToken = resultSet.getString(11);
                    String tokenId = resultSet.getString(12);
                    String grantType = resultSet.getString(13);
                    String subjectIdentifier = resultSet.getString(14);

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authorizedUser,
                            userDomain, tenantDomain);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id " +
                                consumerKey, e);
                    }

                    if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && userDomain.startsWith
                            (OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Federated prefix found in domain " + userDomain + " and " +
                                    "federated users are not mapped to local users. " +
                                    "Hence setting user to a federated user for client id" + consumerKey);
                        }
                        user.setFederatedUser(true);
                    }

                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);

                    dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime, refreshTokenIssuedTime,
                            validityPeriodInMillis, refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessTokenIdentifier);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    dataDO.setGrantType(grantType);
                    dataDO.setTenantID(tenantId);

                } else {
                    scopes.add(resultSet.getString(5));
                }

                iterateId++;
            }

            if (scopes.size() > 0 && dataDO != null) {
                dataDO.setScope((String[]) ArrayUtils.addAll(dataDO.getScope(),
                        scopes.toArray(new String[scopes.size()])));
            }

        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when retrieving Access Token" + e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return dataDO;
    }

    private void updateAccessTokenState(Connection connection, String tokenId, String tokenState,
                                        String tokenStateId, String userStoreDomain)
            throws IdentityOAuth2Exception {

        PreparedStatement prepStmt = null;
        try {
            if (log.isDebugEnabled()) {
                log.debug("Changing status of access token with id: " + tokenId + " to: " + tokenState +
                        " userStoreDomain: " + userStoreDomain);
            }

            String sql = SQLQueries.UPDATE_TOKE_STATE;
            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, tokenState);
            prepStmt.setString(2, tokenStateId);
            prepStmt.setString(3, tokenId);
            prepStmt.executeUpdate();
            OAuth2TokenUtil.postUpdateAccessToken(tokenId, tokenState);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error while updating Access Token with ID : " +
                    tokenId + " to Token State : " + tokenState, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    /**
     * This method is to revoke specific tokens
     *
     * @param tokens tokens that needs to be revoked
     * @throws IdentityOAuth2Exception if failed to revoke the access token
     */
    @Override
    public void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception {

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            revokeAccessTokensIndividually(tokens);
        } else {
            revokeAccessTokensInBatch(tokens);
        }
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String token : tokens) {
                    stringBuilder.append(DigestUtils.sha256Hex(token)).append(" ");
                }
                log.debug("Revoking access tokens(hashed): " + stringBuilder.toString());
            } else {
                log.debug("Revoking access tokens in batch mode");
            }
        }
        String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        if (tokens.length > 1) {
            try {
                List<String> oldTokens = new ArrayList<>();
                connection.setAutoCommit(false);
                String sqlQuery = SQLQueries.REVOKE_ACCESS_TOKEN.replace(IDN_OAUTH2_ACCESS_TOKEN,
                        accessTokenStoreTable);
                ps = connection.prepareStatement(sqlQuery);
                for (String token : tokens) {
                    ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                    ps.setString(2, UUID.randomUUID().toString());
                    ps.setString(3, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
                    ps.addBatch();
                    oldTokens.add(getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
                }
                ps.executeBatch();
                connection.commit();
                // To revoke request objects which have persisted against the access token.
                OAuth2TokenUtil.postUpdateAccessTokens(Arrays.asList(tokens), OAuthConstants.TokenStates.
                        TOKEN_STATE_REVOKED);
                if (isTokenCleanupFeatureEnabled) {
                    oldTokenCleanupObject.cleanupTokensInBatch(oldTokens, connection);
                }
                connection.commit();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollBack(connection);
                throw new IdentityOAuth2Exception("Error occurred while revoking Access Tokens : " +
                        Arrays.toString(tokens), e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
            }
        }
        if (tokens.length == 1) {
            try {
                connection.setAutoCommit(true);
                String sqlQuery = SQLQueries.REVOKE_ACCESS_TOKEN.replace(IDN_OAUTH2_ACCESS_TOKEN,
                        accessTokenStoreTable);
                ps = connection.prepareStatement(sqlQuery);
                ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                ps.setString(2, UUID.randomUUID().toString());
                ps.setString(3, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(tokens[0]));
                ps.executeUpdate();

                // To revoke request objects which have persisted against the access token.
                OAuth2TokenUtil.postUpdateAccessTokens(Arrays.asList(tokens), OAuthConstants.TokenStates.
                        TOKEN_STATE_REVOKED);
                if (isTokenCleanupFeatureEnabled) {
                    oldTokenCleanupObject.cleanupTokenByTokenValue(
                            getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(tokens[0]), connection);
                }

            } catch (SQLException e) {
                // IdentityDatabaseUtil.rollBack(connection);
                throw new IdentityOAuth2Exception("Error occurred while revoking Access Token : " +
                        Arrays.toString(tokens), e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
            }
        }
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {

        List<String> accessTokenId = new ArrayList<>();
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String token : tokens) {
                    stringBuilder.append(DigestUtils.sha256Hex(token)).append(" ");
                }
                log.debug("Revoking access tokens(hashed): " + stringBuilder.toString());
            } else {
                log.debug("Revoking access tokens in individual mode");
            }
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        try {
            connection.setAutoCommit(false);

            for (String token : tokens) {
                String sqlQuery = OAuth2Util.getTokenPartitionedSqlByToken(SQLQueries.REVOKE_ACCESS_TOKEN, token);
                ps = connection.prepareStatement(sqlQuery);
                ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                ps.setString(2, UUID.randomUUID().toString());
                ps.setString(3, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
                int count = ps.executeUpdate();
                if (log.isDebugEnabled()) {
                    log.debug("Number of rows being updated : " + count);
                }
                accessTokenId.add(getTokenIdByAccessToken(token));
            }

            connection.commit();
            // To revoke request objects which have persisted against the access token.
            if (accessTokenId.size() > 0) {
                OAuth2TokenUtil.postUpdateAccessTokens(accessTokenId, OAuthConstants.TokenStates.
                        TOKEN_STATE_REVOKED);
            }

            if (isTokenCleanupFeatureEnabled) {
                for (String token : tokens) {
                    oldTokenCleanupObject.cleanupTokenByTokenValue(
                            getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token), connection);
                }
            }
            connection.commit();

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token : " +
                    Arrays.toString(tokens), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Ths method is to revoke specific tokens
     *
     * @param tokenId token that needs to be revoked
     * @throws IdentityOAuth2Exception if failed to revoke the access token
     */
    public void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking access token with id: " + tokenId + " user: " + userId);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserId(SQLQueries.REVOKE_ACCESS_TOKEN_BY_TOKEN_ID,
                    userId);
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, tokenId);
            int count = ps.executeUpdate();
            if (log.isDebugEnabled()) {
                log.debug("Number of rows being updated : " + count);
            }
            connection.commit();

            // To revoke the tokens from Request Object table.
            OAuth2TokenUtil.postUpdateAccessToken(tokenId, OAuthConstants.TokenStates.
                    TOKEN_STATE_REVOKED);

            if (isTokenCleanupFeatureEnabled && tokenId != null) {
                    oldTokenCleanupObject.cleanupTokenByTokenId(tokenId, connection);
            }
            connection.commit();

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token with ID : " + tokenId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Returns the set of access tokens issued for the user.
     *
     * The returned set of access tokens is consumed by
     * {@link org.wso2.carbon.identity.oauth.listener.IdentityOathEventListener} to clear user claims cached against the
     * tokens during a user attribute update.
     *
     * Unless id_token are issued for client_credentials grants there is no point in returning tokens issued with type
     * APPLICATION since no claims are usually cached against tokens issued for client_credentials.
     *
     * Tokens with type APPLICATION can be associated with a particular user, if he/she is the owner of the
     * app.
     *
     * @param authenticatedUser
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens of user: " + authenticatedUser.toString());
        }

        String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        boolean isIdTokenIssuedForClientCredentialsGrant = isIdTokenIssuedForApplicationTokens();
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs;
        Set<String> accessTokens = new HashSet<>();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserId(SQLQueries.GET_ACCESS_TOKEN_BY_AUTHZUSER,
                    authenticatedUser.toString());
            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, authenticatedUser.getUserName());
            } else {
                ps.setString(1, authenticatedUser.getUserName().toLowerCase());
            }
            ps.setInt(2, OAuth2Util.getTenantId(authenticatedUser.getTenantDomain()));
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            ps.setString(4, authenticatedUser.getUserStoreDomain());
            rs = ps.executeQuery();
            if (isHashDisabled) {
                while (rs.next()) {
                    String accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(rs.getString(1));
                    String tokenUserType = rs.getString(2);

                    // Tokens returned by this method will be used to clear claims cached against the tokens,
                    // we will only return tokens that would contain such cached clams in order to improve performance.
                    if (isApplicationUserToken(tokenUserType)) {
                        // Tokens issued for a user can contain cached claims against them.
                        accessTokens.add(accessToken);
                    } else {
                        if (isIdTokenIssuedForClientCredentialsGrant) {
                            // If id_token is issued for client_credentials grant type, such application tokens could
                            // also contain claims cached against them.
                            accessTokens.add(accessToken);
                        }
                    }
                }
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token with user Name : " +
                    authenticatedUser.getUserName() + " tenant ID : " + OAuth2Util.getTenantId(authenticatedUser
                    .getTenantDomain()), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return accessTokens;
    }

    /**
     * Checks whether id_tokens are issued for application tokens (ie. tokens issued for client_credentials grant type)
     *
     * @return
     */
    private boolean isIdTokenIssuedForApplicationTokens() {

        return !OAuthServerConfiguration.getInstance().getIdTokenNotAllowedGrantTypesSet()
                .contains(OAuthConstants.GrantTypes.CLIENT_CREDENTIALS);
    }

    /**
     * Checks whether the issued token is for a user (ie. of type APPLICATION_USER)
     *
     * @param tokenUserType
     * @return
     */
    private boolean isApplicationUserToken(String tokenUserType) {

        return OAuthConstants.UserType.APPLICATION_USER.equals(tokenUserType);
    }

    /**
     * Retrieves active access tokens for the given consumer key.
     *
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access tokens of client: " + consumerKey);
        }

        Set<String> activeTokens = getActiveAccessTokensByConsumerKey(consumerKey, IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                activeTokens.addAll(getActiveAccessTokensByConsumerKey(consumerKey, availableDomainMapping.getKey()));
            }
        }
        return activeTokens;
    }

    /**
     * Retrieves active access tokens of specified user store for the given consumer key.
     *
     * @param consumerKey
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private Set<String> getActiveAccessTokensByConsumerKey(String consumerKey, String userStoreDomain)
            throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> accessTokens = new HashSet<>();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.
                    GET_ACCESS_TOKENS_FOR_CONSUMER_KEY, userStoreDomain);
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setString(2, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();

            if (isHashDisabled) {
                while (rs.next()) {
                    accessTokens.add(getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(rs.getString(1)));

                }
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting access tokens from acces token table for " +
                    "the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return accessTokens;
    }

    /**
     * Retrieves active AccessTokenDOs for the given consumer key.
     *
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access tokens for client: " + consumerKey);
        }

        Set<AccessTokenDO> accessTokenDOs = getActiveAcessTokenDataByConsumerKey(consumerKey,
                IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                accessTokenDOs.addAll(getActiveAcessTokenDataByConsumerKey(consumerKey,
                        availableDomainMapping.getKey()));
            }
        }
        return accessTokenDOs;
    }

    /**
     * Retrieves active AccessTokenDOs of specified user store for the given consumer key.
     *
     * @param consumerKey
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey, String userStoreDomain)
            throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<AccessTokenDO> activeDetailedTokens;
        Map<String, AccessTokenDO> tokenMap = new HashMap<>();

        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.
                    GET_ACTIVE_DETAILS_FOR_CONSUMER_KEY, userStoreDomain);

            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setString(2, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                String token = rs.getString(2);
                if (tokenMap.containsKey(token)) {
                    AccessTokenDO tokenObj = tokenMap.get(token);
                    String[] previousScope = tokenObj.getScope();
                    String[] newSope = new String[tokenObj.getScope().length + 1];
                    System.arraycopy(previousScope, 0, newSope, 0, previousScope.length);
                    newSope[previousScope.length] = rs.getString(5);
                    tokenObj.setScope(newSope);
                } else {
                    String authzUser = rs.getString(1);
                    int tenentId = rs.getInt(3);
                    String userDomain = rs.getString(4);
                    String tokenSope = rs.getString(5);
                    String[] scope = OAuth2Util.buildScopeArray(tokenSope);
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser,
                            userDomain, OAuth2Util.getTenantDomain(tenentId));
                    AccessTokenDO aTokenDetail = new AccessTokenDO();
                    aTokenDetail.setAccessToken(token);
                    aTokenDetail.setConsumerKey(consumerKey);
                    aTokenDetail.setScope(scope);
                    aTokenDetail.setAuthzUser(user);
                    tokenMap.put(token, aTokenDetail);
                }
            }
            activeDetailedTokens = new HashSet<>(tokenMap.values());
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting access tokens from acces token table for " +
                    "the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }

        return activeDetailedTokens;
    }

    /**
     * This method is used invalidate the existing token and generate a new toke within one DB transaction.
     *
     * @param oldAccessTokenId access token need to be updated.
     * @param tokenState       token state before generating new token.
     * @param consumerKey      consumer key of the existing token
     * @param tokenStateId     new token state id to be updated
     * @param accessTokenDO    new access token details
     * @param userStoreDomain  user store domain which is related to this consumer
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState,
                                                  String consumerKey, String tokenStateId,
                                                  AccessTokenDO accessTokenDO, String userStoreDomain)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Invalidating access token with id: " + oldAccessTokenId + " and creating new access token" +
                        "(hashed): " + DigestUtils.sha256Hex(accessTokenDO.getAccessToken()) + " for client: " +
                        consumerKey + " user: " + accessTokenDO.getAuthzUser().toString() + " scope: " + Arrays
                        .toString(accessTokenDO.getScope()));
            } else {
                log.debug("Invalidating and creating new access token for client: " + consumerKey + " user: " +
                        accessTokenDO.getAuthzUser().toString() + " scope: "
                        + Arrays.toString(accessTokenDO.getScope()));
            }
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            connection.setAutoCommit(false);

            // update existing token as inactive
            updateAccessTokenState(connection, oldAccessTokenId, tokenState, tokenStateId, userStoreDomain);

            String newAccessToken = accessTokenDO.getAccessToken();
            // store new token in the DB
            insertAccessToken(newAccessToken, consumerKey, accessTokenDO, connection, userStoreDomain);

            // update new access token against authorization code if token obtained via authorization code grant type
            updateTokenIdIfAutzCodeGrantType(oldAccessTokenId, accessTokenDO.getTokenId(), connection);

            // commit both transactions
            connection.commit();

            // Post refresh access token event
            OAuth2TokenUtil.postRefreshAccessToken(oldAccessTokenId, accessTokenDO.getTokenId(), tokenState);

            if (isTokenCleanupFeatureEnabled && oldAccessTokenId != null) {
                oldTokenCleanupObject.cleanupTokenByTokenId(oldAccessTokenId, connection);
            }
            connection.commit();
        } catch (SQLException e) {
            String errorMsg = "Error while regenerating access token";
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    /**
     * Retrieves AccessTokenDOs of the given tenant.
     *
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all access tokens of tenant id: " + tenantId);
        }

        Set<AccessTokenDO> accessTokenDOs = getAccessTokensByTenant(tenantId, IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                accessTokenDOs.addAll(getAccessTokensByTenant(tenantId, availableDomainMapping.getKey()));
            }
        }
        return accessTokenDOs;
    }

    /**
     * Retrieves AccessTokenDOs of specified user store of the given tenant.
     *
     * @param tenantId
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private Set<AccessTokenDO> getAccessTokensByTenant(int tenantId, String userStoreDomain)
            throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.LIST_ALL_TOKENS_IN_TENANT,
                    userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = null;
                if (isHashDisabled) {
                    accessToken = getPersistenceProcessor().
                            getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                }
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = null;
                    if (isHashDisabled) {
                        refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    }
                    Timestamp issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                            .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                    String tokenType = resultSet.getString(7);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                    String tokenId = resultSet.getString(9);
                    String authzUser = resultSet.getString(10);
                    userStoreDomain = resultSet.getString(11);
                    String consumerKey = resultSet.getString(12);

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain,
                            OAuth2Util.getTenantDomain(tenantId));
                    AccessTokenDO dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime,
                            refreshTokenIssuedTime, validityPeriodInMillis,
                            refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessToken);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    dataDO.setTenantID(tenantId);
                    accessTokenDOMap.put(accessToken, dataDO);
                } else {
                    String scope = resultSet.getString(8).trim();
                    AccessTokenDO accessTokenDO = accessTokenDOMap.get(accessToken);
                    accessTokenDO.setScope((String[]) ArrayUtils.add(accessTokenDO.getScope(), scope));
                }
            }
            connection.commit();
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE or EXPIRED' access tokens for " +
                    "user  tenant id : " + tenantId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return new HashSet<>(accessTokenDOMap.values());
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all ACTIVE and EXPIRED access tokens of userstore: " + userStoreDomain + " tenant " +
                    "id: " + tenantId);
        }
        // we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection();

        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.LIST_ALL_TOKENS_IN_USER_STORE,
                    userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, userStoreDomain);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = null;
                if (isHashDisabled) {
                    accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                }
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = null;
                    if (isHashDisabled) {
                        refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    }
                    Timestamp issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                            .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                    String tokenType = resultSet.getString(7);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                    String tokenId = resultSet.getString(9);
                    String authzUser = resultSet.getString(10);
                    String consumerKey = resultSet.getString(11);

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain,
                            OAuth2Util.getTenantDomain(tenantId));
                    AccessTokenDO dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime,
                            refreshTokenIssuedTime, validityPeriodInMillis,
                            refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessToken);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    dataDO.setTenantID(tenantId);
                    accessTokenDOMap.put(accessToken, dataDO);
                } else {
                    String scope = resultSet.getString(8).trim();
                    AccessTokenDO accessTokenDO = accessTokenDOMap.get(accessToken);
                    accessTokenDO.setScope((String[]) ArrayUtils.add(accessTokenDO.getScope(), scope));
                }
            }
            connection.commit();
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE or EXPIRED' access tokens for " +
                    "user in store domain : " + userStoreDomain + " and tenant id : " + tenantId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return new HashSet<>(accessTokenDOMap.values());
    }

    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String
            newUserStoreDomain) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Renaming userstore domain: " + currentUserStoreDomain + " as: " + newUserStoreDomain
                    + " tenant id: " + tenantId + " in IDN_OAUTH2_ACCESS_TOKEN table");
        }
        // we do not support access token partitioning here
        currentUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(currentUserStoreDomain);
        newUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(newUserStoreDomain);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        try {

            String sqlQuery = SQLQueries.RENAME_USER_STORE_IN_ACCESS_TOKENS_TABLE;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, newUserStoreDomain);
            ps.setInt(2, tenantId);
            ps.setString(3, currentUserStoreDomain);
            int count = ps.executeUpdate();
            if (log.isDebugEnabled()) {
                log.debug("Number of rows being updated : " + count);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while renaming user store : " + currentUserStoreDomain +
                    " in tenant :" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Retrieves token id of the given token.
     *
     * @param token
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    public String getTokenIdByAccessToken(String token) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
            log.debug("Retrieving id of access token(hashed): " + DigestUtils.sha256Hex(token));
        }

        String tokenId = getTokenIdByAccessToken(token, IdentityUtil.getPrimaryDomainName());

        if (tokenId == null && OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.
                checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                tokenId = getTokenIdByAccessToken(token, availableDomainMapping.getKey());
                if (tokenId != null) {
                    break;
                }
            }
        }

        return tokenId;
    }

    /**
     * Retrieves token id of the given token which issued against specified user store.
     *
     * @param token
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private String getTokenIdByAccessToken(String token, String userStoreDomain) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.RETRIEVE_TOKEN_ID_BY_TOKEN,
                    userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("TOKEN_ID");
            }
            connection.commit();
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Token ID' for " +
                    "token : " + token;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    /**
     * Retrieves access token of the given token id.
     *
     * @param tokenId
     * @return
     * @throws IdentityOAuth2Exception
     */
    private String getAccessTokenByTokenId(String tokenId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access token by token id: " + tokenId);
        }

        String token = getAccessTokenByTokenId(tokenId, IdentityUtil.getPrimaryDomainName());

        if (token == null && OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.
                checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                token = getAccessTokenByTokenId(tokenId, availableDomainMapping.getKey());
                if (token != null) {
                    break;
                }
            }
        }

        return token;
    }

    /**
     * Retrieves access token of the given token id which issued against specified user store.
     *
     * @param tokenId
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private String getAccessTokenByTokenId(String tokenId, String userStoreDomain) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.RETRIEVE_TOKEN_BY_TOKEN_ID,
                    userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, tokenId);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("ACCESS_TOKEN");
            }
            connection.commit();
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Access Token' for " +
                    "token id : " + tokenId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    private void updateTokenIdIfAutzCodeGrantType(String oldAccessTokenId, String newAccessTokenId, Connection
            connection) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.info("Updating access token reference of authorization code issued for access token id: " +
                    oldAccessTokenId + " by new access token id:" + newAccessTokenId);
        }

        PreparedStatement prepStmt = null;
        try {
            String updateNewTokenAgaintAuthzCodeSql = SQLQueries.UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE;
            prepStmt = connection.prepareStatement(updateNewTokenAgaintAuthzCodeSql);
            prepStmt.setString(1, newAccessTokenId);
            prepStmt.setString(2, oldAccessTokenId);
            prepStmt.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while updating Access Token against authorization code for " +
                    "access token with ID : " + oldAccessTokenId, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    private void recoverFromConAppKeyConstraintViolation(String accessToken, String consumerKey, AccessTokenDO
            accessTokenDO, Connection connection, String userStoreDomain, int retryAttemptCounter)
            throws IdentityOAuth2Exception {

        log.warn("Retry attempt to recover 'CON_APP_KEY' constraint violation : " + retryAttemptCounter);

        AccessTokenDO latestNonActiveToken = getLatestAccessTokenByState(connection, consumerKey, accessTokenDO.getAuthzUser(),
                userStoreDomain, OAuth2Util.buildScopeString(accessTokenDO.getScope()), false);

        AccessTokenDO latestActiveToken = getLatestAccessTokenByState(connection, consumerKey, accessTokenDO.getAuthzUser(),
                userStoreDomain, OAuth2Util.buildScopeString(accessTokenDO.getScope()), true);

        if (latestActiveToken != null) {
            if (latestNonActiveToken == null ||
                    latestActiveToken.getIssuedTime().after(latestNonActiveToken.getIssuedTime())) {
                // In here we can use existing token since we have a synchronised communication
                accessTokenDO.setTokenId(latestActiveToken.getTokenId());
                accessTokenDO.setAccessToken(latestActiveToken.getAccessToken());
                accessTokenDO.setRefreshToken(latestActiveToken.getRefreshToken());
                accessTokenDO.setIssuedTime(latestActiveToken.getIssuedTime());
                accessTokenDO.setRefreshTokenIssuedTime(latestActiveToken.getRefreshTokenIssuedTime());
                accessTokenDO.setValidityPeriodInMillis(latestActiveToken.getValidityPeriodInMillis());
                accessTokenDO.setRefreshTokenValidityPeriodInMillis(latestActiveToken
                        .getRefreshTokenValidityPeriodInMillis());
                accessTokenDO.setTokenType(latestActiveToken.getTokenType());
                log.info("Successfully recovered 'CON_APP_KEY' constraint violation with the attempt : " +
                        retryAttemptCounter);
            } else {
                // Inactivate latest active token.
                updateAccessTokenState(connection, latestActiveToken.getTokenId(), "INACTIVE",
                        UUID.randomUUID().toString(), userStoreDomain);

                // Update token issued time make this token as latest token & try to store it again.
                accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain, retryAttemptCounter);
            }
        } else {
            // In this case another process already updated the latest active token to inactive.

            // Update token issued time make this token as latest token & try to store it again.
            accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
            insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain, retryAttemptCounter);
        }
    }

    private int getTokenPersistRetryCount() {

        int tokenPersistRetryCount = DEFAULT_TOKEN_PERSIST_RETRY_COUNT;
        if (getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT) != null) {
            tokenPersistRetryCount = Integer.parseInt(getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT));
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth Token Persistence Retry count set to " + tokenPersistRetryCount);
        }
        return tokenPersistRetryCount;
    }

    @Deprecated
    public AccessTokenDO getAccessTokenDOfromTokenIdentifier(String accessTokenIdentifier) throws
            IdentityOAuth2Exception {

        return OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessTokenIdentifier);
    }

    /**
     * Get latest AccessToken list
     *
     * @param consumerKey
     * @param authzUser
     * @param userStoreDomain
     * @param scope
     * @param includeExpiredTokens
     * @param limit
     * @return
     * @throws IdentityOAuth2Exception
     */
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope,
                                                     boolean includeExpiredTokens, int limit)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving " + (includeExpiredTokens ? " active" : " all ") + " latest " + limit + " access " +
                    "token for user: " + authzUser.toString() + " client: " + consumerKey + " scope: " + scope);
        }

        if (authzUser == null) {
            throw new IdentityOAuth2Exception("Invalid user information for given consumerKey: " + consumerKey);
        }
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(authzUser.getUserStoreDomain());
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        boolean sqlAltered = false;
        try {

            String sql;
            if (connection.getMetaData().getDriverName().contains("MySQL")
                    || connection.getMetaData().getDriverName().contains("H2")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
            } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
            } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
            } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;
            } else {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                sql = sql.replace("ROWNUM < 2", "ROWNUM < " + Integer.toString(limit + 1));
                sqlAltered = true;
            }

            if (!includeExpiredTokens) {
                sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH=? AND TOKEN_STATE='ACTIVE'");
            }

            if (!sqlAltered) {
                sql = sql.replace("LIMIT 1", "LIMIT " + Integer.toString(limit));
            }

            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            String hashedScope = OAuth2Util.hashScopes(scope);
            if (hashedScope == null) {
                sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            if (isUsernameCaseSensitive) {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userDomain);

            if (hashedScope != null) {
                prepStmt.setString(5, hashedScope);
            }

            resultSet = prepStmt.executeQuery();
            long latestIssuedTime = new Date().getTime();
            List<AccessTokenDO> accessTokenDOs = new ArrayList<>();
            int iterationCount = 0;
            while (resultSet.next()) {
                long issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone("UTC")))
                        .getTime();
                if (iterationCount == 0) {
                    latestIssuedTime = issuedTime;
                }

                if (latestIssuedTime == issuedTime) {
                    String tokenState = resultSet.getString(7);
                    String accessToken = null;
                    if (isHashDisabled) {
                        accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(
                                resultSet.getString(1));
                    }
                    String refreshToken = null;
                    if (resultSet.getString(2) != null) {
                        if (isHashDisabled) {
                            refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                        }
                    }
                    long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone
                            ("UTC"))).getTime();
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodInMillis = resultSet.getLong(6);

                    String userType = resultSet.getString(8);
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);
                    // data loss at dividing the validity period but can be neglected
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                            userDomain, tenantDomain);

                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                                "client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, user, OAuth2Util.buildScopeArray
                            (scope), new Timestamp(issuedTime), new Timestamp(refreshTokenIssuedTime)
                            , validityPeriodInMillis, refreshTokenValidityPeriodInMillis, userType);
                    accessTokenDO.setAccessToken(accessToken);
                    accessTokenDO.setRefreshToken(refreshToken);
                    accessTokenDO.setTokenState(tokenState);
                    accessTokenDO.setTokenId(tokenId);
                    accessTokenDOs.add(accessTokenDO);
                } else {
                    return accessTokenDOs;
                }
                iterationCount++;
            }
            return accessTokenDOs;
        } catch (SQLException e) {
            String errorMsg = "Error occurred while trying to retrieve latest 'ACTIVE' access token for Client " +
                    "ID : " + consumerKey + ", User ID : " + authzUser + " and  Scope : " + scope;
            if (includeExpiredTokens) {
                errorMsg = errorMsg.replace("ACTIVE", "ACTIVE or EXPIRED");
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    private boolean isFederatedUser(AccessTokenDO accessTokenDO) {

        return !OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() &&
                accessTokenDO.getAuthzUser().isFederatedUser();
    }
}