/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;

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
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;


/**
 * Data Access Layer functionality for Token management in OAuth 2.0 implementation. This includes
 * storing and retrieving access tokens, authorization codes and refresh tokens.
 */
public class TokenMgtDAO {

    public static final String AUTHZ_USER = "AUTHZ_USER";
    public static final String LOWER_AUTHZ_USER = "LOWER(AUTHZ_USER)";
    private static final String UTC = "UTC";
    private static TokenPersistenceProcessor persistenceProcessor;

    private boolean usePersistAccessTokenHash = OAuthServerConfiguration.getInstance().usePersistAccessTokenHash();
    private OauthTokenIssuer oauthIssuerImpl = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();

    private static final int DEFAULT_POOL_SIZE = 0;
    private static final int DEFAULT_TOKEN_PERSIST_RETRY_COUNT = 5;
    private static final boolean DEFAULT_PERSIST_ENABLED = true;


    private static int maxPoolSize;
    private static int tokenPersistRetryCount;
    private boolean enablePersist;

    private static BlockingDeque<AccessContextTokenDO> accessContextTokenQueue = new LinkedBlockingDeque<>();

    private static BlockingDeque<AuthContextTokenDO> authContextTokenQueue = new LinkedBlockingDeque<>();

    private static final Log log = LogFactory.getLog(TokenMgtDAO.class);

    private static final String IDN_OAUTH2_ACCESS_TOKEN = "IDN_OAUTH2_ACCESS_TOKEN";
    private static final String IDN_OAUTH2_AUTHORIZATION_CODE = "IDN_OAUTH2_AUTHORIZATION_CODE";

    // These config properties are defined in identity.xml
    private static final String OAUTH_TOKEN_PERSISTENCE_ENABLE = "OAuth.TokenPersistence.Enable";
    private static final String OAUTH_TOKEN_PERSISTENCE_POOLSIZE = "OAuth.TokenPersistence.PoolSize";
    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";

    // We read from these properties for the sake of backward compatibility
    private static final String FRAMEWORK_PERSISTENCE_ENABLE = "JDBCPersistenceManager.SessionDataPersist.Enable";
    private static final String FRAMEWORK_PERSISTENCE_POOLSIZE = "JDBCPersistenceManager.SessionDataPersist.PoolSize";


    static {

        final Log log = LogFactory.getLog(TokenMgtDAO.class);

        maxPoolSize = getTokenPersistPoolSize();
        if (maxPoolSize > 0) {
            log.info("Thread pool size for OAuth Token persistent consumer : " + maxPoolSize);

            ExecutorService threadPool = Executors.newFixedThreadPool(maxPoolSize);

            for (int i = 0; i < maxPoolSize; i++) {
                threadPool.execute(new TokenPersistenceTask(accessContextTokenQueue));
            }

            threadPool = Executors.newFixedThreadPool(maxPoolSize);

            for (int i = 0; i < maxPoolSize; i++) {
                threadPool.execute(new AuthPersistenceTask(authContextTokenQueue));
            }
        }
    }


    public TokenMgtDAO() {
        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
            if (log.isDebugEnabled()) {
                log.debug("TokenPersistenceProcessor set for: " + persistenceProcessor.getClass());
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextProcessor", e);
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }

        enablePersist = isPersistenceEnabled();
        if (IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT) != null) {
            tokenPersistRetryCount = Integer.parseInt(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT));
        } else {
            tokenPersistRetryCount = DEFAULT_TOKEN_PERSIST_RETRY_COUNT;
        }

        if (log.isDebugEnabled()) {
            log.debug("OAuth Token Persistence Enabled: " + enablePersist);
            log.debug("OAuth Token Persistence PoolSize: " + maxPoolSize);
            log.debug("OAuth Token Persistence Retry count set to " + tokenPersistRetryCount);
        }
    }

    public void storeAuthorizationCode(String authzCode, String consumerKey, String callbackUrl,
                                       AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        if (!enablePersist) {
            return;
        }

        if (maxPoolSize > 0) {
            authContextTokenQueue.push(new AuthContextTokenDO(authzCode, consumerKey, callbackUrl, authzCodeDO));
        } else {
            persistAuthorizationCode(authzCode, consumerKey, callbackUrl, authzCodeDO);
        }
    }

    public void persistAuthorizationCode(String authzCode, String consumerKey, String callbackUrl,
                                         AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        if (!enablePersist) {
            return;
        }

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Persisting authorization code (hashed): " + DigestUtils.sha256Hex(authzCode) + " for " +
                        "client: " + consumerKey + " user: " + authzCodeDO.getAuthorizedUser().toString());
            } else {
                log.debug("Persisting authorization code for client: " + consumerKey + " user: " + authzCodeDO
                        .getAuthorizedUser().toString());
            }
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String userDomain = authzCodeDO.getAuthorizedUser().getUserStoreDomain();
        String authenticatedIDP = authzCodeDO.getAuthorizedUser().getFederatedIdPName();

        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && authzCodeDO.getAuthorizedUser()
                .isFederatedUser()) {
            userDomain = OAuth2Util.getFederatedUserDomain(authenticatedIDP);
        }

        try {

            if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                prepStmt = connection.prepareStatement(SQLQueries.STORE_AUTHORIZATION_CODE_WITH_PKCE);
                prepStmt.setString(1, authzCodeDO.getAuthzCodeId());
                prepStmt.setString(2, persistenceProcessor.getProcessedAuthzCode(authzCode));
                prepStmt.setString(3, callbackUrl);
                prepStmt.setString(4, OAuth2Util.buildScopeString(authzCodeDO.getScope()));
                prepStmt.setString(5, authzCodeDO.getAuthorizedUser().getUserName());
                prepStmt.setString(6, OAuth2Util.getSanitizedUserStoreDomain(userDomain));
                int tenantId = OAuth2Util.getTenantId(authzCodeDO.getAuthorizedUser().getTenantDomain());
                prepStmt.setInt(7, tenantId);
                prepStmt.setTimestamp(8, authzCodeDO.getIssuedTime(),
                        Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                prepStmt.setLong(9, authzCodeDO.getValidityPeriod());
                prepStmt.setString(10, authzCodeDO.getAuthorizedUser().getAuthenticatedSubjectIdentifier());
                prepStmt.setString(11, authzCodeDO.getPkceCodeChallenge());
                prepStmt.setString(12, authzCodeDO.getPkceCodeChallengeMethod());
                prepStmt.setString(13, persistenceProcessor.getProcessedClientId(consumerKey));

            } else {
                prepStmt = connection.prepareStatement(SQLQueries.STORE_AUTHORIZATION_CODE);
                prepStmt.setString(1, authzCodeDO.getAuthzCodeId());
                prepStmt.setString(2, persistenceProcessor.getProcessedAuthzCode(authzCode));
                prepStmt.setString(3, callbackUrl);
                prepStmt.setString(4, OAuth2Util.buildScopeString(authzCodeDO.getScope()));
                prepStmt.setString(5, authzCodeDO.getAuthorizedUser().getUserName());
                prepStmt.setString(6, OAuth2Util.getSanitizedUserStoreDomain(userDomain));
                int tenantId = OAuth2Util.getTenantId(authzCodeDO.getAuthorizedUser().getTenantDomain());
                prepStmt.setInt(7, tenantId);
                prepStmt.setTimestamp(8, authzCodeDO.getIssuedTime(),
                        Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                prepStmt.setLong(9, authzCodeDO.getValidityPeriod());
                prepStmt.setString(10, authzCodeDO.getAuthorizedUser().getAuthenticatedSubjectIdentifier());
                prepStmt.setString(11, persistenceProcessor.getProcessedClientId(consumerKey));

            }

            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when storing the authorization code for consumer key : " +
                    consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public void deactivateAuthorizationCode(String authzCode, String tokenId) throws IdentityOAuth2Exception {

        if (!enablePersist) {
            return;
        }

        if (maxPoolSize > 0) {
            authContextTokenQueue.push(new AuthContextTokenDO(authzCode, tokenId));
        } else {
            AuthzCodeDO authzCodeDO = new AuthzCodeDO();
            authzCodeDO.setAuthorizationCode(authzCode);
            authzCodeDO.setOauthTokenId(tokenId);
            deactivateAuthorizationCode(authzCodeDO);
        }
    }

    public void storeAccessToken(String accessToken, String consumerKey,
                                 AccessTokenDO accessTokenDO, Connection connection,
                                 String userStoreDomain) throws IdentityOAuth2Exception {

        if (!enablePersist) {
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

        storeAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain, 0);
    }

    private void storeAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                  Connection connection, String userStoreDomain, int retryAttempt)
            throws IdentityOAuth2Exception {

        if (usePersistAccessTokenHash) {
            try {
                accessToken = oauthIssuerImpl.getAccessTokenHash(accessToken);
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Error while getting access token hash for token: " + accessToken);
                }
                throw new IdentityOAuth2Exception("Error while getting access token hash.");
            }
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

        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && accessTokenDO.getAuthzUser()
                .isFederatedUser()) {
            if (log.isDebugEnabled()) {
                log.debug("Adding federated domain to user store domain to user " + accessTokenDO.getAuthzUser()
                        .getAuthenticatedSubjectIdentifier());
            }
            userDomain = OAuth2Util.getFederatedUserDomain(authenticatedIDP);
        }

        if (log.isDebugEnabled()) {
            log.debug("Userstore domain for user " + accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier()
                    + " is :" + userDomain);
        }

        String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN, userDomain);
        String sqlAddScopes = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.INSERT_OAUTH2_TOKEN_SCOPE,
                userDomain);

        try {
            insertTokenPrepStmt = connection.prepareStatement(sql);
            insertTokenPrepStmt.setString(1, persistenceProcessor.getProcessedAccessTokenIdentifier(accessToken));

            if (accessTokenDO.getRefreshToken() != null) {
                insertTokenPrepStmt.setString(2, persistenceProcessor.getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
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
            insertTokenPrepStmt.setString(16, persistenceProcessor.getProcessedClientId(consumerKey));
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
            if (retryAttempt > 0) {
                log.info("Successfully recovered 'CON_APP_KEY' constraint violation with the attempt : " +
                        retryAttempt);
            }
        } catch (SQLIntegrityConstraintViolationException e) {
            IdentityDatabaseUtil.rollBack(connection);
            if (retryAttempt >= tokenPersistRetryCount) {
                log.error("'CON_APP_KEY' constrain violation retry count exceeds above the maximum count - " +
                        tokenPersistRetryCount);
                String errorMsg = "Access Token for consumer key : " + consumerKey + ", user : " +
                        accessTokenDO.getAuthzUser() + " and scope : " +
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()) + "already exists";
                throw new IdentityOAuth2Exception(errorMsg, e);
            }

            recoverFromConAppKeyConstraintViolation(accessToken, consumerKey, accessTokenDO, connection,
                    userStoreDomain, retryAttempt + 1);
        } catch (DataTruncation e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Invalid request", e);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            // Handle constrain violation issue in JDBC drivers which does not throw
            // SQLIntegrityConstraintViolationException
            if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_APP_KEY")) {
                if (retryAttempt >= tokenPersistRetryCount) {
                    log.error("'CON_APP_KEY' constrain violation retry count exceeds above the maximum count - " +
                            tokenPersistRetryCount);
                    String errorMsg = "Access Token for consumer key : " + consumerKey + ", user : " +
                            accessTokenDO.getAuthzUser() + " and scope : " +
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()) + "already exists";
                    throw new IdentityOAuth2Exception(errorMsg, e);
                }

                recoverFromConAppKeyConstraintViolation(accessToken, consumerKey, accessTokenDO,
                        connection, userStoreDomain, retryAttempt + 1);
            } else {
                throw new IdentityOAuth2Exception(
                        "Error when storing the access token for consumer key : " + consumerKey, e);
            }
        } finally {
            IdentityDatabaseUtil.closeStatement(addScopePrepStmt);
            IdentityDatabaseUtil.closeStatement(insertTokenPrepStmt);
        }

    }

    public void storeAccessToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO,
                                 AccessTokenDO existingAccessTokenDO, String userStoreDomain)
            throws IdentityException {

        if (!enablePersist) {
            return;
        }

        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);

        if (maxPoolSize > 0) {
            accessContextTokenQueue.push(new AccessContextTokenDO(accessToken, consumerKey, newAccessTokenDO
                    , existingAccessTokenDO, userStoreDomain));
        } else {
            persistAccessToken(accessToken, consumerKey, newAccessTokenDO, existingAccessTokenDO, userStoreDomain);
        }
    }

    public boolean persistAccessToken(String accessToken, String consumerKey,
                                      AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO,
                                      String userStoreDomain) throws IdentityOAuth2Exception {
        if (!enablePersist) {
            return false;
        }

        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            connection.setAutoCommit(false);
            if (existingAccessTokenDO != null) {
                //  Mark the existing access token as expired on database if a token exist for the user
                setAccessTokenState(connection, existingAccessTokenDO.getTokenId(), OAuthConstants.TokenStates
                        .TOKEN_STATE_EXPIRED, UUID.randomUUID().toString(), userStoreDomain);
            }
            storeAccessToken(accessToken, consumerKey, newAccessTokenDO, connection, userStoreDomain);
            if (newAccessTokenDO.getAuthorizationCode() != null) {
                // expire authz code and insert issued access token against authz code
                AuthzCodeDO authzCodeDO = new AuthzCodeDO();
                authzCodeDO.setAuthorizationCode(newAccessTokenDO.getAuthorizationCode());
                authzCodeDO.setOauthTokenId(newAccessTokenDO.getTokenId());
                deactivateAuthorizationCode(authzCodeDO, connection);
            }
            connection.commit();
            return true;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error occurred while persisting access token", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    public AccessTokenDO retrieveLatestAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                                   String userStoreDomain, String scope,
                                                   boolean includeExpiredTokens)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest access token for client: " + consumerKey + " user: " + authzUser.toString()
                    + " scope: " + scope);
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
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
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
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
                    String accessToken = persistenceProcessor.getPreprocessedAccessTokenIdentifier(
                            resultSet.getString(1));
                    String refreshToken = null;
                    if (resultSet.getString(2) != null) {
                        refreshToken = persistenceProcessor.getPreprocessedRefreshToken(resultSet.getString(2));
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
                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(tenantAwareUsernameWithNoUserDomain);
                    user.setTenantDomain(tenantDomain);
                    user.setUserStoreDomain(userDomain);
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

    public Set<AccessTokenDO> retrieveAccessTokens(String consumerKey, AuthenticatedUser userName,
                                                   String userStoreDomain, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens for client: " + consumerKey + " user: " + userName.toString());
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(userName.toString());
        String tenantDomain = userName.getTenantDomain();
        String tenantAwareUsernameWithNoUserDomain = userName.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(userName.getUserStoreDomain());
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);

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
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
            if (isUsernameCaseSensitive) {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userDomain);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = persistenceProcessor.
                        getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = persistenceProcessor.
                            getPreprocessedRefreshToken(resultSet.getString(2));
                    Timestamp issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                            .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                    String tokenType = resultSet.getString(7);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(tenantAwareUsernameWithNoUserDomain);
                    user.setTenantDomain(tenantDomain);
                    user.setUserStoreDomain(userDomain);
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


    public AuthzCodeDO validateAuthorizationCode(String consumerKey, String authorizationKey)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Validating authorization code(hashed): " + DigestUtils.sha256Hex(authorizationKey)
                        + " for client: " +  consumerKey);
            } else {
                log.debug("Validating authorization code for client: " + consumerKey);
            }
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            AuthenticatedUser user = null;
            String codeState = null;
            String authorizedUser = null;
            String userstoreDomain = null;
            String scopeString = null;
            String callbackUrl = null;
            String tenantDomain = null;
            String codeId = null;
            String subjectIdentifier = null;
            String pkceCodeChallenge = null;
            String pkceCodeChallengeMethod = null;

            Timestamp issuedTime = null;
            long validityPeriod = 0;
            int tenantId;
            if (OAuth2ServiceComponentHolder.isPkceEnabled()) {

                prepStmt = connection.prepareStatement(SQLQueries.VALIDATE_AUTHZ_CODE_WITH_PKCE);
                prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
                prepStmt.setString(2, persistenceProcessor.getProcessedAuthzCode(authorizationKey));
                resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                    codeState = resultSet.getString(8);
                    authorizedUser = resultSet.getString(1);
                    userstoreDomain = resultSet.getString(2);
                    tenantId = resultSet.getInt(3);
                    tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                    scopeString = resultSet.getString(4);
                    callbackUrl = resultSet.getString(5);
                    issuedTime = resultSet.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    validityPeriod = resultSet.getLong(7);
                    codeId = resultSet.getString(11);
                    subjectIdentifier = resultSet.getString(12);
                    pkceCodeChallenge = resultSet.getString(13);
                    pkceCodeChallengeMethod = resultSet.getString(14);
                    user = new AuthenticatedUser();
                    user.setUserName(authorizedUser);
                    user.setTenantDomain(tenantDomain);
                    user.setUserStoreDomain(userstoreDomain);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                                "client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    authorizedUser = UserCoreUtil.addDomainToName(authorizedUser, userstoreDomain);
                    authorizedUser = UserCoreUtil.addTenantDomainToEntry(authorizedUser, tenantDomain);

                    if (!OAuthConstants.AuthorizationCodeState.ACTIVE.equals(codeState)) {
                        //revoking access token issued for authorization code as per RFC 6749 Section 4.1.2
                        if (log.isDebugEnabled()) {
                            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                                log.debug("Validated authorization code(hashed): " + DigestUtils.sha256Hex
                                        (authorizationKey) + " for client: " + consumerKey + " is not active. So " +
                                        "revoking the access tokens issued for the authorization code.");
                            } else {
                                log.debug("Validated authorization code for client: " + consumerKey + " is not active" +
                                        ". So revoking the access tokens issued for the authorization code.");
                            }
                        }
                        String tokenId = resultSet.getString(9);
                        revokeToken(tokenId, authorizedUser);
                    }
                } else {
                    // this means we were not able to find the authorization code in the database table.
                    return null;
                }

            } else {
                prepStmt = connection.prepareStatement(SQLQueries.VALIDATE_AUTHZ_CODE);
                prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
                prepStmt.setString(2, persistenceProcessor.getProcessedAuthzCode(authorizationKey));
                resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                    codeState = resultSet.getString(8);
                    authorizedUser = resultSet.getString(1);
                    userstoreDomain = resultSet.getString(2);
                    tenantId = resultSet.getInt(3);
                    tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                    scopeString = resultSet.getString(4);
                    callbackUrl = resultSet.getString(5);
                    issuedTime = resultSet.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    validityPeriod = resultSet.getLong(7);
                    codeId = resultSet.getString(11);
                    subjectIdentifier = resultSet.getString(12);

                    user = new AuthenticatedUser();
                    user.setUserName(authorizedUser);
                    user.setTenantDomain(tenantDomain);
                    user.setUserStoreDomain(userstoreDomain);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                                "client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    authorizedUser = UserCoreUtil.addDomainToName(authorizedUser, userstoreDomain);
                    authorizedUser = UserCoreUtil.addTenantDomainToEntry(authorizedUser, tenantDomain);

                    if (!OAuthConstants.AuthorizationCodeState.ACTIVE.equals(codeState)) {
                        if (log.isDebugEnabled()) {
                            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                                log.debug("Validated authorization code(hashed): " + DigestUtils.sha256Hex
                                        (authorizationKey) + " for client: " + consumerKey + " is not active. So " +
                                        "revoking the access tokens issued for the authorization code.");
                            } else {
                                log.debug("Validated authorization code for client: " + consumerKey + " is not active" +
                                        ". So revoking the access tokens issued for the authorization code.");
                            }
                        }

                        //revoking access token issued for authorization code as per RFC 6749 Section 4.1.2
                        String tokenId = resultSet.getString(9);
                        revokeToken(tokenId, authorizedUser);
                    }
                } else {
                    // this means we were not able to find the authorization code in the database table.
                    return null;
                }

            }

            connection.commit();

            return new AuthzCodeDO(user, OAuth2Util.buildScopeArray(scopeString), issuedTime, validityPeriod,
                    callbackUrl, consumerKey, authorizationKey, codeId, codeState, pkceCodeChallenge,
                    pkceCodeChallengeMethod);

        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when validating an authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    public void changeAuthzCodeState(String authzCode, String newState) throws IdentityOAuth2Exception {
        if (maxPoolSize > 0) {
            authContextTokenQueue.push(new AuthContextTokenDO(authzCode));
        } else {
            doChangeAuthzCodeState(authzCode, newState);
        }
    }

    public void deactivateAuthorizationCode(List<AuthzCodeDO> authzCodeDOs) throws IdentityOAuth2Exception {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                    stringBuilder.append("Deactivating authorization code(hashed): ")
                            .append(DigestUtils.sha256Hex(authzCodeDO.getAuthorizationCode()))
                            .append(" client: ")
                            .append(authzCodeDO.getConsumerKey()).append(" user: ")
                            .append(authzCodeDO.getAuthorizedUser().toString())
                            .append("\n");
                }
                log.debug(stringBuilder.toString());
            } else {
                StringBuilder stringBuilder = new StringBuilder();
                for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                    stringBuilder.append("Deactivating authorization code client: ")
                            .append(authzCodeDO.getConsumerKey()).append(" user: ")
                            .append(authzCodeDO.getAuthorizedUser().toString())
                            .append("\n");
                }
                log.debug(stringBuilder.toString());
            }
        }
        try {
            prepStmt = connection.prepareStatement(SQLQueries.DEACTIVATE_AUTHZ_CODE_AND_INSERT_CURRENT_TOKEN);
            for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                prepStmt.setString(1, authzCodeDO.getOauthTokenId());
                prepStmt.setString(2, persistenceProcessor.getPreprocessedAuthzCode(authzCodeDO.getAuthorizationCode()));
                prepStmt.addBatch();
            }
            prepStmt.executeBatch();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public void doChangeAuthzCodeState(String authzCode, String newState) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Changing state of authorization code(hashed): " + DigestUtils.sha256Hex(authzCode)
                        + " to: " + newState);
            } else {
                log.debug("Changing state of authorization code  to: " + newState);
            }
        }

        String authCodeStoreTable = OAuthConstants.AUTHORIZATION_CODE_STORE_TABLE;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            String sqlQuery = SQLQueries.UPDATE_AUTHORIZATION_CODE_STATE.replace(IDN_OAUTH2_AUTHORIZATION_CODE,
                    authCodeStoreTable);
            prepStmt = connection.prepareStatement(sqlQuery);
            prepStmt.setString(1, newState);
            prepStmt.setString(2, persistenceProcessor.getPreprocessedAuthzCode(authzCode));
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while updating the state of Authorization Code : " +
                    authzCode.toString(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public void deactivateAuthorizationCode(AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            deactivateAuthorizationCode(authzCodeDO, connection);
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }

    }

    private void deactivateAuthorizationCode(AuthzCodeDO authzCodeDO, Connection connection) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
            log.debug("Deactivating authorization code(hashed): " + DigestUtils.sha256Hex(authzCodeDO
                        .getAuthorizationCode()));

        }

        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.DEACTIVATE_AUTHZ_CODE_AND_INSERT_CURRENT_TOKEN);
            prepStmt.setString(1, authzCodeDO.getOauthTokenId());
            prepStmt.setString(2, persistenceProcessor.getPreprocessedAuthzCode(authzCodeDO.getAuthorizationCode()));
            prepStmt.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(null, null, prepStmt);
        }
    }

    public RefreshTokenValidationDataDO validateRefreshToken(String consumerKey, String refreshToken)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug("Validating refresh token(hashed): " + DigestUtils.sha256Hex(refreshToken) + " client: " +
                        consumerKey);
            } else {
                log.debug("Validating refresh token for client: " + consumerKey);
            }
        }

        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql;

        try {
            if (connection.getMetaData().getDriverName().contains("MySQL")
                    || connection.getMetaData().getDriverName().contains("H2")) {
                sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MYSQL;
            } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_DB2SQL;
            } else if (connection.getMetaData().getDriverName().contains("MS SQL")
                    || connection.getMetaData().getDriverName().contains("Microsoft")) {
                sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_POSTGRESQL;
            } else if (connection.getMetaData().getDriverName().contains("INFORMIX")) {
                sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_INFORMIX;
            } else {
                sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_ORACLE;
            }

            sql = OAuth2Util.getTokenPartitionedSqlByToken(sql, refreshToken);

            if (refreshToken == null) {
                sql = sql.replace("REFRESH_TOKEN = ?", "REFRESH_TOKEN IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
            if (refreshToken != null) {
                prepStmt.setString(2, persistenceProcessor.getProcessedRefreshToken(refreshToken));
            }

            resultSet = prepStmt.executeQuery();

            int iterateId = 0;
            List<String> scopes = new ArrayList<>();
            while (resultSet.next()) {

                if (iterateId == 0) {
                    validationDataDO.setAccessToken(persistenceProcessor.getPreprocessedAccessTokenIdentifier(
                            resultSet.getString(1)));
                    String userName = resultSet.getString(2);
                    int tenantId = resultSet.getInt(3);
                    String userDomain = resultSet.getString(4);
                    String tenantDomain = OAuth2Util.getTenantDomain(tenantId);

                    validationDataDO.setScope(OAuth2Util.buildScopeArray(resultSet.getString(5)));
                    validationDataDO.setRefreshTokenState(resultSet.getString(6));
                    validationDataDO.setIssuedTime(
                            resultSet.getTimestamp(7, Calendar.getInstance(TimeZone.getTimeZone(UTC))));
                    validationDataDO.setValidityPeriodInMillis(resultSet.getLong(8));
                    validationDataDO.setTokenId(resultSet.getString(9));
                    validationDataDO.setGrantType(resultSet.getString(10));
                    String subjectIdentifier = resultSet.getString(11);
                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(userName);
                    user.setUserStoreDomain(userDomain);
                    user.setTenantDomain(tenantDomain);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                                "client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    validationDataDO.setAuthorizedUser(user);

                } else {
                    scopes.add(resultSet.getString(5));
                }

                iterateId++;
            }

            if (scopes.size() > 0 && validationDataDO != null) {
                validationDataDO.setScope((String[]) ArrayUtils.addAll(validationDataDO.getScope(),
                        scopes.toArray(new String[scopes.size()])));
            }

            connection.commit();

        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when validating a refresh token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return validationDataDO;
    }

    public AccessTokenDO retrieveAccessToken(String accessTokenIdentifier, boolean includeExpired)
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

            prepStmt.setString(1, persistenceProcessor.getProcessedAccessTokenIdentifier(accessTokenIdentifier));
            resultSet = prepStmt.executeQuery();

            int iterateId = 0;
            List<String> scopes = new ArrayList<>();
            while (resultSet.next()) {

                if (iterateId == 0) {

                    String consumerKey = persistenceProcessor.getPreprocessedClientId(resultSet.getString(1));
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

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authorizedUser);
                    user.setUserStoreDomain(userDomain);
                    user.setTenantDomain(tenantDomain);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id " +
                                consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);

                    if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && userDomain.startsWith
                            (OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Federated prefix found in domain " + userDomain + "and federated users are not" +
                                    " mapped to local users. Hence setting user to a federated user");
                        }
                        user.setFederatedUser(true);
                    }

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

    /**
     * @param connection      database connection
     * @param tokenId         accesstoken
     * @param tokenState      state of the token need to be updated.
     * @param tokenStateId    token state id.
     * @param userStoreDomain user store domain.
     * @throws IdentityOAuth2Exception
     */
    public void setAccessTokenState(Connection connection, String tokenId, String tokenState,
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
    public void revokeTokens(String[] tokens) throws IdentityOAuth2Exception {

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            revokeTokensIndividual(tokens);
        } else {
            revokeTokensBatch(tokens);
        }
    }

    public void revokeTokensBatch(String[] tokens) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String token : tokens){
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
                connection.setAutoCommit(false);
                String sqlQuery = SQLQueries.REVOKE_ACCESS_TOKEN.replace(IDN_OAUTH2_ACCESS_TOKEN,
                        accessTokenStoreTable);
                ps = connection.prepareStatement(sqlQuery);
                for (String token : tokens) {
                    ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                    ps.setString(2, UUID.randomUUID().toString());
                    ps.setString(3, persistenceProcessor.getProcessedAccessTokenIdentifier(token));
                    ps.addBatch();
                }
                ps.executeBatch();
                connection.commit();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollBack(connection);
                throw new IdentityOAuth2Exception("Error occurred while revoking Access Tokens : " +
                        Arrays.toString(tokens), e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
            }
        } if (tokens.length == 1) {
            try {
                connection.setAutoCommit(true);
                String sqlQuery = SQLQueries.REVOKE_ACCESS_TOKEN.replace(IDN_OAUTH2_ACCESS_TOKEN,
                        accessTokenStoreTable);
                ps = connection.prepareStatement(sqlQuery);
                ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                ps.setString(2, UUID.randomUUID().toString());
                ps.setString(3, persistenceProcessor.getProcessedAccessTokenIdentifier(tokens[0]));
                ps.executeUpdate();
            } catch (SQLException e) {
                //IdentityDatabaseUtil.rollBack(connection);
                throw new IdentityOAuth2Exception("Error occurred while revoking Access Token : " +
                        Arrays.toString(tokens), e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
            }
        }
    }

    public void revokeTokensIndividual(String[] tokens) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String token : tokens){
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
                ps.setString(3, persistenceProcessor.getProcessedAccessTokenIdentifier(token));
                int count = ps.executeUpdate();
                if (log.isDebugEnabled()) {
                    log.debug("Number of rows being updated : " + count);
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
    public void revokeToken(String tokenId, String userId) throws IdentityOAuth2Exception {

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
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token with ID : " + tokenId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * @param authenticatedUser
     * @return
     * @throws IdentityOAuth2Exception
     */
    public Set<String> getAccessTokensForUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens of user: " + authenticatedUser.toString());
        }

        String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> accessTokens = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
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
            while (rs.next()) {
                accessTokens.add(persistenceProcessor.getPreprocessedAccessTokenIdentifier(rs.getString(1)));
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
     * @param authenticatedUser
     * @return
     * @throws IdentityOAuth2Exception
     */
    public Set<String> getAuthorizationCodesForUser(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization codes of user: " + authenticatedUser.toString());
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        try {
            String sqlQuery = SQLQueries.GET_AUTHORIZATION_CODES_BY_AUTHZUSER;
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
            ps.setString(3, authenticatedUser.getUserStoreDomain());
            ps.setString(4, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();

            while (rs.next()){
                long validityPeriodInMillis = rs.getLong(3);
                Timestamp timeCreated = rs.getTimestamp(2, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long issuedTimeInMillis = timeCreated.getTime();

                // if authorization code is not expired.
                if (OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodInMillis) > 1000) {
                    authorizationCodes.add(persistenceProcessor.getPreprocessedAuthzCode(rs.getString(1)));
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
        return authorizationCodes;
    }

    /**
     * Retrieves active access tokens for the given consumer key.
     *
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    public Set<String> getActiveTokensForConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access tokens of client: " + consumerKey);
        }

        Set<String> activeTokens = getActiveTokensForConsumerKey(consumerKey, IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                activeTokens.addAll(getActiveTokensForConsumerKey(consumerKey, availableDomainMapping.getKey()));
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
    private Set<String> getActiveTokensForConsumerKey(String consumerKey, String userStoreDomain)
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
            while (rs.next()) {
                accessTokens.add(persistenceProcessor.getPreprocessedAccessTokenIdentifier(rs.getString(1)));
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
    public Set<AccessTokenDO> getActiveDetailedTokensForConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access tokens for client: " + consumerKey);
        }

        Set<AccessTokenDO> accessTokenDOs = getActiveDetailedTokensForConsumerKey(consumerKey,
                IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                accessTokenDOs.addAll(getActiveDetailedTokensForConsumerKey(consumerKey,
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
    private Set<AccessTokenDO> getActiveDetailedTokensForConsumerKey(String consumerKey, String userStoreDomain)
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
                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authzUser);
                    user.setTenantDomain(OAuth2Util.getTenantDomain(tenentId));
                    user.setUserStoreDomain(userDomain);
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

    public Set<String> getAuthorizationCodesForConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization codes for client: " + consumerKey);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        try {
            String sqlQuery = SQLQueries.GET_AUTHORIZATION_CODES_FOR_CONSUMER_KEY;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            rs = ps.executeQuery();
            while (rs.next()) {
                authorizationCodes.add(persistenceProcessor.getPreprocessedAuthzCode(rs.getString(1)));
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting authorization codes from authorization code " +
                    "table for the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }

    public Set<String> getActiveAuthorizationCodesForConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active authorization codes for client: " + consumerKey);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        try {
            String sqlQuery = SQLQueries.GET_ACTIVE_AUTHORIZATION_CODES_FOR_CONSUMER_KEY;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setString(2, OAuthConstants.AuthorizationCodeState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                authorizationCodes.add(persistenceProcessor.getPreprocessedAuthzCode(rs.getString(1)));
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting authorization codes from authorization code " +
                    "table for the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }

    /**
     * This method is to list the application authorized by OAuth resource owners
     *
     * @param authzUser username of the resource owner
     * @return set of distinct client IDs authorized by user until now
     * @throws IdentityOAuth2Exception if failed to update the access token
     */
    public Set<String> getAllTimeAuthorizedClientIds(AuthenticatedUser authzUser) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all authorized clients by user: " + authzUser.toString());
        }

        PreparedStatement ps = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        ResultSet rs = null;
        Set<String> distinctConsumerKeys = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(authzUser.getUserStoreDomain());

        try {
            int tenantId = OAuth2Util.getTenantId(tenantDomain);

            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserId(SQLQueries.
                    GET_DISTINCT_APPS_AUTHORIZED_BY_USER_ALL_TIME, authzUser.toString());

            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain);
            } else {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            ps.setInt(2, tenantId);
            ps.setString(3, userDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                String consumerKey = persistenceProcessor.getPreprocessedClientId(rs.getString(1));
                distinctConsumerKeys.add(consumerKey);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while retrieving all distinct Client IDs authorized by " +
                            "User ID : " + authzUser + " until now", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        if (log.isDebugEnabled()) {
            StringBuilder consumerKeys = new StringBuilder();
            for (String consumerKey : distinctConsumerKeys) {
                consumerKeys.append(consumerKey).append(" ");
            }
            log.debug("Found authorized clients " + consumerKeys.toString() + " for user: " + authzUser.toString());
        }
        return distinctConsumerKeys;
    }

    /**
     * This method is to get resource scope key of the resource uri
     *
     * @param resourceUri Resource Path
     * @return Scope key of the resource
     * @throws IdentityOAuth2Exception if failed to find the resource scope
     */
    @Deprecated
    public String findScopeOfResource(String resourceUri) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving scope for resource: " + resourceUri);
        }
        String sql = SQLQueries.RETRIEVE_SCOPE_NAME_FOR_RESOURCE;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
                PreparedStatement ps = connection.prepareStatement(sql);) {

            ps.setString(1, resourceUri);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("NAME");
                }
            }
            return null;
        } catch (SQLException e) {
            String errorMsg = "Error getting scopes for resource - " + resourceUri + " : " + e.getMessage();
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * This method is to get resource scope key and tenant id of the resource uri
     *
     * @param resourceUri Resource Path
     * @return Pair which contains resource scope key and the tenant id
     * @throws IdentityOAuth2Exception if failed to find the tenant and resource scope
     */
    public Pair<String, Integer> findTenantAndScopeOfResource(String resourceUri) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving tenant and scope for resource: " + resourceUri);
        }
        String sql = SQLQueries.RETRIEVE_SCOPE_WITH_TENANT_FOR_RESOURCE;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
                PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, resourceUri);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String scopeName = rs.getString("NAME");
                    int tenantId = rs.getInt("TENANT_ID");
                    if (log.isDebugEnabled()) {
                        log.debug("Found tenant id: " + tenantId + " and scope: " + scopeName + " for resource: " +
                                resourceUri);
                    }
                    return Pair.of(scopeName, tenantId);
                }
            }
            return null;
        } catch (SQLException e) {
            String errorMsg = "Error getting scopes for resource - " + resourceUri;
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    public boolean validateScope(Connection connection, String accessToken, String resourceUri) {
        return false;
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
    public void invalidateAndCreateNewToken(String oldAccessTokenId, String tokenState,
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
            setAccessTokenState(connection, oldAccessTokenId, tokenState, tokenStateId, userStoreDomain);

            String newAccessToken = accessTokenDO.getAccessToken();
            // store new token in the DB
            storeAccessToken(newAccessToken, consumerKey, accessTokenDO, connection, userStoreDomain);

            // update new access token against authorization code if token obtained via authorization code grant type
            updateTokenIdIfAutzCodeGrantType(oldAccessTokenId, accessTokenDO.getTokenId(), connection);

            // commit both transactions
            connection.commit();
        } catch (SQLException e) {
            String errorMsg = "Error while regenerating access token";
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    /**
     * Revoke the OAuth Consent which is recorded in the IDN_OPENID_USER_RPS table against the user for a particular
     * Application
     *
     * @param username        - Username of the Consent owner
     * @param applicationName - Name of the OAuth App
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception - If an unexpected error occurs.
     */
    public void revokeOAuthConsentByApplicationAndUser(String username, String applicationName)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking OAuth consent for application: " + applicationName + " by user: " + username);
        }

        if (username == null || applicationName == null) {
            log.error("Could not remove consent of user " + username + " for application " + applicationName);
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            connection.setAutoCommit(false);

            String sql = SQLQueries.DELETE_USER_RPS;

            ps = connection.prepareStatement(sql);
            ps.setString(1, username);
            ps.setString(2, applicationName);
            ps.execute();
            connection.commit();

        } catch (SQLException e) {
            String errorMsg = "Error deleting OAuth consent of Application " + applicationName + " and User " + username;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Revoke the OAuth Consent which is recorded in the IDN_OPENID_USER_RPS table against the user for a particular
     * Application
     *
     * @param username        - Username of the Consent owner
     * @param applicationName - Name of the OAuth App
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception - If an unexpected error occurs.
     */
    public void revokeOAuthConsentByApplicationAndUser(String username, String tenantDomain, String applicationName)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking OAuth consent for application: " + applicationName + " by user: " + username + " " +
                    "tenant: " + tenantDomain);
        }

        if (username == null || applicationName == null) {
            log.error("Could not remove consent of user " + username + " for application " + applicationName);
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            connection.setAutoCommit(false);

            String sql = SQLQueries.DELETE_USER_RPS_IN_TENANT;

            ps = connection.prepareStatement(sql);
            ps.setString(1, username);
            ps.setInt(2, IdentityTenantUtil.getTenantId(tenantDomain));
            ps.setString(3, applicationName);
            ps.execute();
            connection.commit();

        } catch (SQLException e) {
            String errorMsg = "Error deleting OAuth consent of Application " + applicationName + " and User " + username;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Update the OAuth Consent Approve Always which is recorded in the IDN_OPENID_USER_RPS table against the user for a particular
     * Application
     *
     * @param tenantAwareUserName - Username of the Consent owner
     * @param applicationName     - Name of the OAuth App
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception - If an unexpected error occurs.
     */
    public void updateApproveAlwaysForAppConsentByResourceOwner(String tenantAwareUserName, String tenantDomain, String applicationName, String state)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Setting consent for " + state + " OAuth consent for application: " + applicationName + " by " +
                    "user: " + tenantAwareUserName + " tenant: " + tenantDomain);
        }

        if (tenantAwareUserName == null || applicationName == null) {
            log.error("Could not remove consent of user " + tenantAwareUserName + " for application " + applicationName);
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            connection.setAutoCommit(false);

            String sql = SQLQueries.UPDATE_TRUSTED_ALWAYS_IDN_OPENID_USER_RPS;

            ps = connection.prepareStatement(sql);
            ps.setString(1, state);
            ps.setString(2, tenantAwareUserName);
            ps.setInt(3, IdentityTenantUtil.getTenantId(tenantDomain));
            ps.setString(4, applicationName);
            ps.execute();
            connection.commit();

        } catch (SQLException e) {
            String errorMsg = "Error updating trusted always in a consent of Application " + applicationName + " and User " + tenantAwareUserName;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Retrieves AccessTokenDOs of the given tenant.
     *
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    public Set<AccessTokenDO> getAccessTokensOfTenant(int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all access tokens of tenant id: " + tenantId);
        }

        Set<AccessTokenDO> accessTokenDOs = getAccessTokensOfTenant(tenantId, IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                accessTokenDOs.addAll(getAccessTokensOfTenant(tenantId, availableDomainMapping.getKey()));
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
    private Set<AccessTokenDO> getAccessTokensOfTenant(int tenantId, String userStoreDomain)
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
                String accessToken = persistenceProcessor.
                        getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = persistenceProcessor.
                            getPreprocessedRefreshToken(resultSet.getString(2));
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

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authzUser);
                    user.setTenantDomain(OAuth2Util.getTenantDomain(tenantId));
                    user.setUserStoreDomain(userStoreDomain);
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

    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all ACTIVE and EXPIRED access tokens of userstore: " + userStoreDomain + " tenant " +
                    "id: " + tenantId);
        }
        //we do not support access token partitioning here
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
                String accessToken = persistenceProcessor.getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = persistenceProcessor.
                            getPreprocessedRefreshToken(resultSet.getString(2));
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

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authzUser);
                    user.setTenantDomain(OAuth2Util.getTenantDomain(tenantId));
                    user.setUserStoreDomain(userStoreDomain);
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

    public void renameUserStoreDomainInAccessTokenTable(int tenantId, String currentUserStoreDomain, String
            newUserStoreDomain) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Renaming userstore domain: " + currentUserStoreDomain + " as: " + newUserStoreDomain
                    + " tenant id: " + tenantId + " in IDN_OAUTH2_ACCESS_TOKEN table");
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        currentUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(currentUserStoreDomain);
        newUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(newUserStoreDomain);
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

    public List<AuthzCodeDO> getLatestAuthorizationCodesOfTenant(int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest authorization codes of tenant id: " + tenantId);
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;

        List<AuthzCodeDO> latestAuthzCodes = new ArrayList<>();
        try {
            String sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_TENANT;
            ps = connection.prepareStatement(sqlQuery);
            ps.setInt(1, tenantId);
            rs = ps.executeQuery();
            while (rs.next()) {
                String authzCodeId = rs.getString(1);
                String authzCode = rs.getString(2);
                String consumerKey = rs.getString(3);
                String authzUser = rs.getString(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                Timestamp issuedTime = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = rs.getLong(7);
                String callbackUrl = rs.getString(8);
                String userStoreDomain = rs.getString(9);

                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(authzUser);
                user.setUserStoreDomain(userStoreDomain);
                user.setTenantDomain(OAuth2Util.getTenantDomain(tenantId));
                latestAuthzCodes.add(new AuthzCodeDO(user, scope, issuedTime, validityPeriodInMillis, callbackUrl,
                        consumerKey, authzCode, authzCodeId));
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while retrieving latest authorization codes of tenant " +
                    ":" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return latestAuthzCodes;
    }

    public List<AuthzCodeDO> getLatestAuthorizationCodesOfUserStore(int tenantId, String userStorDomain) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest authorization codes of userstore: " + userStorDomain + " tenant id: " +
                    tenantId);
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        String userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStorDomain);

        List<AuthzCodeDO> latestAuthzCodes = new ArrayList<>();
        try {
            String sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_USER_DOMAIN;
            ps = connection.prepareStatement(sqlQuery);
            ps.setInt(1, tenantId);
            ps.setString(2, userStoreDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                String authzCodeId = rs.getString(1);
                String authzCode = rs.getString(2);
                String consumerKey = rs.getString(3);
                String authzUser = rs.getString(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                Timestamp issuedTime = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = rs.getLong(7);
                String callbackUrl = rs.getString(8);

                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(authzUser);
                user.setUserStoreDomain(userStoreDomain);
                user.setTenantDomain(OAuth2Util.getTenantDomain(tenantId));
                latestAuthzCodes.add(new AuthzCodeDO(user, scope, issuedTime, validityPeriodInMillis, callbackUrl,
                        consumerKey, authzCode, authzCodeId));
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while retrieving latest authorization codes of user " +
                    "store : " + userStoreDomain + " in tenant :" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return latestAuthzCodes;
    }

    public void renameUserStoreDomainInAuthorizationCodeTable(int tenantId, String currentUserStoreDomain, String
            newUserStoreDomain) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Renaming userstore domain: " + currentUserStoreDomain + " as: " + newUserStoreDomain
                    + " tenant id: " + tenantId + " in IDN_OAUTH2_AUTHORIZATION_CODE table");
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        currentUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(currentUserStoreDomain);
        newUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(newUserStoreDomain);
        try {
            String sqlQuery = SQLQueries.RENAME_USER_STORE_IN_AUTHORIZATION_CODES_TABLE;
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
                    "in tenant :" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    public String getCodeIdByAuthorizationCode(String authzCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
            log.debug("Retrieving id of authorization code(hashed): " + DigestUtils.sha256Hex(authzCode));
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = SQLQueries.RETRIEVE_CODE_ID_BY_AUTHORIZATION_CODE;

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, persistenceProcessor.getProcessedAuthzCode(authzCode));
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("CODE_ID");
            }
            connection.commit();
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Code ID' for " +
                    "authorization code : " + authzCode;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    public String getAuthzCodeByCodeId(String codeId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization code by code id: " + codeId);
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = SQLQueries.RETRIEVE_AUTHZ_CODE_BY_CODE_ID;

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, codeId);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("AUTHORIZATION_CODE");
            }
            connection.commit();
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Authorization Code' for " +
                    "authorization code : " + codeId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    /**
     * Retrieves token id of the given token.
     *
     * @param token
     * @return
     * @throws IdentityOAuth2Exception
     */
    public String getTokenIdByToken(String token) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieving id of access token(hashed): " + DigestUtils.sha256Hex(token));
        }

        String tokenId = getTokenIdByToken(token, IdentityUtil.getPrimaryDomainName());

        if (tokenId == null && OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.
                checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping: availableDomainMappings.entrySet()) {
                tokenId = getTokenIdByToken(token, availableDomainMapping.getKey());
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
    private String getTokenIdByToken(String token, String userStoreDomain) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.RETRIEVE_TOKEN_ID_BY_TOKEN,
                    userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, persistenceProcessor.getProcessedAccessTokenIdentifier(token));
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
    public String getTokenByTokenId(String tokenId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access token by token id: " + tokenId);
        }

        String token = getTokenByTokenId(tokenId, IdentityUtil.getPrimaryDomainName());

        if (token == null && OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.
                checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping: availableDomainMappings.entrySet()) {
                token = getTokenByTokenId(tokenId, availableDomainMapping.getKey());
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
    private String getTokenByTokenId(String tokenId, String userStoreDomain) throws IdentityOAuth2Exception {

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

    /**
     * Get the list of roles associated for a given scope.
     *
     * @param scopeName Name of the scope.
     * @return The Set of roles associated with the given scope.
     * @throws IdentityOAuth2Exception If an SQL error occurs while retrieving the roles.
     */
    @Deprecated
    public Set<String> getBindingsOfScopeByScopeName(String scopeName) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving bindings of scope: " + scopeName);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();

        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> bindings = new HashSet<>();

        try {
            String sql = SQLQueries.RETRIEVE_BINDINGS_OF_SCOPE;

            ps = connection.prepareStatement(sql);
            ps.setString(1, scopeName);
            rs = ps.executeQuery();

            while (rs.next()) {
                String binding = rs.getString("SCOPE_BINDING");
                if (!binding.isEmpty()) {
                    bindings.add(binding);
                }
            }
            connection.commit();
            if (log.isDebugEnabled()) {
                StringBuilder bindingsStringBuilder = new StringBuilder();
                for (String binding : bindings) {
                    bindingsStringBuilder.append(binding).append(" ");
                }
                log.debug("Binding for scope: " + scopeName + " found: " + bindingsStringBuilder.toString());
            }
            return bindings;
        } catch (SQLException e) {
            String errorMsg = "Error getting roles of scope - " + scopeName;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
    }

    /**
     * Get the list of roles associated for a given scope.
     *
     * @param scopeName name of the scope.
     * @param tenantId Tenant Id
     * @return The Set of roles associated with the given scope.
     * @throws IdentityOAuth2Exception If an SQL error occurs while retrieving the roles.
     */
    public Set<String> getBindingsOfScopeByScopeName(String scopeName, int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving bindings of scope: " + scopeName + " tenant id: " + tenantId);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();

        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> bindings = new HashSet<>();

        try {
            String sql = SQLQueries.RETRIEVE_BINDINGS_OF_SCOPE_FOR_TENANT;

            ps = connection.prepareStatement(sql);
            ps.setString(1, scopeName);
            ps.setInt(2, tenantId);
            rs = ps.executeQuery();

            while (rs.next()) {
                String binding = rs.getString("SCOPE_BINDING");
                if (!binding.isEmpty()) {
                    bindings.add(binding);
                }
            }
            connection.commit();
            if (log.isDebugEnabled()) {
                StringBuilder bindingStringBuilder = new StringBuilder();
                for (String binding : bindings) {
                    bindingStringBuilder.append(binding).append(" ");
                }
                log.debug("Binding for scope: " + scopeName + " found: " + bindingStringBuilder.toString() + " tenant" +
                        " id: " + tenantId);
            }
            return bindings;
        } catch (SQLException e) {
            String errorMsg = "Error getting bindings of scope - " + scopeName;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
    }

    public void updateAppAndRevokeTokensAndAuthzCodes(String consumerKey, Properties properties,
                                                      String[] authorizationCodes, String[] accessTokens)
            throws IdentityOAuth2Exception, IdentityApplicationManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Updating state of client: " + consumerKey + " and revoking all access tokens and " +
                    "authorization codes.");
        }

        String action;
        if (properties.containsKey(OAuthConstants.ACTION_PROPERTY_KEY)) {
            action = properties.getProperty(OAuthConstants.ACTION_PROPERTY_KEY);
        } else {
            throw new IdentityOAuth2Exception("Invalid operation.");
        }

        Connection connection = null;
        PreparedStatement updateStateStatement = null;
        PreparedStatement revokeActiveTokensStatement = null;
        PreparedStatement deactivateActiveCodesStatement = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            connection.setAutoCommit(false);
            if (OAuthConstants.ACTION_REVOKE.equals(action)) {
                String newAppState;
                if (properties.containsKey(OAuthConstants.OAUTH_APP_NEW_STATE)) {
                    newAppState = properties.getProperty(OAuthConstants.OAUTH_APP_NEW_STATE);
                } else {
                    throw new IdentityOAuth2Exception("New App State is not specified.");
                }

                if (log.isDebugEnabled()) {
                    log.debug("Changing the state of the client: " + consumerKey + " to " + newAppState + " state.");
                }

                // update application state of the oauth app
                updateStateStatement = connection.prepareStatement
                        (org.wso2.carbon.identity.oauth.dao.SQLQueries.OAuthAppDAOSQLQueries.UPDATE_APPLICATION_STATE);
                updateStateStatement.setString(1, newAppState);
                updateStateStatement.setString(2, consumerKey);
                updateStateStatement.execute();

            } else if (OAuthConstants.ACTION_REGENERATE.equals(action)) {
                String newSecretKey;
                if (properties.containsKey(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY)) {
                    newSecretKey = properties.getProperty(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY);
                } else {
                    throw new IdentityOAuth2Exception("New Consumer Secret is not specified.");
                }

                if (log.isDebugEnabled()) {
                    log.debug("Regenerating the client secret of: " + consumerKey);
                }

                // update consumer secret of the oauth app
                updateStateStatement = connection.prepareStatement
                        (org.wso2.carbon.identity.oauth.dao.SQLQueries.OAuthAppDAOSQLQueries.UPDATE_OAUTH_SECRET_KEY);
                updateStateStatement.setString(1, persistenceProcessor.getProcessedClientSecret(newSecretKey));
                updateStateStatement.setString(2, persistenceProcessor.getProcessedClientId(consumerKey));
                updateStateStatement.execute();
            }

            //Revoke all active access tokens
            if (ArrayUtils.isNotEmpty(accessTokens)) {
                String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
                if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
                    for (String token : accessTokens) {
                        String sqlQuery = OAuth2Util.getTokenPartitionedSqlByToken(SQLQueries.REVOKE_APP_ACCESS_TOKEN,
                                token);

                        revokeActiveTokensStatement = connection.prepareStatement(sqlQuery);
                        revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                        revokeActiveTokensStatement.setString(2, UUID.randomUUID().toString());
                        revokeActiveTokensStatement.setString(3, consumerKey);
                        int count = revokeActiveTokensStatement.executeUpdate();
                        if (log.isDebugEnabled()) {
                            log.debug("Number of rows being updated : " + count);
                        }
                    }
                } else {
                    String sqlQuery = SQLQueries.REVOKE_APP_ACCESS_TOKEN.replace(IDN_OAUTH2_ACCESS_TOKEN, accessTokenStoreTable);
                    revokeActiveTokensStatement = connection.prepareStatement(sqlQuery);
                    revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                    revokeActiveTokensStatement.setString(2, UUID.randomUUID().toString());
                    revokeActiveTokensStatement.setString(3, consumerKey);
                    revokeActiveTokensStatement.setString(4, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
                    revokeActiveTokensStatement.execute();
                }
            }

            //Deactivate all active authorization codes
            String sqlQuery = SQLQueries.UPDATE_AUTHORIZATION_CODE_STATE_FOR_CONSUMER_KEY;
            deactivateActiveCodesStatement = connection.prepareStatement(sqlQuery);
            deactivateActiveCodesStatement.setString(1, OAuthConstants.AuthorizationCodeState.REVOKED);
            deactivateActiveCodesStatement.setString(2, consumerKey);
            deactivateActiveCodesStatement.executeUpdate();

            connection.commit();

        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        } finally {
            IdentityDatabaseUtil.closeStatement(updateStateStatement);
            IdentityDatabaseUtil.closeStatement(revokeActiveTokensStatement);
            IdentityDatabaseUtil.closeAllConnections(connection, null, deactivateActiveCodesStatement);
        }
    }



    private void recoverFromConAppKeyConstraintViolation(String accessToken, String consumerKey, AccessTokenDO
            accessTokenDO, Connection connection, String userStoreDomain, int retryAttempt)
            throws IdentityOAuth2Exception {

        log.warn("Retry attempt to recover 'CON_APP_KEY' constraint violation : " + retryAttempt);

        AccessTokenDO latestNonActiveToken = retrieveLatestToken(connection, consumerKey, accessTokenDO.getAuthzUser(),
                userStoreDomain, OAuth2Util.buildScopeString(accessTokenDO.getScope()), false);

        AccessTokenDO latestActiveToken = retrieveLatestToken(connection, consumerKey, accessTokenDO.getAuthzUser(),
                userStoreDomain, OAuth2Util.buildScopeString(accessTokenDO.getScope()), true);

        if (latestActiveToken != null) {
            if (latestNonActiveToken == null ||
                    latestActiveToken.getIssuedTime().after(latestNonActiveToken.getIssuedTime())) {
                if (maxPoolSize == 0) {
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
                            retryAttempt);
                } else {
                    // In here we have to use new token since we have asynchronous communication. User already
                    // received that token

                    // Inactivate latest active token.
                    setAccessTokenState(connection, latestActiveToken.getTokenId(), "INACTIVE",
                            UUID.randomUUID().toString(), userStoreDomain);

                    // Update token issued time make this token as latest token & try to store it again.
                    accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                    storeAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain,
                            retryAttempt);
                }
            } else {
                // Inactivate latest active token.
                setAccessTokenState(connection, latestActiveToken.getTokenId(), "INACTIVE",
                        UUID.randomUUID().toString(), userStoreDomain);

                // Update token issued time make this token as latest token & try to store it again.
                accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                storeAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain, retryAttempt);
            }
        } else {
            // In this case another process already updated the latest active token to inactive.

            // Update token issued time make this token as latest token & try to store it again.
            accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
            storeAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain, retryAttempt);
        }
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
    public List<AccessTokenDO> retrieveLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
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
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(authzUser.getUserStoreDomain());
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);

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
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
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
                    String accessToken = persistenceProcessor.getPreprocessedAccessTokenIdentifier(
                            resultSet.getString(1));
                    String refreshToken = null;
                    if (resultSet.getString(2) != null) {
                        refreshToken = persistenceProcessor.getPreprocessedRefreshToken(resultSet.getString(2));
                    }
                    long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone
                            ("UTC"))).getTime();
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodInMillis = resultSet.getLong(6);

                    String userType = resultSet.getString(8);
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);
                    // data loss at dividing the validity period but can be neglected
                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(tenantAwareUsernameWithNoUserDomain);
                    user.setTenantDomain(tenantDomain);
                    user.setUserStoreDomain(userDomain);

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

    public AccessTokenDO retrieveLatestToken(Connection connection, String consumerKey, AuthenticatedUser authzUser,
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
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
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
                String accessToken = persistenceProcessor.getPreprocessedAccessTokenIdentifier(
                        resultSet.getString(1));
                String refreshToken = null;
                if (resultSet.getString(2) != null) {
                    refreshToken = persistenceProcessor.getPreprocessedRefreshToken(resultSet.getString(2));
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
                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(tenantAwareUsernameWithNoUserDomain);
                user.setTenantDomain(tenantDomain);
                user.setUserStoreDomain(userDomain);
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

    /**
     * Revokes access tokens issued against specified consumer key and specified tenant id when SaaS is disabled.
     *
     * @param consumerKey client ID
     * @param tenantId    application tenant ID
     * @throws IdentityOAuth2Exception
     */
    public void revokeSaaSTokensOfOtherTenants(String consumerKey, int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking access tokens of client: " + consumerKey + " tenant id: " + tenantId + " issued for " +
                    "other tenants");
        }

        if (consumerKey == null) {
            log.error("Couldn't revoke token for tenant ID: " + tenantId + " because of null consumer key");
            return;
        }

        revokeSaaSTokensOfOtherTenants(consumerKey, IdentityUtil.getPrimaryDomainName(), tenantId);

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                revokeSaaSTokensOfOtherTenants(consumerKey, availableDomainMapping.getKey(), tenantId);
            }
        }
    }

    /**
     * Revokes access tokens issued against specified consumer key, specified user store & specified tenant id when SaaS
     * is disabled.
     *
     * @param consumerKey
     * @param userStoreDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    public void revokeSaaSTokensOfOtherTenants(String consumerKey, String userStoreDomain, int tenantId) throws
            IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.REVOKE_SAAS_TOKENS_OF_OTHER_TENANTS,
                    userStoreDomain);
            ps = connection.prepareStatement(sql);
            ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            ps.setString(4, consumerKey);
            ps.setInt(5, tenantId);
            ps.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            String errorMsg = "Error revoking access tokens for client ID: " + consumerKey + "and tenant ID:" + tenantId;
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    private boolean isPersistenceEnabled() {

        boolean enablePersist = DEFAULT_PERSIST_ENABLED;
        if (IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_ENABLE) != null) {
            enablePersist = Boolean.parseBoolean(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_ENABLE));
        } else if (IdentityUtil.getProperty(FRAMEWORK_PERSISTENCE_ENABLE) != null) {
            enablePersist = Boolean.parseBoolean(IdentityUtil.getProperty(FRAMEWORK_PERSISTENCE_ENABLE));
        }

        return enablePersist;
    }

    private static int getTokenPersistPoolSize () {

        int maxPoolSize = DEFAULT_POOL_SIZE;
        try {
            String maxPoolSizeConfigValue = IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_POOLSIZE);
            if (StringUtils.isNotBlank(maxPoolSizeConfigValue)) {
                maxPoolSize = Integer.parseInt(maxPoolSizeConfigValue);
            } else {
                maxPoolSizeConfigValue = IdentityUtil.getProperty(FRAMEWORK_PERSISTENCE_POOLSIZE);
                if (StringUtils.isNotBlank(maxPoolSizeConfigValue)) {
                    maxPoolSize = Integer.parseInt(maxPoolSizeConfigValue);
                }
            }
        } catch (NumberFormatException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while parsing OAuth Token Persistence PoolSize", e);
            }
            log.warn("OAuth Token Persistence Pool size is not configured. Using default value: " + maxPoolSize);
        }

        return maxPoolSize;
    }
}
