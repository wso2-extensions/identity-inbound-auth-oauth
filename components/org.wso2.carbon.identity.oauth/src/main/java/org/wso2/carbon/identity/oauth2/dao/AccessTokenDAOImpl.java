/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.util.JdbcUtils;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants.OAuthColumnName;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.core.util.IdentityUtil.getProperty;
import static org.wso2.carbon.identity.core.util.LambdaExceptionUtils.rethrowRowMapper;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.GET_ACCESS_TOKENS_BY_BINDING_REFERENCE;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.STORE_TOKEN_BINDING;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.IS_EXTENDED_TOKEN;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getUserResidentTenantDomain;

/**
 * Access token related data access object implementation.
 */
public class AccessTokenDAOImpl extends AbstractOAuthDAO implements AccessTokenDAO {

    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";
    private static final int DEFAULT_TOKEN_PERSIST_RETRY_COUNT = 5;
    private static final String IDN_OAUTH2_ACCESS_TOKEN = "IDN_OAUTH2_ACCESS_TOKEN";
    private static final String CONSENTED_TOKEN_COLUMN_NAME = "CONSENTED_TOKEN";
    private boolean isTokenCleanupFeatureEnabled = OAuthServerConfiguration.getInstance().isTokenCleanupEnabled();
    private static final String DEFAULT_TOKEN_TO_SESSION_MAPPING = "DEFAULT";

    private static final Log log = LogFactory.getLog(AccessTokenDAOImpl.class);
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

        String accessTokenHash = accessToken;
        try {
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
            //check for persist alias for the token type
            if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                accessTokenHash = oauthTokenIssuer.getAccessTokenHash(accessToken);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Error while getting access token hash for token(hashed): " + DigestUtils
                        .sha256Hex(accessTokenHash));
            }
            throw new IdentityOAuth2Exception("Error while getting access token hash.", e);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
        }

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Persisting access token(hashed): " + DigestUtils.sha256Hex(accessTokenHash) + " for " +
                        "client: " + consumerKey + " user: " + accessTokenDO.getAuthzUser().getLoggableUserId()
                        + " scope: " + Arrays.toString(accessTokenDO.getScope()));
            } else {
                log.debug("Persisting access token for client: " + consumerKey + " user: " +
                        accessTokenDO.getAuthzUser().getLoggableUserId() + " scope: "
                        + Arrays.toString(accessTokenDO.getScope()));
            }
        }
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        String userDomain = OAuth2Util.getUserStoreDomain(accessTokenDO.getAuthzUser());
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(accessTokenDO.getAuthzUser());
        PreparedStatement insertTokenPrepStmt = null;
        PreparedStatement addScopePrepStmt = null;
        PreparedStatement insertTokenExtendedAttributePrepStmt = null;

        if (log.isDebugEnabled()) {
            String username;
            if (isFederatedUser(accessTokenDO)) {
                username = accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier();
            } else {
                username = accessTokenDO.getAuthzUser().toFullQualifiedUsername();
            }
            log.debug("Userstore domain for user: " + username + " is " + userDomain);
        }

        String sql;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN_WITH_IDP_NAME_WITH_CONSENTED_TOKEN;
            } else {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN_WITH_IDP_NAME;
            }
        } else {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN_WITH_CONSENTED_TOKEN;
            } else {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN;
            }
        }
        sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userDomain);
        String sqlAddScopes = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.INSERT_OAUTH2_TOKEN_SCOPE,
                userDomain);
        String sqlInsertTokenExtendedAttribute = OAuth2Util.getTokenPartitionedSqlByUserStore(
                SQLQueries.INSERT_OAUTH2_TOKEN_ATTRIBUTES, userDomain);

        boolean doInsertTokenExtendedAttributes = OAuth2ServiceComponentHolder.isTokenExtendedTableExist() &&
                accessTokenDO.getAccessTokenExtendedAttributes() != null &&
                accessTokenDO.getAccessTokenExtendedAttributes().isExtendedToken();
        try {
            insertTokenPrepStmt = connection.prepareStatement(sql);
            insertTokenPrepStmt.setString(1, getPersistenceProcessor().getProcessedAccessTokenIdentifier(
                    accessTokenHash));

            if (accessTokenDO.getRefreshToken() != null) {
                insertTokenPrepStmt.setString(2,
                        getPersistenceProcessor().getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
            } else {
                insertTokenPrepStmt.setString(2, accessTokenDO.getRefreshToken());
            }

            insertTokenPrepStmt.setString(3, accessTokenDO.getAuthzUser().getUserName());
            String userTenantDomain = getUserResidentTenantDomain(accessTokenDO.getAuthzUser());
            int tenantId = OAuth2Util.getTenantId(userTenantDomain);
            insertTokenPrepStmt.setInt(4, tenantId);
            insertTokenPrepStmt.setString(5, OAuth2Util.getSanitizedUserStoreDomain(userDomain));
            insertTokenPrepStmt
                    .setTimestamp(6, accessTokenDO.getIssuedTime(), Calendar.getInstance(TimeZone.getTimeZone(UTC)));
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
                    .setString(16, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(accessTokenHash));
            if (accessTokenDO.getRefreshToken() != null) {
                insertTokenPrepStmt.setString(17,
                        getHashingPersistenceProcessor().getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
            } else {
                insertTokenPrepStmt.setString(17, accessTokenDO.getRefreshToken());
            }
            boolean tokenBindingAvailable = isTokenBindingAvailable(accessTokenDO.getTokenBinding());
            if (tokenBindingAvailable) {
                insertTokenPrepStmt.setString(18, accessTokenDO.getTokenBinding().getBindingReference());
            } else {
                insertTokenPrepStmt.setString(18, NONE);
            }

            String authorizedOrganization = accessTokenDO.getAuthzUser().getAccessingOrganization();
            if (StringUtils.isBlank(authorizedOrganization)) {
                authorizedOrganization = OAuthConstants.AuthorizedOrganization.NONE;
            }
            insertTokenPrepStmt.setString(19, authorizedOrganization);

            int appTenantId = IdentityTenantUtil.getLoginTenantId();
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                    insertTokenPrepStmt.setString(20, Boolean.toString(accessTokenDO.isConsentedToken()));
                    insertTokenPrepStmt.setString(21, authenticatedIDP);
                    // Set tenant ID of the IDP by considering it is same as appTenantID.
                    insertTokenPrepStmt.setInt(22, appTenantId);
                    insertTokenPrepStmt.setString(23, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    insertTokenPrepStmt.setInt(24, appTenantId);
                } else {
                    insertTokenPrepStmt.setString(20, authenticatedIDP);
                    // Set tenant ID of the IDP by considering it is same as appTenantID.
                    insertTokenPrepStmt.setInt(21, appTenantId);
                    insertTokenPrepStmt.setString(22, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    insertTokenPrepStmt.setInt(23, appTenantId);
                }
            } else {
                if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                    insertTokenPrepStmt.setString(20, Boolean.toString(accessTokenDO.isConsentedToken()));
                    insertTokenPrepStmt.setString(21, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    insertTokenPrepStmt.setInt(22, appTenantId);
                } else {
                    insertTokenPrepStmt.setString(20, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    insertTokenPrepStmt.setInt(21, appTenantId);
                }
            }
            insertTokenPrepStmt.executeUpdate();

            String accessTokenId = accessTokenDO.getTokenId();
            addScopePrepStmt = connection.prepareStatement(sqlAddScopes);

            if (accessTokenDO.getScope() != null && accessTokenDO.getScope().length > 0) {
                for (String scope : accessTokenDO.getScope()) {
                    addScopePrepStmt.setString(1, accessTokenId);
                    addScopePrepStmt.setString(2, scope);
                    addScopePrepStmt.setInt(3, tenantId);
                    addScopePrepStmt.addBatch();
                }
            }
            addScopePrepStmt.executeBatch();

            if (tokenBindingAvailable) {
                if (log.isDebugEnabled()) {
                    log.debug("Storing token binding information" +
                            " accessTokenId: " + accessTokenId +
                            " bindingType: " + accessTokenDO.getTokenBinding().getBindingType() +
                            " bindingRef: " + accessTokenDO.getTokenBinding().getBindingReference());
                }
                try (PreparedStatement preparedStatement = connection.prepareStatement(STORE_TOKEN_BINDING)) {
                    preparedStatement.setString(1, accessTokenId);
                    preparedStatement.setString(2, accessTokenDO.getTokenBinding().getBindingType());
                    preparedStatement.setString(3, accessTokenDO.getTokenBinding().getBindingReference());
                    preparedStatement.setString(4, accessTokenDO.getTokenBinding().getBindingValue());
                    preparedStatement.setInt(5, tenantId);
                    preparedStatement.execute();
                }
            }

            if (doInsertTokenExtendedAttributes) {
                insertTokenExtendedAttributePrepStmt = connection.prepareStatement(sqlInsertTokenExtendedAttribute);
                insertTokenExtendedAttributePrepStmt.setString(1, IS_EXTENDED_TOKEN);
                insertTokenExtendedAttributePrepStmt.setString(2, "true");
                insertTokenExtendedAttributePrepStmt.setString(3, accessTokenId);
                insertTokenExtendedAttributePrepStmt.addBatch();
                if (accessTokenDO.getAccessTokenExtendedAttributes().getParameters() != null) {
                    for (Map.Entry<String, String> entry : accessTokenDO.getAccessTokenExtendedAttributes()
                            .getParameters()
                            .entrySet()) {
                        insertTokenExtendedAttributePrepStmt.setString(1, entry.getKey());
                        insertTokenExtendedAttributePrepStmt.setString(2, entry.getValue());
                        insertTokenExtendedAttributePrepStmt.setString(3, accessTokenId);
                        insertTokenExtendedAttributePrepStmt.addBatch();
                    }
                }
                insertTokenExtendedAttributePrepStmt.executeBatch();
            }

            if (retryAttemptCounter > 0) {
                log.info("Successfully recovered 'CON_APP_KEY' constraint violation with the attempt : " +
                        retryAttemptCounter);
            }
        } catch (SQLIntegrityConstraintViolationException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Invalid request", e);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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
        } catch (Exception e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            // Handle constrain violation issue in JDBC drivers which does not throw
            // SQLIntegrityConstraintViolationException or SQLException.
            if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_APP_KEY") || (e.getCause() != null &&
                    StringUtils.containsIgnoreCase(e.getCause().getMessage(), "CON_APP_KEY"))
                    || (e.getCause() != null && e.getCause().getCause() != null &&
                    StringUtils.containsIgnoreCase(e.getCause().getCause().getMessage(), "CON_APP_KEY"))) {
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
            if (doInsertTokenExtendedAttributes) {
                IdentityDatabaseUtil.closeStatement(insertTokenExtendedAttributePrepStmt);
            }
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
                        consumerKey + " user: " + newAccessTokenDO.getAuthzUser().getLoggableUserId() + " scope: "
                        + Arrays.toString(newAccessTokenDO.getScope()));
            } else {
                log.debug("Persisting access token for client: " + consumerKey + " user: "
                        + newAccessTokenDO.getAuthzUser().getLoggableUserId() + " scope: "
                        + Arrays.toString(newAccessTokenDO.getScope()));
            }
        }

        String userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(rawUserStoreDomain);

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            if (existingAccessTokenDO != null) {
                //  Mark the existing access token as expired on database if a token exist for the user
                updateAccessTokenState(connection, existingAccessTokenDO.getTokenId(), OAuthConstants.TokenStates
                        .TOKEN_STATE_EXPIRED, UUID.randomUUID().toString(), userStoreDomain,
                        existingAccessTokenDO.getGrantType());
            }
            insertAccessToken(accessToken, consumerKey, newAccessTokenDO, connection, userStoreDomain);

            if (isTokenCleanupFeatureEnabled && existingAccessTokenDO != null) {
                oldTokenCleanupObject.cleanupTokenByTokenId(existingAccessTokenDO.getTokenId(), connection);
            }
            IdentityDatabaseUtil.commitTransaction(connection);
            return true;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while persisting access token", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, boolean includeExpiredTokens)
            throws IdentityOAuth2Exception {

        return getLatestAccessToken(consumerKey, authzUser, userStoreDomain, scope, NONE, includeExpiredTokens);
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, String tokenBindingReference, boolean includeExpiredTokens)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest access token for client: " + consumerKey + " user: "
                    + authzUser.getLoggableUserId() + " scope: " + scope);
        }
        String tenantDomain = getUserResidentTenantDomain(authzUser);
        String authorizedOrganization = authzUser.getAccessingOrganization();
        if (StringUtils.isBlank(authorizedOrganization)) {
            authorizedOrganization = OAuthConstants.AuthorizedOrganization.NONE;
        }
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        boolean isUsernameCaseSensitive
                = IdentityUtil.isUserStoreCaseSensitive(authzUser.getUserStoreDomain(), tenantId);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = OAuth2Util.getUserStoreDomain(authzUser);
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authzUser);

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {

            String sql = getLatestAccessTokenQuerySQL(connection);

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
            int appTenantId = OAuth2Util.getTenantId(authzUser.getTenantDomain());
            prepStmt.setInt(2, appTenantId);
            if (isUsernameCaseSensitive) {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userDomain);

            if (hashedScope != null) {
                prepStmt.setString(6, hashedScope);
            }

            prepStmt.setString(7, tokenBindingReference);
            prepStmt.setString(8, authorizedOrganization);

            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(9, authenticatedIDP);
                // Set tenant ID of the IDP by considering it is same as appTenantID.
                prepStmt.setInt(10, appTenantId);
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
                    String accessToken = getPersistenceProcessor()
                            .getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                    String refreshToken = null;
                    if (resultSet.getString(2) != null) {
                        refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
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
                    String grantType = resultSet.getString(11);
                    String isConsentedToken = StringUtils.EMPTY;
                    if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                        isConsentedToken = resultSet.getString(12);
                    }
                    // data loss at dividing the validity period but can be neglected
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userDomain,
                            tenantDomain, authenticatedIDP);

                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                    AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, user, OAuth2Util.buildScopeArray
                            (scope), new Timestamp(issuedTime), new Timestamp(refreshTokenIssuedTime)
                            , validityPeriodInMillis, refreshTokenValidityPeriodInMillis, userType);
                    accessTokenDO.setAccessToken(accessToken);
                    accessTokenDO.setRefreshToken(refreshToken);
                    accessTokenDO.setTokenState(tokenState);
                    accessTokenDO.setTokenId(tokenId);
                    accessTokenDO.setGrantType(grantType);
                    accessTokenDO.setAppResidentTenantId(appTenantId);

                    if (StringUtils.isNotEmpty(isConsentedToken)) {
                        accessTokenDO.setIsConsentedToken(Boolean.parseBoolean(isConsentedToken));
                    }
                    if (StringUtils.isNotBlank(tokenBindingReference) && !NONE.equals(tokenBindingReference)) {
                        setTokenBindingToAccessTokenDO(accessTokenDO, connection, tokenId);
                    }
                    if (log.isDebugEnabled() && IdentityUtil
                            .isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                        log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex(accessToken)
                                + " for client: " + consumerKey + " user: " + authzUser.getLoggableUserId()
                                + " scope: " + scope + " token binding reference: " + tokenBindingReference);
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

    private String getLatestAccessTokenQuerySQL(Connection connection) throws SQLException {

        String sql;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                if (connection.getMetaData().getDriverName().contains("MySQL")
                        || connection.getMetaData().getDriverName().contains(FrameworkConstants.H2)
                        || connection.getMetaData().getDriverName().contains(FrameworkConstants.MARIA_DB)) {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_POSTGRESQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_INFORMIX;
                } else {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_ORACLE;
                }
            } else {
                if (connection.getMetaData().getDriverName().contains("MySQL")
                        || connection.getMetaData().getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_POSTGRESQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_ORACLE;
                }
            }
        } else {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                if (connection.getMetaData().getDriverName().contains("MySQL")
                        || connection.getMetaData().getDriverName().contains("H2")) {
                    sql = SQLQueries.GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                    sql = SQLQueries.GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.
                            GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;
                } else {
                    sql = SQLQueries.GET_LATEST_ACCESS_TOKEN_WITH_CONSENTED_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                }
            } else {
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
            }
        }
        return sql;
    }

    private AccessTokenDO getLatestAccessTokenByState(Connection connection, String consumerKey,
                                                      AuthenticatedUser authzUser, String userStoreDomain, String scope,
                                                      boolean active)
            throws IdentityOAuth2Exception, SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest " + (active ? " active" : " non active") + " access token for user: " +
                    authzUser.getLoggableUserId() + " client: " + consumerKey + " scope: " + scope);
        }
        String tenantDomain = getUserResidentTenantDomain(authzUser);

        String authorizedOrganization = authzUser.getAccessingOrganization();
        if (StringUtils.isBlank(authorizedOrganization)) {
            authorizedOrganization = OAuthConstants.AuthorizedOrganization.NONE;
        }

        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        boolean isUsernameCaseSensitive
                = IdentityUtil.isUserStoreCaseSensitive(authzUser.getUserStoreDomain(), tenantId);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = OAuth2Util.getUserStoreDomain(authzUser);
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authzUser);

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {

            String sql;
            String driverName = connection.getMetaData().getDriverName();
            if (active) {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    if (driverName.contains("MySQL")
                            || driverName.contains("MariaDB")
                            || driverName.contains("H2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MYSQL;
                    } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_DB2SQL;
                    } else if (driverName.contains("MS SQL")
                            || driverName.contains("Microsoft")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                    } else if (driverName.contains("PostgreSQL")) {
                        sql = SQLQueries.
                                RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_POSTGRESQL;
                    } else if (driverName.contains("Informix")) {
                        // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_INFORMIX;

                    } else {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_ORACLE;
                    }
                } else {
                    if (driverName.contains("MySQL")
                            || driverName.contains("MariaDB")
                            || driverName.contains("H2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
                    } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
                    } else if (driverName.contains("MS SQL")
                            || driverName.contains("Microsoft")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                    } else if (driverName.contains("PostgreSQL")) {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
                    } else if (driverName.contains("Informix")) {
                        // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;

                    } else {
                        sql = SQLQueries.RETRIEVE_LATEST_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                    }
                }
            } else {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    if (driverName.contains("MySQL")
                            || driverName.contains("MariaDB")
                            || driverName.contains("H2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MYSQL;
                    } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                        sql = SQLQueries.
                                RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_DB2SQL;
                    } else if (driverName.contains("MS SQL")
                            || driverName.contains("Microsoft")) {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                    } else if (driverName.contains("PostgreSQL")) {
                        sql = SQLQueries.
                                RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_POSTGRESQL;
                    } else if (driverName.contains("Informix")) {
                        // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                        sql = SQLQueries.
                                RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_INFORMIX;

                    } else {
                        sql = SQLQueries.
                                RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_ORACLE;
                    }
                } else {
                    if (driverName.contains("MySQL")
                            || driverName.contains("MariaDB")
                            || driverName.contains("H2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
                    } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
                    } else if (driverName.contains("MS SQL")
                            || driverName.contains("Microsoft")) {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                    } else if (driverName.contains("PostgreSQL")) {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
                    } else if (driverName.contains("Informix")) {
                        // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;

                    } else {
                        sql = SQLQueries.RETRIEVE_LATEST_NON_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                    }
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
            int appTenantId = IdentityTenantUtil.getLoginTenantId();
            prepStmt.setInt(2, appTenantId);
            if (isUsernameCaseSensitive) {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userDomain);

            if (hashedScope != null) {
                prepStmt.setString(6, hashedScope);
            }

            prepStmt.setString(7, authorizedOrganization);

            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(8, authenticatedIDP);
                // Set tenant ID of the IDP by considering it is same as appTenantID.
                prepStmt.setInt(9, appTenantId);
            }

            resultSet = prepStmt.executeQuery();
            AccessTokenDO accessTokenDO = null;

            if (resultSet.next()) {
                String accessToken = getPersistenceProcessor()
                        .getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                String refreshToken = null;
                if (resultSet.getString(2) != null) {
                    refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
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
                        userDomain, tenantDomain, authenticatedIDP);
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
                accessTokenDO.getAuthzUser().setAccessingOrganization(authzUser.getAccessingOrganization());
                accessTokenDO.getAuthzUser().setUserResidentOrganization(authzUser.getUserResidentOrganization());
            }
            return accessTokenDO;

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser authenticatedUser,
                                              String userStoreDomain, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens for client: " + consumerKey + " user: " + authenticatedUser.toString());
        }

        String tenantDomain = getUserResidentTenantDomain(authenticatedUser);
        String tenantAwareUsernameWithNoUserDomain = authenticatedUser.getUserName();
        String userDomain = OAuth2Util.getUserStoreDomain(authenticatedUser);
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        boolean isUsernameCaseSensitive
                = IdentityUtil.isUserStoreCaseSensitive(authenticatedUser.getUserStoreDomain(), tenantId);
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authenticatedUser);

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            String sql;

            if (includeExpired) {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN_BY_CLIENT_ID_USER_IDP_NAME;
                } else {
                    sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN_BY_CLIENT_ID_USER;
                }
            } else {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_IDP_NAME;
                } else {
                    sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER;
                }
            }

            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            int appTenantId = IdentityTenantUtil.getLoginTenantId();
            if (authenticatedUser.getUserResidentOrganization() != null) {
                appTenantId = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
            }
            prepStmt.setInt(2, appTenantId);
            if (isUsernameCaseSensitive) {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userDomain);
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(6, authenticatedIDP);
                // Set tenant ID of the IDP by considering it is same as appTenantID.
                prepStmt.setInt(7, appTenantId);
            }

            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = getPersistenceProcessor()
                        .getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    Timestamp issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                            .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                    String tokenType = resultSet.getString(7);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);
                    String tokenBindingReference = resultSet.getString(11);
                    String authorizedOrganization = resultSet.getString(12);

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                            userDomain, tenantDomain, authenticatedIDP, authorizedOrganization, appTenantId);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data " +
                                "for client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    AccessTokenDO dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime,
                            refreshTokenIssuedTime, validityPeriodInMillis,
                            refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessToken);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    if (StringUtils.isNotBlank(tokenBindingReference) && !NONE.equals(tokenBindingReference)) {
                        setTokenBindingToAccessTokenDO(dataDO, connection, tokenId);
                    }
                    accessTokenDOMap.put(accessToken, dataDO);
                } else {
                    String scope = resultSet.getString(8).trim();
                    AccessTokenDO accessTokenDO = accessTokenDOMap.get(accessToken);
                    accessTokenDO.setScope((String[]) ArrayUtils.add(accessTokenDO.getScope(), scope));
                }
            }
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE' access tokens for " +
                    "Client ID : " + consumerKey + " and User ID : " + authenticatedUser;
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
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql;
            boolean isConsentedColumnDataFetched = false;
            if (includeExpired) {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN_IDP_NAME;
                } else {
                        sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN;
                }
            } else {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                            sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN_IDP_NAME_WITH_CONSENTED_TOKEN;
                            isConsentedColumnDataFetched = true;
                        } else {
                            sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN_IDP_NAME;
                        }
                } else {
                        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                            sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN_WITH_CONSENTED_TOKEN;
                            isConsentedColumnDataFetched = true;
                        } else {
                            sql = SQLQueries.RETRIEVE_ACTIVE_ACCESS_TOKEN;
                        }
                }
            }

            sql = OAuth2Util.getTokenPartitionedSqlByToken(sql, accessTokenIdentifier);

            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1,
                    getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(accessTokenIdentifier));
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
                    String authenticatedIDP = null;
                    String tokenBindingReference = resultSet.getString(15);
                    String authorizedOrganization = resultSet.getString(16);
                    int appResideTenantId = resultSet.getInt(17);

                    if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        authenticatedIDP = resultSet.getString(18);
                    }

                    boolean isConsentedToken = false;
                    if (isConsentedColumnDataFetched) {
                        int consentedTokenColumnIndex = resultSet.findColumn(CONSENTED_TOKEN_COLUMN_NAME);
                        isConsentedToken = resultSet.getBoolean(consentedTokenColumnIndex);
                    }

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authorizedUser,
                            userDomain, tenantDomain, authenticatedIDP, authorizedOrganization, appResideTenantId);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data " +
                                "for client id " + consumerKey, e);
                    }

                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);

                    dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime, refreshTokenIssuedTime,
                            validityPeriodInMillis, refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessTokenIdentifier);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    dataDO.setGrantType(grantType);
                    dataDO.setTenantID(tenantId);
                    dataDO.setIsConsentedToken(isConsentedToken);
                    dataDO.setAppResidentTenantId(appResideTenantId);

                    if (StringUtils.isNotBlank(tokenBindingReference) && !NONE.equals(tokenBindingReference)) {
                        setTokenBindingToAccessTokenDO(dataDO, connection, tokenId);
                    }
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

    private void setTokenBindingToAccessTokenDO(AccessTokenDO dataDO, Connection connection, String tokenId)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Setting token binding for tokenId: " + tokenId);
        }
        try (PreparedStatement tokenBindingPreparedStatement = connection
                .prepareStatement(RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID)) {
            tokenBindingPreparedStatement.setString(1, tokenId);
            try (ResultSet tokenBindingResultSet = tokenBindingPreparedStatement.executeQuery()) {
                while (tokenBindingResultSet.next()) {
                    if (!StringUtils.equals(DEFAULT_TOKEN_TO_SESSION_MAPPING,
                            tokenBindingResultSet.getString("TOKEN_BINDING_TYPE"))) {
                        TokenBinding tokenBinding = new TokenBinding();
                        tokenBinding.setBindingType(tokenBindingResultSet.getString("TOKEN_BINDING_TYPE"));
                        tokenBinding.setBindingReference(tokenBindingResultSet.getString("TOKEN_BINDING_REF"));
                        tokenBinding.setBindingValue(tokenBindingResultSet.getString("TOKEN_BINDING_VALUE"));
                        dataDO.setTokenBinding(tokenBinding);
                        if (log.isDebugEnabled()) {
                            log.debug("Set token binding information" +
                                    " accessTokenId: " + tokenId +
                                    " bindingType: " + tokenBinding.getBindingType() +
                                    " bindingRef: " + tokenBinding.getBindingReference());
                        }
                    }
                }
            }
        }
    }

    /**
     * Persist all token to session mapping in the token binding table with binding type as "DEFAULT".
     *
     * @param sessionContextIdentifier SessionContextIdentifier
     * @param tokenId                  TokenId.
     * @param tenantId                 TenantId.
     * @throws IdentityOAuth2Exception
     */
    public void storeTokenToSessionMapping(String sessionContextIdentifier, String tokenId, int tenantId)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Storing token to session mapping information for" +
                    " accessTokenId: " + tokenId +
                    " bindingType: " + DEFAULT_TOKEN_TO_SESSION_MAPPING +
                    " bindingRef: " + sessionContextIdentifier);
        }
        if (isNotBlank(sessionContextIdentifier) && isNotBlank(tokenId)) {
            Connection connection = IdentityDatabaseUtil.getDBConnection(false);
            try (PreparedStatement preparedStatement = connection.prepareStatement(STORE_TOKEN_BINDING)) {
                preparedStatement.setString(1, tokenId);
                preparedStatement.setString(2, DEFAULT_TOKEN_TO_SESSION_MAPPING);
                preparedStatement.setString(3,
                        OAuth2Util.getTokenBindingReference(sessionContextIdentifier));
                preparedStatement.setString(4, sessionContextIdentifier);
                preparedStatement.setInt(5, tenantId);
                preparedStatement.execute();
            } catch (SQLException e) {
                String errorMsg = "Error while persisting token to session mapping for sessionId: " +
                        sessionContextIdentifier;
                if (log.isDebugEnabled()) {
                    log.debug(errorMsg);
                }
                throw new IdentityOAuth2Exception(errorMsg, e);
            } finally {
                IdentityDatabaseUtil.closeConnection(connection);
            }
        }
    }

    /**
     * Get all tokens mapped to the bindingRef.
     *
     * @param sessionId SessionIdentifier
     * @throws IdentityOAuth2Exception
     * @return
     */
    public Set<String> getTokenIdBySessionIdentifier(String sessionId) throws IdentityOAuth2Exception {

        String sql = SQLQueries.RETRIEVE_TOKENS_MAPPED_FOR_TOKEN_BINDING_VALUE;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        Set<String> tokenIds = new HashSet<>();
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, sessionId);
            prepStmt.setString(2, DEFAULT_TOKEN_TO_SESSION_MAPPING);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                while (resultSet.next()) {
                    tokenIds.add(resultSet.getString("TOKEN_ID"));
                }
            }

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'token id' for " +
                    "binding value : " + sessionId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return tokenIds;
    }

    public void updateAccessTokenState(String tokenId, String tokenState) throws IdentityOAuth2Exception {
        updateAccessTokenState(tokenId, tokenState, null);
    }

    public void updateAccessTokenState(String tokenId, String tokenState, String grantType)
            throws IdentityOAuth2Exception {
        boolean tokenUpdateSuccessful;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            if (log.isDebugEnabled()) {
                log.debug("Changing status of access token with id: " + tokenId + " to: " + tokenState);
            }

            String sql = SQLQueries.UPDATE_TOKEN_STATE;
            try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {

                prepStmt.setString(1, tokenState);
                prepStmt.setString(2, UUID.randomUUID().toString());
                prepStmt.setString(3, tokenId);
                prepStmt.executeUpdate();
                tokenUpdateSuccessful = true;

                if (isTokenCleanupFeatureEnabled && !OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState)) {
                    oldTokenCleanupObject.cleanupTokenByTokenId(tokenId, connection);
                }

                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error while updating Access Token with ID : " +
                        tokenId + " to Token State : " + tokenState, e);
            }

        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while closing connection after updating Access Token with ID : " +
                    tokenId + " to Token State : " + tokenState, e);
        }
        if (tokenUpdateSuccessful) {
            if (StringUtils.equals(grantType, OAuthConstants.GrantTypes.CLIENT_CREDENTIALS) ||
                    StringUtils.equals(grantType, OAuthConstants.GrantTypes.PASSWORD)) {
                OAuth2TokenUtil.postUpdateAccessToken(tokenId, tokenState, false);
            } else {
                OAuth2TokenUtil.postUpdateAccessToken(tokenId, tokenState, true);
            }
        }
    }

    private boolean isPreviousTokenConsented(Connection connection, String tokenId)
            throws SQLException {

        String sql = SQLQueries.GET_TOKEN_IS_CONSENTED_OR_NOT;
        PreparedStatement prepStmt = connection.prepareStatement(sql);
        prepStmt.setString(1, tokenId);
        ResultSet resultSet = prepStmt.executeQuery();
        String initialGrant = StringUtils.EMPTY;
        while (resultSet.next()) {
            initialGrant = resultSet.getString(1);
        }
        return Boolean.parseBoolean(initialGrant);
    }

    private void updateAccessTokenState(Connection connection, String tokenId, String tokenState, String tokenStateId,
                                        String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception, SQLException {

        PreparedStatement prepStmt = null;
        try {
            if (log.isDebugEnabled()) {
                log.debug("Changing status of access token with id: " + tokenId + " to: " + tokenState +
                        " userStoreDomain: " + userStoreDomain);
            }

            String sql = SQLQueries.UPDATE_TOKEN_STATE;
            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, tokenState);
            prepStmt.setString(2, tokenStateId);
            prepStmt.setString(3, tokenId);
            prepStmt.executeUpdate();
            if (StringUtils.equals(grantType, OAuthConstants.GrantTypes.CLIENT_CREDENTIALS) ||
                    StringUtils.equals(grantType, OAuthConstants.GrantTypes.PASSWORD)) {
                OAuth2TokenUtil.postUpdateAccessToken(tokenId, tokenState, false);
            } else {
                OAuth2TokenUtil.postUpdateAccessToken(tokenId, tokenState, true);
            }

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error while updating Access Token with ID : " +
                    tokenId + " to Token State : " + tokenState, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    /**
     * This method is to revoke specific tokens where tokens should be plain text tokens.
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

    /**
     * This method is to revoke specific tokens where tokens can be plain text tokens or hashed tokens. Hashed tokens
     * can be reached here from internal calls such as from any listeners ex: IdentityOathEventListener etc. We need
     * to differentiate this types of internal calls hence these calls retrieved the tokens from the DB and then try
     * to revoke it.
     * When the Token Hashing Feature enabled, the token which is retrieve from the DB will be a hashed token. Hence
     * we don't need to hash it again.
     *
     * @param tokens        Tokens that needs to be revoked.
     * @param isHashedToken Indicate provided token is a hashed token or plain text token.
     * @throws IdentityOAuth2Exception if failed to revoke the access token
     */
    @Override
    public void revokeAccessTokens(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (isHashedToken) {
            // Token is hashed, no need to hash it again.
            if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
                revokeAccessTokensIndividually(tokens, true);
            } else {
                revokeAccessTokensInBatch(tokens, true);
            }
        } else {
            // Token is plain token, hence pass it to default revokeAccessTokens method.
            revokeAccessTokens(tokens);
        }
    }

    /**
     * Revoke the access token(s) as a batch. Token(s) which is reached here will be a plain text tokens.
     *
     * @param tokens        Token that needs to be revoked.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {

        revokeAccessTokensInBatch(tokens, false);
    }

    /**
     * Revoke the access token(s) as a batch.
     *
     * @param tokens        Token that needs to be revoked.
     * @param isHashedToken Given token is hashed token or plain text.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void revokeAccessTokensInBatch(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

        if (ArrayUtils.isEmpty(tokens)) {
            if (log.isDebugEnabled()) {
                log.debug("No tokens to revoke in batch mode. Therefore not continuing further in revocation.");
            }
            return;
        }

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
                String sqlQuery = SQLQueries.REVOKE_ACCESS_TOKEN.replace(IDN_OAUTH2_ACCESS_TOKEN,
                        accessTokenStoreTable);
                ps = connection.prepareStatement(sqlQuery);
                for (String token : tokens) {
                    ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                    ps.setString(2, UUID.randomUUID().toString());
                    if (isHashedToken) {
                        ps.setString(3, token);
                    } else {
                        ps.setString(3, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
                    }
                    ps.addBatch();
                    oldTokens.add(getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
                }
                ps.executeBatch();
                IdentityDatabaseUtil.commitTransaction(connection);
                // To revoke request objects which have persisted against the access token.
                OAuth2TokenUtil.postUpdateAccessTokens(Arrays.asList(tokens), OAuthConstants.TokenStates.
                        TOKEN_STATE_REVOKED);
                if (isTokenCleanupFeatureEnabled) {
                    oldTokenCleanupObject.cleanupTokensInBatch(oldTokens, connection);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
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
                if (isHashedToken) {
                    ps.setString(3, tokens[0]);
                } else {
                    ps.setString(3, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(tokens[0]));
                }
                ps.executeUpdate();

                // To revoke request objects which have persisted against the access token.
                OAuth2TokenUtil.postUpdateAccessTokens(Arrays.asList(tokens), OAuthConstants.TokenStates.
                        TOKEN_STATE_REVOKED);
                if (isTokenCleanupFeatureEnabled) {
                    oldTokenCleanupObject.cleanupTokenByTokenValue(
                            getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(tokens[0]), connection);
                }
            } catch (SQLException e) {
                // IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error occurred while revoking Access Token : " +
                        Arrays.toString(tokens), e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
            }
        }
    }

    /**
     * Revoke the access token(s) individually. Token(s) which is reached here will be a plain text tokens.
     *
     * @param tokens        Token that needs to be revoked.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {

        revokeAccessTokensIndividually(tokens, false);
    }

    /**
     * Revoke the access token(s) individually.
     *
     * @param tokens        Token that needs to be revoked.
     * @param isHashedToken Given token is hashed token or plain text.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void revokeAccessTokensIndividually(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {

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
            for (String token : tokens) {
                String sqlQuery = OAuth2Util.getTokenPartitionedSqlByToken(SQLQueries.REVOKE_ACCESS_TOKEN, token);
                ps = connection.prepareStatement(sqlQuery);
                ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                ps.setString(2, UUID.randomUUID().toString());
                if (isHashedToken) {
                    ps.setString(3, token);
                } else {
                    ps.setString(3, getHashingPersistenceProcessor().getProcessedAccessTokenIdentifier(token));
                }
                int count = ps.executeUpdate();
                if (log.isDebugEnabled()) {
                    log.debug("Number of rows being updated : " + count);
                }
                accessTokenId.add(getTokenIdByAccessToken(token));
            }
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
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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
        boolean revoked;

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
            IdentityDatabaseUtil.commitTransaction(connection);
            revoked = true;

            if (isTokenCleanupFeatureEnabled && tokenId != null) {
                oldTokenCleanupObject.cleanupTokenByTokenId(tokenId, connection);
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token with ID : " + tokenId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        if (revoked) {
            // To revoke the tokens from Request Object table.
            OAuth2TokenUtil.postUpdateAccessToken(tokenId, OAuthConstants.TokenStates.
                    TOKEN_STATE_REVOKED, true);
        }
    }

    /**
     * Returns the set of access tokens issued for the user.
     *
     * @param authenticatedUser Authenticated user object.
     * @return Access tokens as a set of Strings.
     * @throws IdentityOAuth2Exception If any errors occurred.
     */
    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens of user: " + authenticatedUser.getLoggableUserId());
        }
        int tenantId = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
        boolean isUsernameCaseSensitive =
                IdentityUtil.isUserStoreCaseSensitive(authenticatedUser.getUserStoreDomain(), tenantId);
        boolean isIdTokenIssuedForClientCredentialsGrant = isIdTokenIssuedForApplicationTokens();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs;
        Set<String> accessTokens = new HashSet<>();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.GET_ACCESS_TOKEN_BY_AUTHZUSER,
                    authenticatedUser.getUserStoreDomain());
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
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token with user Name : " +
                    authenticatedUser.getUserName() + " tenant ID : " + OAuth2Util.getTenantId(authenticatedUser
                    .getTenantDomain()), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return accessTokens;
    }

    /**
     * Returns the set of access tokens issued for the user which are having openid scope.
     *
     * @param authenticatedUser Authenticated user object.
     * @return Access tokens as a set of AccessTokenDO
     * @throws IdentityOAuth2Exception If any errors occurred.
     */
    @Override
    public Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens of user: " + authenticatedUser.toString());
        }

        int tenantId = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
        boolean isUsernameCaseSensitive =
                IdentityUtil.isUserStoreCaseSensitive(authenticatedUser.getUserStoreDomain(), tenantId);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs;
        Set<AccessTokenDO> accessTokens;
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(
                    SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER, authenticatedUser.getUserStoreDomain());
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
            ps.setString(5, OAuthConstants.Scope.OPENID);
            rs = ps.executeQuery();

            Map<String, AccessTokenDO> tokenMap = getAccessTokenDOMapFromResultSet(authenticatedUser, rs);

            connection.commit();
            accessTokens = new HashSet<>(tokenMap.values());
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking access token with username : " +
                    authenticatedUser.getUserName() + " tenant ID : " + OAuth2Util.getTenantId(authenticatedUser
                    .getTenantDomain()), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return accessTokens;
    }

    private Map<String, AccessTokenDO> getAccessTokenDOMapFromResultSet(AuthenticatedUser authenticatedUser,
                                                                        ResultSet rs) throws SQLException,
            IdentityOAuth2Exception {

        Map<String, AccessTokenDO> tokenMap = new HashMap<>();
        while (rs.next()) {
            Timestamp timeCreated = rs.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            long issuedTimeInMillis = timeCreated.getTime();
            long validityPeriodInMillis = rs.getLong(5);

            /*
             * Tokens returned by this method will be used to clear claims cached against the tokens.
             * We will only return tokens that would contain such cached clams in order to improve
             * performance.
             * Tokens issued for openid scope can contain cached claims against them.
             * Tokens that are in ACTIVE state and not expired should be removed from the cache.
             */
            if (isAccessTokenExpired(issuedTimeInMillis, validityPeriodInMillis)) {
                continue;
            }

            String accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(rs.getString(1));
            String refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(rs.getString(2));
            String tokenId = rs.getString(3);
            Timestamp refreshTokenTimeCreated = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            long refreshTokenValidityPeriodInMillis = rs.getLong(7);
            String consumerKey = rs.getString(8);
            String grantType = rs.getString(9);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setAuthzUser(authenticatedUser);
            accessTokenDO.setTenantID(OAuth2Util.getTenantId(authenticatedUser.getTenantDomain()));
            accessTokenDO.setAccessToken(accessToken);
            accessTokenDO.setRefreshToken(refreshToken);
            accessTokenDO.setTokenId(tokenId);
            accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            accessTokenDO.setIssuedTime(timeCreated);
            accessTokenDO.setValidityPeriodInMillis(validityPeriodInMillis);
            accessTokenDO.setRefreshTokenIssuedTime(refreshTokenTimeCreated);
            accessTokenDO.setRefreshTokenValidityPeriodInMillis(refreshTokenValidityPeriodInMillis);
            accessTokenDO.setConsumerKey(consumerKey);
            accessTokenDO.setGrantType(grantType);

            tokenMap.put(accessToken, accessTokenDO);
        }
        return tokenMap;
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

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> accessTokens = new HashSet<>();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.
                    GET_ACCESS_TOKENS_FOR_CONSUMER_KEY, userStoreDomain);
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setInt(2, IdentityTenantUtil.getLoginTenantId());
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();

            while (rs.next()) {
                accessTokens.add(getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(rs.getString(1)));

            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<AccessTokenDO> activeDetailedTokens;
        Map<String, AccessTokenDO> tokenMap = new HashMap<>();

        try {
            String sqlQuery;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sqlQuery = SQLQueries.GET_ACTIVE_DETAILS_FOR_CONSUMER_KEY_IDP_NAME;
            } else {
                sqlQuery = SQLQueries.GET_ACTIVE_DETAILS_FOR_CONSUMER_KEY;
            }
            sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(sqlQuery, userStoreDomain);

            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            int appTenantId = IdentityTenantUtil.getLoginTenantId();
            ps.setInt(2, appTenantId);
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
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
                    String authorizedOrganizationId = null;
                    String authenticatedIDP = null;
                    if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        authenticatedIDP = rs.getString(6);
                        authorizedOrganizationId = rs.getString(8);
                    }
                    String[] scope = OAuth2Util.buildScopeArray(tokenSope);
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userDomain,
                            OAuth2Util.getTenantDomain(tenentId), authenticatedIDP, authorizedOrganizationId,
                            appTenantId);
                    user.setAuthenticatedSubjectIdentifier(rs.getString(7));
                    AccessTokenDO aTokenDetail = new AccessTokenDO();
                    aTokenDetail.setAccessToken(token);
                    aTokenDetail.setConsumerKey(consumerKey);
                    aTokenDetail.setScope(scope);
                    aTokenDetail.setAuthzUser(user);
                    aTokenDetail.setAuthorizedOrganizationId(authorizedOrganizationId);
                    tokenMap.put(token, aTokenDetail);
                }
            }
            activeDetailedTokens = new HashSet<>(tokenMap.values());
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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
     * @deprecated to use {{@link #invalidateAndCreateNewAccessToken(String, String, String, String,
     * AccessTokenDO, String, String)}}
     */
    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState,
                                                  String consumerKey, String tokenStateId,
                                                  AccessTokenDO accessTokenDO, String userStoreDomain)
            throws IdentityOAuth2Exception {
        invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey, tokenStateId,
                accessTokenDO, userStoreDomain, null);
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
     * @param grantType        grant type of the old access token
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState,
                                                  String consumerKey, String tokenStateId,
                                                  AccessTokenDO accessTokenDO, String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Invalidating access token with id: " + oldAccessTokenId + " and creating new access token" +
                        "(hashed): " + DigestUtils.sha256Hex(accessTokenDO.getAccessToken()) + " for client: " +
                        consumerKey + " user: " + accessTokenDO.getAuthzUser().getLoggableUserId() + " scope: " + Arrays
                        .toString(accessTokenDO.getScope()));
            } else {
                log.debug("Invalidating and creating new access token for client: " + consumerKey + " user: " +
                        accessTokenDO.getAuthzUser().getLoggableUserId() + " scope: "
                        + Arrays.toString(accessTokenDO.getScope()));
            }
        }
        boolean tokenUpdateSuccessful;
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        try {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled() && !accessTokenDO.isConsentedToken()) {
                // Check whether the previous token is issued for a consent required grant or not.
                boolean isPreviousTokenConsented = isPreviousTokenConsented(connection, oldAccessTokenId);
                accessTokenDO.setIsConsentedToken(isPreviousTokenConsented);
            }
            // update existing token as inactive
            updateAccessTokenState(connection, oldAccessTokenId, tokenState, tokenStateId, userStoreDomain, grantType);

            String newAccessToken = accessTokenDO.getAccessToken();
            // store new token in the DB
            insertAccessToken(newAccessToken, consumerKey, accessTokenDO, connection, userStoreDomain);

            if (StringUtils.equals(grantType, OAuthConstants.GrantTypes.AUTHORIZATION_CODE)) {
                updateTokenIdIfAutzCodeGrantType(oldAccessTokenId, accessTokenDO.getTokenId(), connection);
            }

            if (isTokenCleanupFeatureEnabled && oldAccessTokenId != null) {
                oldTokenCleanupObject.cleanupTokenByTokenId(oldAccessTokenId, connection);
            }
            IdentityDatabaseUtil.commitTransaction(connection);
            tokenUpdateSuccessful = true;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String errorMsg = "Error while regenerating access token";
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
        if (tokenUpdateSuccessful) {
            // Post refresh access token event
            if (StringUtils.equals(grantType, OAuthConstants.GrantTypes.CLIENT_CREDENTIALS) ||
                    StringUtils.equals(grantType, OAuthConstants.GrantTypes.PASSWORD)) {
                OAuth2TokenUtil.postRefreshAccessToken(oldAccessTokenId, accessTokenDO.getTokenId(), tokenState, false);
            } else {
                OAuth2TokenUtil.postRefreshAccessToken(oldAccessTokenId, accessTokenDO.getTokenId(), tokenState, true);
            }
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

    public Set<AccessTokenDO> getAccessTokensByAuthorizedOrg(String organizationId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all access tokens issued for organization id: " + organizationId);
        }

        Set<AccessTokenDO> accessTokenDOs =
                getAccessTokensByAuthorizedOrg(organizationId, IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                accessTokenDOs.addAll(getAccessTokensByAuthorizedOrg(organizationId, availableDomainMapping.getKey()));
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

        String organizationId = resolveOrganizationId(IdentityTenantUtil.getTenantDomain(tenantId));
        String rootTenantDomain = getRootTenantDomainByOrganizationId(organizationId);
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            String sql;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sql = SQLQueries.LIST_ALL_TOKENS_IN_TENANT_IDP_NAME;
            } else {
                sql = SQLQueries.LIST_ALL_TOKENS_IN_TENANT;
            }
            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = getPersistenceProcessor().
                        getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
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
                    String authorizedOrganization = resultSet.getString(13);
                    String authenticatedIDP = null;
                    if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        authenticatedIDP = resultSet.getString(14);
                    }

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain,
                            OAuth2Util.getTenantDomain(tenantId), authenticatedIDP, authorizedOrganization,
                            rootTenantDomain);
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
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE or EXPIRED' access tokens for " +
                    "user  tenant id : " + tenantId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return new HashSet<>(accessTokenDOMap.values());
    }

    private Set<AccessTokenDO> getAccessTokensByAuthorizedOrg(String organizationId, String userStoreDomain)
            throws IdentityOAuth2Exception {

        String sql;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
            sql = SQLQueries.LIST_ALL_TOKENS_ISSUED_FOR_ORGANIZATION_IDP_NAME;
        } else {
            sql = SQLQueries.LIST_ALL_TOKENS_ISSUED_FOR_ORGANIZATION;
        }
        sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);
        String rootTenantDomain = getRootTenantDomainByOrganizationId(organizationId);
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(sql)) {
            prepStmt.setString(1, organizationId);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                while (resultSet.next()) {
                    String accessToken = getPersistenceProcessor().
                            getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                    if (accessTokenDOMap.get(accessToken) == null) {
                        String refreshToken =
                                getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                        Timestamp issuedTime =
                                resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                        Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                                .getTimeZone(UTC)));
                        long validityPeriodInMillis = resultSet.getLong(5);
                        long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                        String tokenType = resultSet.getString(7);
                        String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                        String tokenId = resultSet.getString(9);
                        String authzUser = resultSet.getString(10);
                        int tenantId = resultSet.getInt(11);
                        userStoreDomain = resultSet.getString(12);
                        String consumerKey = resultSet.getString(13);
                        String authenticatedIDP = null;
                        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                            authenticatedIDP = resultSet.getString(14);
                        }

                        AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain,
                                OAuth2Util.getTenantDomain(tenantId), authenticatedIDP, organizationId,
                                rootTenantDomain);
                        AccessTokenDO dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime,
                                refreshTokenIssuedTime, validityPeriodInMillis,
                                refreshTokenValidityPeriodMillis, tokenType);
                        dataDO.setAccessToken(accessToken);
                        dataDO.setRefreshToken(refreshToken);
                        dataDO.setTokenId(tokenId);
                        dataDO.setTenantID(tenantId);
                        dataDO.setAuthorizedOrganizationId(organizationId);
                        accessTokenDOMap.put(accessToken, dataDO);
                    } else {
                        String scope = resultSet.getString(8).trim();
                        AccessTokenDO accessTokenDO = accessTokenDOMap.get(accessToken);
                        accessTokenDO.setScope((String[]) ArrayUtils.add(accessTokenDO.getScope(), scope));
                    }
                }
            }
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE or EXPIRED' access tokens issued for" +
                    "organization: " + organizationId;
            throw new IdentityOAuth2Exception(errorMsg, e);
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
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            String sql;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sql = SQLQueries.LIST_ALL_TOKENS_IN_USER_STORE_IDP_NAME;
            } else {
                sql = SQLQueries.LIST_ALL_TOKENS_IN_USER_STORE;
            }
            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, userStoreDomain);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken =
                        getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
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
                    String authenticatedIDP = null;
                    if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        authenticatedIDP = resultSet.getString(12);
                    }

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain,
                            OAuth2Util.getTenantDomain(tenantId), authenticatedIDP);
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
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
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

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

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
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Token ID' for " +
                    "token : " + token;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    @Override
    public String getAccessTokenByTokenId(String tokenId) throws IdentityOAuth2Exception {

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

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.RETRIEVE_TOKEN_BY_TOKEN_ID,
                    userStoreDomain);

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, tokenId);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                String persistedAccessToken = resultSet.getString("ACCESS_TOKEN");
                return getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(persistedAccessToken);
            }
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Access Token' for token id: " + tokenId;
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
        try {
            connection.setAutoCommit(false);
            log.warn("Retry attempt to recover 'CON_APP_KEY' constraint violation : " + retryAttemptCounter);

            AccessTokenDO latestNonActiveToken = getLatestAccessTokenByState(connection, consumerKey,
                    accessTokenDO.getAuthzUser(), userStoreDomain,
                    OAuth2Util.buildScopeString(accessTokenDO.getScope()), false);

            AccessTokenDO latestActiveToken = getLatestAccessTokenByState(connection, consumerKey,
                    accessTokenDO.getAuthzUser(), userStoreDomain,
                    OAuth2Util.buildScopeString(accessTokenDO.getScope()), true);
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);

            if (latestActiveToken != null) {
                OAuthTokenReqMessageContext tokReqMsgCtx = OAuth2Util.getTokenRequestContext();
                OAuthAuthzReqMessageContext authzReqMsgCtx = OAuth2Util.getAuthzRequestContext();
                // For JWT tokens, always issue a new token expiring the existing token.
                if ((tokReqMsgCtx != null && oauthTokenIssuer.renewAccessTokenPerRequest(tokReqMsgCtx))
                        || (authzReqMsgCtx != null && oauthTokenIssuer.renewAccessTokenPerRequest(authzReqMsgCtx))) {
                    updateAccessTokenState(connection, latestActiveToken.getTokenId(), OAuthConstants.TokenStates
                                    .TOKEN_STATE_EXPIRED, UUID.randomUUID().toString(), userStoreDomain,
                            latestActiveToken.getGrantType());
                    // Update token issued time make this token as latest token & try to store it again.
                    accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                    insertAccessToken(accessTokenDO.getAccessToken(), consumerKey, accessTokenDO, connection,
                            userStoreDomain, retryAttemptCounter);
                } else if (OAuth2Util.getAccessTokenExpireMillis(latestActiveToken) != 0 &&
                        (latestNonActiveToken == null || latestActiveToken.getIssuedTime().after
                                (latestNonActiveToken.getIssuedTime()))) {

                    // If there is an active token in the database, it is not expired and it is the last issued
                    // token, use the existing token. In here we can use existing token since we have a
                    // synchronised communication.
                    accessTokenDO.setTokenId(latestActiveToken.getTokenId());
                    accessTokenDO.setAccessToken(latestActiveToken.getAccessToken());
                    accessTokenDO.setRefreshToken(latestActiveToken.getRefreshToken());
                    accessTokenDO.setIssuedTime(latestActiveToken.getIssuedTime());
                    accessTokenDO.setRefreshTokenIssuedTime(latestActiveToken.getRefreshTokenIssuedTime());
                    accessTokenDO.setValidityPeriodInMillis(latestActiveToken.getValidityPeriodInMillis());
                    accessTokenDO.setRefreshTokenValidityPeriodInMillis(
                            latestActiveToken.getRefreshTokenValidityPeriodInMillis());
                    accessTokenDO.setTokenType(latestActiveToken.getTokenType());
                    log.info("Successfully recovered 'CON_APP_KEY' constraint violation with the attempt : "
                            + retryAttemptCounter);

                } else if (!(OAuth2Util.getAccessTokenExpireMillis(latestActiveToken) == 0)) {
                    // If the last active token in the database is expired, update the token status in the database.
                    updateAccessTokenState(connection, latestActiveToken.getTokenId(), OAuthConstants.TokenStates
                                    .TOKEN_STATE_EXPIRED, UUID.randomUUID().toString(), userStoreDomain,
                            latestActiveToken.getGrantType());

                    // Update token issued time make this token as latest token & try to store it again.
                    accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                    insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain,
                            retryAttemptCounter);

                } else {
                    // Inactivate latest active token.
                    updateAccessTokenState(connection, latestActiveToken.getTokenId(), OAuthConstants.TokenStates
                                    .TOKEN_STATE_INACTIVE, UUID.randomUUID().toString(), userStoreDomain,
                            latestActiveToken.getGrantType());

                    // Update token issued time make this token as latest token & try to store it again.
                    accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                    insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain,
                            retryAttemptCounter);
                }
            } else {
                // In this case another process already updated the latest active token to inactive.

                // Update token issued time make this token as latest token & try to store it again.
                accessTokenDO.setIssuedTime(new Timestamp(new Date().getTime()));
                insertAccessToken(accessToken, consumerKey, accessTokenDO, connection, userStoreDomain,
                        retryAttemptCounter);
            }
            connection.commit();
        } catch (SQLException e) {
            try {
                if (connection != null) {
                    connection.rollback();
                }
            } catch (SQLException e1) {
                throw new IdentityOAuth2Exception("An rolling back transactions error occurred while trying to "
                        + "recover 'CON_APP_KEY' constraint violation. ", e1);
            }
            String errorMsg = "SQL error occurred while trying to recover 'CON_APP_KEY' constraint violation.";
            throw new IdentityOAuth2Exception(errorMsg, e);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey + ".", e);
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
    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope, boolean includeExpiredTokens,
                                                     int limit)
            throws IdentityOAuth2Exception {

        return getLatestAccessTokens(consumerKey, authzUser, userStoreDomain, scope, NONE, includeExpiredTokens, limit);
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope, String tokenBindingReference,
                                                     boolean includeExpiredTokens, int limit)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving " + (includeExpiredTokens ? " active" : " all ") + " latest " + limit + " access " +
                    "token for user: " + authzUser.toString() + " client: " + consumerKey + " scope: " + scope);
        }

        if (authzUser == null) {
            throw new IdentityOAuth2Exception("Invalid user information for given consumerKey: " + consumerKey);
        }
        String tenantDomain = authzUser.getTenantDomain();
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        boolean isUsernameCaseSensitive =
                IdentityUtil.isUserStoreCaseSensitive(authzUser.getUserStoreDomain(), tenantId);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        String userDomain = OAuth2Util.getUserStoreDomain(authzUser);
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authzUser);

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        boolean sqlAltered = false;
        try {

            String sql;

            String driverName = connection.getMetaData().getDriverName();
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                if (driverName.contains("MySQL")
                        || driverName.contains("MariaDB")
                        || driverName.contains("H2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_DB2SQL;
                } else if (driverName.contains("MS SQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                } else if (driverName.contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_MSSQL;
                } else if (driverName.contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_POSTGRESQL;
                } else if (driverName.contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_IDP_NAME_ORACLE;
                    sql = sql.replace("ROWNUM < 2", "ROWNUM < " + Integer.toString(limit + 1));
                    sqlAltered = true;
                }
            } else {
                if (driverName.contains("MySQL")
                        || driverName.contains("MariaDB")
                        || driverName.contains("H2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
                } else if (driverName.contains("MS SQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                } else if (driverName.contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
                } else if (driverName.contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
                } else if (driverName.contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
                    sql = sql.replace("ROWNUM < 2", "ROWNUM < " + Integer.toString(limit + 1));
                    sqlAltered = true;
                }
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
            prepStmt.setInt(2, IdentityTenantUtil.getLoginTenantId());
            if (isUsernameCaseSensitive) {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userDomain);

            if (hashedScope != null) {
                prepStmt.setString(6, hashedScope);
            }

            prepStmt.setString(7, tokenBindingReference);

            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(8, authenticatedIDP);
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
                    String accessToken = getPersistenceProcessor()
                            .getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                    String refreshToken = null;
                    if (resultSet.getString(2) != null) {
                        refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    }
                    long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone
                            ("UTC"))).getTime();
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodInMillis = resultSet.getLong(6);

                    String userType = resultSet.getString(8);
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);
                    String grantType = resultSet.getString(11);
                    // data loss at dividing the validity period but can be neglected
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                            userDomain, tenantDomain, authenticatedIDP);

                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data " +
                                "for client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, user, OAuth2Util.buildScopeArray
                            (scope), new Timestamp(issuedTime), new Timestamp(refreshTokenIssuedTime)
                            , validityPeriodInMillis, refreshTokenValidityPeriodInMillis, userType);
                    accessTokenDO.setAccessToken(accessToken);
                    accessTokenDO.setRefreshToken(refreshToken);
                    accessTokenDO.setTokenState(tokenState);
                    accessTokenDO.setTokenId(tokenId);
                    accessTokenDO.setGrantType(grantType);
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

    /**
     * Check whether a valid access token binding available.
     *
     * @param tokenBinding token binding.
     * @return true if valid binding available.
     */
    private boolean isTokenBindingAvailable(TokenBinding tokenBinding) {

        return tokenBinding != null && StringUtils.isNotBlank(tokenBinding.getBindingType()) && StringUtils
                .isNotBlank(tokenBinding.getBindingReference()) && StringUtils
                .isNotBlank(tokenBinding.getBindingValue());
    }

    /**
     * Retrieves active AccessTokenDOs with token id for the given consumer key.
     *
     * @param consumerKey client id
     * @return access token data object set
     * @throws IdentityOAuth2Exception
     */
    @Override
    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(String consumerKey)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access token set with token id of client: " + consumerKey);
        }
        Set<AccessTokenDO> activeAccessTokenDOSet = getActiveAccessTokenSetByConsumerKeyForOpenidScope(consumerKey,
                IdentityUtil.getPrimaryDomainName());

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                activeAccessTokenDOSet.addAll(getActiveAccessTokenSetByConsumerKeyForOpenidScope(consumerKey,
                        availableDomainMapping.getKey()));
            }
        }
        return activeAccessTokenDOSet;
    }

    /**
     * Retrieves active AccessTokenDOs with token id for the given consumer key.
     *
     * @param consumerKey client id
     * @return access token data object set
     * @throws IdentityOAuth2Exception
     */
    @Override
    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyAndScope(String consumerKey, List<String> scopes)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access token set with token id of client: " + consumerKey);
        }
        Set<AccessTokenDO> activeAccessTokenDOSet = new HashSet<>();
        for (String scope: scopes) {
            activeAccessTokenDOSet.addAll(getActiveAccessTokenSetByConsumerKeyForScope(consumerKey,
                    IdentityUtil.getPrimaryDomainName(), scope));

            if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
                Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
                for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                    activeAccessTokenDOSet.addAll(getActiveAccessTokenSetByConsumerKeyForOpenidScope(consumerKey,
                            availableDomainMapping.getKey()));
                }
            }
        }

        return activeAccessTokenDOSet;
    }

    /**
     * Retrieves active AccessTokenDOs with token id for a given consumer key
     *
     * @param consumerKey     client id
     * @param userStoreDomain userstore domain
     * @return set of access token data objects
     * @throws IdentityOAuth2Exception
     */
    private Set<AccessTokenDO> getActiveAccessTokenSetByConsumerKeyForOpenidScope(String consumerKey,
                                                                                  String userStoreDomain)
            throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<AccessTokenDO> accessTokens = new HashSet<>();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.
                    GET_ACCESS_TOKENS_AND_TOKEN_IDS_FOR_CONSUMER_KEY, userStoreDomain);
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setInt(2, IdentityTenantUtil.getLoginTenantId());
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            ps.setString(4, OAuthConstants.Scope.OPENID);
            rs = ps.executeQuery();

            while (rs.next()) {
                String accessToken = getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(rs.getString(1));
                String tokenId = rs.getString(2);
                Timestamp timeCreated = rs.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long issuedTimeInMillis = timeCreated.getTime();
                long validityPeriodInMillis = rs.getLong(4);

                if (!isAccessTokenExpired(issuedTimeInMillis, validityPeriodInMillis)) {
                    AccessTokenDO accessTokenDO = new AccessTokenDO();
                    accessTokenDO.setAccessToken(accessToken);
                    accessTokenDO.setTokenId(tokenId);
                    accessTokens.add(accessTokenDO);
                }

            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting access tokens from access token table for "
                    + "the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return accessTokens;

    }

    /**
     * Retrieves active AccessTokenDOs with token id for a given consumer key
     *
     * @param consumerKey     client id
     * @param userStoreDomain userstore domain
     * @return set of access token data objects
     * @throws IdentityOAuth2Exception
     */
    private Set<AccessTokenDO> getActiveAccessTokenSetByConsumerKeyForScope(String consumerKey,
                                                                            String userStoreDomain,
                                                                            String scope)
            throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        Set<AccessTokenDO> accessTokens = new HashSet<>();
        int appTenantId = IdentityTenantUtil.getLoginTenantId();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.
                    GET_ACCESS_TOKENS_FOR_CONSUMER_KEY_AND_SCOPE, userStoreDomain);
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setInt(2, appTenantId);
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            ps.setString(4, scope);
            resultSet = ps.executeQuery();

            while (resultSet.next()) {
                String accessToken = getPersistenceProcessor()
                        .getPreprocessedAccessTokenIdentifier(resultSet.getString(OAuthColumnName.ACCESS_TOKEN));
                String tokenScope = resultSet.getString(OAuthColumnName.TOKEN_SCOPE);
                String refreshToken = resultSet.getString(OAuthColumnName.REFRESH_TOKEN);
                String tokenId = resultSet.getString(OAuthColumnName.TOKEN_ID);
                int tenantId = resultSet.getInt(OAuthColumnName.TENANT_ID);
                String authzUser = resultSet.getString(OAuthColumnName.AUTHZ_USER);
                String subjectIdentifier = resultSet.getString(OAuthColumnName.SUBJECT_IDENTIFIER);
                String userDomain = resultSet.getString(OAuthColumnName.USER_DOMAIN);
                String authenticatedIDPName = resultSet.getString(OAuthColumnName.AUTHENTICATED_IDP_NAME);
                String authorizedOrganization = resultSet.getString(OAuthColumnName.AUTHORIZED_ORGANIZATION);
                String bindingRef = resultSet.getString(OAuthColumnName.TOKEN_BINDING_REF);
                TokenBinding tokenBinding = new TokenBinding();
                tokenBinding.setBindingReference(bindingRef);

                AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser,
                        userDomain, OAuth2Util.getTenantDomain(tenantId), authenticatedIDPName, authorizedOrganization,
                        appTenantId);
                user.setAuthenticatedSubjectIdentifier(subjectIdentifier);

                Timestamp issuedTime = resultSet
                        .getTimestamp(OAuthColumnName.TIME_CREATED, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                Timestamp refreshTokenIssuedTime =
                        resultSet.getTimestamp(OAuthColumnName.REFRESH_TOKEN_TIME_CREATED
                                , Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = resultSet.getLong(OAuthColumnName.VALIDITY_PERIOD);
                long refreshTokenValidityPeriodMillis
                        = resultSet.getLong(OAuthColumnName.REFRESH_TOKEN_VALIDITY_PERIOD);
                String tokenType = resultSet.getString(OAuthColumnName.USER_TYPE);
                String[] scopes = OAuth2Util.buildScopeArray(tokenScope);

                AccessTokenDO accessTokenDO = new AccessTokenDO();
                accessTokenDO.setAccessToken(accessToken);
                accessTokenDO.setConsumerKey(consumerKey);
                accessTokenDO.setScope(scopes);
                accessTokenDO.setAuthzUser(user);
                accessTokenDO.setTenantID(tenantId);
                accessTokenDO.setRefreshToken(refreshToken);
                accessTokenDO.setTokenId(tokenId);
                accessTokenDO.setIssuedTime(issuedTime);
                accessTokenDO.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                accessTokenDO.setValidityPeriod(validityPeriodInMillis);
                accessTokenDO.setRefreshTokenValidityPeriod(refreshTokenValidityPeriodMillis);
                accessTokenDO.setTokenType(tokenType);
                accessTokenDO.setTokenBinding(tokenBinding);
                accessTokens.add(accessTokenDO);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting access tokens from access token table for "
                    + "the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, ps);
        }
        return accessTokens;
    }

    /**
     * Checks whether the issued token is expired.
     *
     * @param issuedTimeInMillis
     * @param validityPeriodMillis
     * @return true if access token is expired. False if not.
     */
    private boolean isAccessTokenExpired(long issuedTimeInMillis, long validityPeriodMillis) {

        return OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodMillis) < 0;
    }

    public Set<AccessTokenDO> getAccessTokensByBindingRef(AuthenticatedUser user, String bindingRef)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access tokens issued to user, " + user.getUserName() + " with binding " +
                    "reference " + bindingRef);
        }

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries
                    .GET_ACCESS_TOKENS_BY_BINDING_REFERENCE_AND_USER, user.getUserStoreDomain());
            int tenantId = OAuth2Util.getTenantId(user.getTenantDomain());
            Map<String, AccessTokenDO> tokenMap = new HashMap<>();
            jdbcTemplate.executeQuery(sqlQuery,
                    rethrowRowMapper((resultSet, i) -> {
                        String token = getPersistenceProcessor()
                                .getPreprocessedAccessTokenIdentifier(resultSet.getString("ACCESS_TOKEN"));
                        AccessTokenDO accessTokenDO = new AccessTokenDO();
                        if (tokenMap.containsKey(token)) {
                            AccessTokenDO tokenObj = tokenMap.get(token);
                            String[] previousScope = tokenObj.getScope();
                            String[] newSope = new String[tokenObj.getScope().length + 1];
                            System.arraycopy(previousScope, 0, newSope, 0, previousScope.length);
                            newSope[previousScope.length] = resultSet.getString(2);
                            tokenObj.setScope(newSope);
                        } else {
                            String consumerKey = resultSet.getString("CONSUMER_KEY");
                            String tokenScope = resultSet.getString("TOKEN_SCOPE");
                            String refreshToken = resultSet.getString("REFRESH_TOKEN");
                            String tokenId = resultSet.getString("TOKEN_ID");
                            Timestamp issuedTime = resultSet
                                    .getTimestamp("TIME_CREATED", Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                            Timestamp refreshTokenIssuedTime =
                                    resultSet.getTimestamp("REFRESH_TOKEN_TIME_CREATED", Calendar.getInstance(TimeZone
                                            .getTimeZone(UTC)));
                            long validityPeriodInMillis = resultSet.getLong("VALIDITY_PERIOD");
                            long refreshTokenValidityPeriodMillis = resultSet.getLong("REFRESH_TOKEN_VALIDITY_PERIOD");
                            String tokenType = resultSet.getString("USER_TYPE");

                            String[] scope = OAuth2Util.buildScopeArray(tokenScope);
                            accessTokenDO.setAccessToken(token);
                            accessTokenDO.setConsumerKey(consumerKey);
                            accessTokenDO.setScope(scope);
                            accessTokenDO.setAuthzUser(user);
                            accessTokenDO.setTenantID(tenantId);
                            accessTokenDO.setRefreshToken(refreshToken);
                            accessTokenDO.setTokenId(tokenId);
                            accessTokenDO.setIssuedTime(issuedTime);
                            accessTokenDO.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                            accessTokenDO.setValidityPeriod(validityPeriodInMillis);
                            accessTokenDO.setRefreshTokenValidityPeriod(refreshTokenValidityPeriodMillis);
                            accessTokenDO.setTokenType(tokenType);
                            tokenMap.put(token, accessTokenDO);
                        }
                        return null;
                    }),
                    (PreparedStatement preparedStatement) -> {
                        preparedStatement.setString(1, user.getUserName());
                        preparedStatement.setInt(2, tenantId);
                        preparedStatement.setString(3, user.getUserStoreDomain());
                        preparedStatement.setString(4, bindingRef);
                    });
            return new HashSet<>(tokenMap.values());
        } catch (DataAccessException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving access tokens.", e);
        }
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(String bindingRef) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active access tokens issued with binding reference : " + bindingRef);
        }

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            String sqlQuery = GET_ACCESS_TOKENS_BY_BINDING_REFERENCE;
            Map<String, AccessTokenDO> tokenMap = new HashMap<>();
            jdbcTemplate.executeQuery(sqlQuery,
                    rethrowRowMapper((resultSet, i) -> {
                        String token = getPersistenceProcessor()
                                .getPreprocessedAccessTokenIdentifier(resultSet.getString("ACCESS_TOKEN"));
                        AccessTokenDO accessTokenDO = new AccessTokenDO();
                        if (tokenMap.containsKey(token)) {
                            AccessTokenDO tokenObj = tokenMap.get(token);
                            String[] previousScope = tokenObj.getScope();
                            String[] newScope = new String[tokenObj.getScope().length + 1];
                            System.arraycopy(previousScope, 0, newScope, 0, previousScope.length);
                            newScope[previousScope.length] = resultSet.getString("TOKEN_SCOPE");
                            tokenObj.setScope(newScope);
                        } else {
                            String consumerKey = resultSet.getString("CONSUMER_KEY");
                            String tokenScope = resultSet.getString("TOKEN_SCOPE");
                            String refreshToken = resultSet.getString("REFRESH_TOKEN");
                            String tokenId = resultSet.getString("TOKEN_ID");
                            int tenantId = resultSet.getInt("TENANT_ID");
                            String authzUser = resultSet.getString("AUTHZ_USER");
                            String subjectIdentifier = resultSet.getString("SUBJECT_IDENTIFIER");
                            String userDomain = resultSet.getString("USER_DOMAIN");
                            String authenticatedIDPName = resultSet.getString("NAME");
                            String authorizedOrganization = resultSet.getString("AUTHORIZED_ORGANIZATION");
                            AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser,
                                    userDomain, OAuth2Util.getTenantDomain(tenantId), authenticatedIDPName,
                                    authorizedOrganization, IdentityTenantUtil.getTenantDomainFromContext());
                            user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                            Timestamp issuedTime = resultSet
                                    .getTimestamp("TIME_CREATED", Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                            Timestamp refreshTokenIssuedTime =
                                    resultSet.getTimestamp("REFRESH_TOKEN_TIME_CREATED", Calendar.getInstance(TimeZone
                                            .getTimeZone(UTC)));
                            long validityPeriodInMillis = resultSet.getLong("VALIDITY_PERIOD");
                            long refreshTokenValidityPeriodMillis = resultSet.getLong("REFRESH_TOKEN_VALIDITY_PERIOD");
                            String tokenType = resultSet.getString("USER_TYPE");

                            String[] scope = OAuth2Util.buildScopeArray(tokenScope);
                            accessTokenDO.setAccessToken(token);
                            accessTokenDO.setConsumerKey(consumerKey);
                            accessTokenDO.setScope(scope);
                            accessTokenDO.setAuthzUser(user);
                            accessTokenDO.setTenantID(tenantId);
                            accessTokenDO.setRefreshToken(refreshToken);
                            accessTokenDO.setTokenId(tokenId);
                            accessTokenDO.setIssuedTime(issuedTime);
                            accessTokenDO.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                            accessTokenDO.setValidityPeriod(validityPeriodInMillis);
                            accessTokenDO.setRefreshTokenValidityPeriod(refreshTokenValidityPeriodMillis);
                            accessTokenDO.setTokenType(tokenType);
                            tokenMap.put(token, accessTokenDO);
                        }
                        return Collections.emptySet();
                    }),
                    (PreparedStatement preparedStatement) -> {
                        preparedStatement.setString(1, bindingRef);
                    });
            return new HashSet<>(tokenMap.values());
        } catch (DataAccessException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving access tokens.", e);
        }
    }

    public void updateTokenIsConsented(String tokenId, boolean isConsentedGrant)
            throws IdentityOAuth2Exception {

        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Updating the token's last issued grant type for token with id: " + tokenId + " to: " +
                        isConsentedGrant);
            }

            String sql = SQLQueries.UPDATE_TOKEN_CONSENTED_TOKEN;
            try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
                try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {
                    prepStmt.setString(1, Boolean.toString(isConsentedGrant));
                    prepStmt.setString(2, tokenId);
                    prepStmt.executeUpdate();
                    IdentityDatabaseUtil.commitTransaction(connection);
                } catch (SQLException e) {
                    IdentityDatabaseUtil.rollbackTransaction(connection); // ToDo add the exception here
                    throw new IdentityOAuth2Exception("Error while updating the access token.", e);
                }
            } catch (SQLException e) {
                throw new IdentityOAuth2Exception("Error while updating Access Token with ID: " + tokenId +
                        " to last issued grant type : ", e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("CONSENTED_TOKEN column is not available. Since not updating the token with id: "
                        + tokenId + " to: " + isConsentedGrant);
            }
        }
    }

    private String resolveOrganizationId(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while resolving organization ID for the tenant domain: " +
                    tenantDomain, e);
        }
    }

    private String getRootTenantDomainByOrganizationId(String organizationId) throws IdentityOAuth2Exception {

        try {
            String rootOrgID = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .getPrimaryOrganizationId(organizationId);
            return OAuthComponentServiceHolder.getInstance().getOrganizationManager().resolveTenantDomain(rootOrgID);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while resolving root tenant domain by organization ID: " +
                    organizationId, e);
        }
    }
}
