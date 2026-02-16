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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

import static org.wso2.carbon.identity.core.util.IdentityUtil.getProperty;
import static org.wso2.carbon.identity.oauth2.dao.AbstractOAuthDAO.UTC;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RevokedTokenPersistenceSQLQueries;

/**
 * RDBMS based revoked access token persistence implementation.
 */
public class RevokedTokenDAOImpl implements RevokedTokenPersistenceDAO {

    private static final Log LOG = LogFactory.getLog(RevokedTokenDAOImpl.class);
    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";
    private static final int DEFAULT_TOKEN_PERSIST_RETRY_COUNT = 5;
    private static final String ENTITY_REVOKED_EVENT_CONSTRAINT = "IDN_SUBJECT_ENTITY_REVOKED_EVENT_CONSTRAINT";

    @Override
    public boolean isRevokedToken(String token, String consumerKey) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return false;
        }

        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                String maskedToken = DigestUtils.sha256Hex(token);
                LOG.debug(String.format("Validating access token (SHA-256): %s from the database.", maskedToken));
            } else {
                LOG.debug("Validating access token from the IDN_OAUTH2_REVOKED_TOKENS table.");
            }
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(
                    RevokedTokenPersistenceSQLQueries.IS_REVOKED_TOKEN)) {
                preparedStatement.setString(1, token);
                preparedStatement.setString(2, consumerKey);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an revoked token.", e);
        }
    }

    @Override
    public void addRevokedToken(String token, String consumerKey, Long expiryTime)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }

        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                LOG.debug(String.format("Insert revoked token (hashed): %s for consumer key: %s with expiry time: %s",
                        DigestUtils.sha256Hex(token), consumerKey, expiryTime));
            } else {
                LOG.debug(String.format("Insert revoked token for consumer key: %s with expiry time: %s", consumerKey,
                        expiryTime));
            }
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(
                    RevokedTokenPersistenceSQLQueries.INSERT_REVOKED_TOKEN)) {
                preparedStatement.setString(1, UUID.randomUUID().toString());
                preparedStatement.setString(2, token);
                preparedStatement.setString(3, consumerKey);
                preparedStatement.setTimestamp(4, new Timestamp(expiryTime),
                        Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                preparedStatement.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception(String.format("Failed to add revoked token for consumer key: %s with "
                        + "expiry time: %s", consumerKey, expiryTime), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(String.format("Failed to add revoked token for consumer key: %s with "
                    + "expiry time: %s", consumerKey, expiryTime), e);
        }
    }

    @Override
    public boolean isTokenRevokedForSubjectEntity(String entityId, Date tokenIssuedTime)
            throws IdentityOAuth2Exception {

        // Here subjects can be users or applications.
        // The subjectIdType can be either "USER_ID", "USER_NAME" or "CLIENT_ID".

        if (!isEnabled()) {
            return false;
        }

        /*
         * Check whether any internally revoked event is persisted for the given entity which is revoked after
         * the given token issued timestamp.
         */
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Check whether any internally revoked event is present for the subject entity "
                    + "id after issuing the token at: %s", tokenIssuedTime));
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(
                     RevokedTokenPersistenceSQLQueries.IS_SUBJECT_ENTITY_REVOKED_EVENT)) {
            ps.setString(1, entityId);
            ps.setTimestamp(2, new Timestamp(tokenIssuedTime.getTime()),
                    Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            try (ResultSet resultSet = ps.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of internally revoked JWT for subject "
                    + "entity id.", e);
        }
    }

    @Override
    public void revokeTokensBySubjectEvent(String subjectId, String subjectIdType,
                                           long revocationTime, int tenantId, int retryAttemptCounter)
            throws IdentityOAuth2Exception {

        // Here subjects can be users or applications.
        // The subjectIdType can be either "USER_ID", "USER_NAME" or "CLIENT_ID".

        if (!isEnabled()) {
            return;
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            String updateQuery = RevokedTokenPersistenceSQLQueries.UPDATE_SUBJECT_ENTITY_REVOKED_EVENT;
            try (PreparedStatement ps = connection.prepareStatement(updateQuery)) {
                ps.setTimestamp(1, new Timestamp(revocationTime),
                        Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                ps.setString(2, subjectId);
                ps.setString(3, subjectIdType);
                ps.setInt(4, tenantId);
                int rowsAffected = ps.executeUpdate();
                if (rowsAffected == 0) {
                    LOG.debug("Subject event token revocation rule not found. Inserting new rule.");
                    IdentityDatabaseUtil.rollbackTransaction(connection);
                    String insertQuery = RevokedTokenPersistenceSQLQueries.INSERT_SUBJECT_ENTITY_REVOKED_EVENT;
                    try (PreparedStatement ps1 = connection.prepareStatement(insertQuery)) {
                        ps1.setString(1, UUID.randomUUID().toString());
                        ps1.setString(2, subjectId);
                        ps1.setString(3, subjectIdType);
                        ps1.setTimestamp(4, new Timestamp(revocationTime),
                                Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                        ps1.setInt(5, tenantId);
                        ps1.execute();
                        IdentityDatabaseUtil.commitTransaction(connection);
                        if (retryAttemptCounter > 0) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Successfully recovered " + ENTITY_REVOKED_EVENT_CONSTRAINT
                                        + " constraint violation with the attempt : "
                                        + retryAttemptCounter);
                            }
                        }
                    } catch (SQLIntegrityConstraintViolationException e) {
                        rollbackSubjectEventTransaction(connection);
                        retryOnConstraintViolationException(retryAttemptCounter, subjectId, subjectIdType,
                                revocationTime, tenantId, e);
                    } catch (SQLException e) {
                        rollbackSubjectEventTransaction(connection);
                        // Handle constrain violation issue in JDBC drivers which does not throw
                        // SQLIntegrityConstraintViolationException
                        if (StringUtils.containsIgnoreCase(e.getMessage(), ENTITY_REVOKED_EVENT_CONSTRAINT)) {
                            retryOnConstraintViolationException(retryAttemptCounter, subjectId, subjectIdType,
                                    revocationTime, tenantId, e);
                        } else {
                            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                                    + e.getMessage(), e);
                        }
                    }
                } else {
                    LOG.debug("User event token revocation rule updated.");
                    IdentityDatabaseUtil.commitTransaction(connection);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                        + e.getMessage(), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                    + e.getMessage(), e);
        }
    }

    /**
     * Retry the user event token revocation event persisting transaction on constraint violation exception.
     *
     * @param retryAttemptCounter Retry attempt counter
     * @param subjectId           Subject id
     * @param subjectIdType       Subject id type
     * @param revocationTime      Revocation time
     * @param tenantId              Tenant
     * @param exception           Constraint Violation Exception
     * @throws IdentityOAuth2Exception If maximum retry count exceeds
     */
    private void retryOnConstraintViolationException(int retryAttemptCounter, String subjectId, String subjectIdType,
                                                     long revocationTime, int tenantId, Exception exception)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("User event token revocation rule for subject id : %s, "
                            + "type : %s and tenant : %s already exists", subjectId, subjectIdType, tenantId));
        }
        if (retryAttemptCounter >= getTokenPersistRetryCount()) {
            String errorMessage = ENTITY_REVOKED_EVENT_CONSTRAINT
                    + " constraint violation retry count exceeds the maximum count.";
            throw new IdentityOAuth2Exception(errorMessage, exception);
        }
        revokeTokensBySubjectEvent(subjectId, subjectIdType, revocationTime, tenantId,
                retryAttemptCounter + 1);
    }

    /**
     * Rollback the user event token revocation event persisting transaction.
     *
     * @param connection Connection
     */
    private void rollbackSubjectEventTransaction(Connection connection) {

        LOG.debug("Subject event token revocation rule already persisted.");
        IdentityDatabaseUtil.rollbackTransaction(connection);
    }

    /**
     * Get the maximum number of retries for token persistence.
     *
     * @return Maximum number of retries for token persistence.
     */
    private int getTokenPersistRetryCount() {

        int tokenPersistRetryCount = DEFAULT_TOKEN_PERSIST_RETRY_COUNT;
        if (getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT) != null) {
            tokenPersistRetryCount = Integer.parseInt(getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT));
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("OAuth Token Persistence Retry count set to " + tokenPersistRetryCount);
        }
        return tokenPersistRetryCount;
    }

    /**
     * Check whether the revoked token persistence is enabled.
     *
     * @return true if the revoked token persistence is enabled, false otherwise.
     */
    private boolean isEnabled() {

        return !OAuth2Util.isAccessTokenPersistenceEnabled() && OAuth2Util.isKeepRevokedAccessTokenEnabled();
    }
}
