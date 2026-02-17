/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.model.OldAccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * This is DAO class for cleaning old Tokens. When new tokens is generated ,refreshed or revoked old access token
 * will be moved to Audit table and deleted from the Access token table. Token cleaning process can be enable or
 * disable and old tokens can retain enable or disable by the configuration setting.
 */
public class OldTokensCleanDAO {

    private static final Log log = LogFactory.getLog(OldTokensCleanDAO.class);

    public void cleanupTokenByTokenId(String tokenId, Connection connection) throws SQLException {

        try {
            connection.setAutoCommit(false);
            if (OAuthServerConfiguration.getInstance().useRetainOldAccessTokens()) {
                String sql = SQLQueries.RETRIEVE_AND_STORE_IN_AUDIT_WITH_IDP_NAME;

                PreparedStatement prepStmt = connection.prepareStatement(sql);
                prepStmt.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
                prepStmt.setString(2, tokenId);
                prepStmt.executeUpdate();
            }
            removeTokenFromMainTable(tokenId, connection);
            connection.commit();
        } catch (SQLException e) {
            connection.rollback();
            log.error("SQL error occurred while cleanup token by tokenId", e);
        }
    }

    public void cleanupTokenByTokenValue(String token, Connection connection) throws SQLException {
        OldAccessTokenDO oldAccessTokenObject = new OldAccessTokenDO();

        String sql = SQLQueries.RETRIEVE_OLD_TOKEN_BY_TOKEN_HASH_WITH_IDP_NAME;

        PreparedStatement prepStmt = connection.prepareStatement(sql);
        prepStmt.setString(1, token);
        ResultSet resultSet = prepStmt.executeQuery();
        //iterate result set and insert to AccessTokenDO object.
        if (resultSet.next()) {
            oldAccessTokenObject.setTokenId(resultSet.getString(1));
            oldAccessTokenObject.setAccessToken(resultSet.getString(2));
            oldAccessTokenObject.setRefreshToken(resultSet.getString(3));
            oldAccessTokenObject.setConsumerKeyId(resultSet.getInt(4));
            oldAccessTokenObject.setAuthzUser(resultSet.getString(5));
            oldAccessTokenObject.setTenantId(resultSet.getInt(6));
            oldAccessTokenObject.setUserDomain(resultSet.getString(7));
            oldAccessTokenObject.setUserType(resultSet.getString(8));
            oldAccessTokenObject.setGrantType(resultSet.getString(9));
            oldAccessTokenObject.setTimeCreated(resultSet.getTimestamp(10));
            oldAccessTokenObject.setRefreshTokenTimeCreated(resultSet.getTimestamp(11));
            oldAccessTokenObject.setValdityPeriod(resultSet.getLong(12));
            oldAccessTokenObject.setRefreshTokenValidityPeriod(resultSet.getLong(13));
            oldAccessTokenObject.setTokenScopeHash(resultSet.getString(14));
            oldAccessTokenObject.setTokenState(resultSet.getString(15));
            oldAccessTokenObject.setTokenStateId(resultSet.getString(16));
            oldAccessTokenObject.setSubjectIdentifier(resultSet.getString(17));
            oldAccessTokenObject.setAccessTokenHash(resultSet.getString(18));
            oldAccessTokenObject.setRefreshTokenHash(resultSet.getString(19));
            String tokenBindingRef = resultSet.getString(20);
            if (StringUtils.isNotBlank(tokenBindingRef)) {
                TokenBinding tokenBinding = new TokenBinding();
                tokenBinding.setBindingReference(tokenBindingRef);
                oldAccessTokenObject.setTokenBinding(tokenBinding);
            }

            String isConsentedToken = resultSet.getString(21);
            if (StringUtils.isNotEmpty(isConsentedToken)) {
                oldAccessTokenObject.setIsConsentedToken(Boolean.parseBoolean(isConsentedToken));
            }

            oldAccessTokenObject.setAuthorizedOrganizationId(resultSet.getString(22));

            oldAccessTokenObject.setIdpId(resultSet.getInt(23));
        }
        if (OAuthServerConfiguration.getInstance().useRetainOldAccessTokens()) {
            saveTokenInAuditTable(oldAccessTokenObject, connection);
        }
        removeTokenFromMainTable(oldAccessTokenObject.getTokenId(), connection);
    }

    private void saveTokenInAuditTable(OldAccessTokenDO oldAccessTokenDAO, Connection connection) throws SQLException {

        String sql = SQLQueries.STORE_OLD_TOKEN_IN_AUDIT_WITH_IDP_NAME;

        PreparedStatement insertintoaudittable = connection.prepareStatement(sql);
        insertintoaudittable.setString(1, oldAccessTokenDAO.getTokenId());
        insertintoaudittable.setString(2, oldAccessTokenDAO.getAccessToken());
        insertintoaudittable.setString(3, oldAccessTokenDAO.getRefreshToken());
        insertintoaudittable.setInt(4, oldAccessTokenDAO.getConsumerKeyId());
        insertintoaudittable.setString(5, oldAccessTokenDAO.getAuthzUserValue());
        insertintoaudittable.setInt(6, oldAccessTokenDAO.getTenantId());
        insertintoaudittable.setString(7, oldAccessTokenDAO.getUserDomain());
        insertintoaudittable.setString(8, oldAccessTokenDAO.getUserType());
        insertintoaudittable.setString(9, oldAccessTokenDAO.getGrantType());
        insertintoaudittable.setTimestamp(10, oldAccessTokenDAO.getTimeCreated());
        insertintoaudittable.setTimestamp(11, oldAccessTokenDAO.getRefreshTokenTimeCreated());
        insertintoaudittable.setLong(12, oldAccessTokenDAO.getValdityPeriod());
        insertintoaudittable.setLong(13, oldAccessTokenDAO.getRefreshTokenValidityPeriod());
        insertintoaudittable.setString(14, oldAccessTokenDAO.getTokenScopeHash());
        insertintoaudittable.setString(15, oldAccessTokenDAO.getTokenState());
        insertintoaudittable.setString(16, oldAccessTokenDAO.getTokenStateId());
        insertintoaudittable.setString(17, oldAccessTokenDAO.getSubjectIdentifier());
        insertintoaudittable.setString(18, oldAccessTokenDAO.getAccessTokenHash());
        insertintoaudittable.setString(19, oldAccessTokenDAO.getRefreshTokenHash());
        insertintoaudittable.setTimestamp(20, new Timestamp(System.currentTimeMillis()));
        if (oldAccessTokenDAO.getTokenBinding() != null && StringUtils
                .isNotBlank(oldAccessTokenDAO.getTokenBinding().getBindingReference())) {
            insertintoaudittable.setString(21, oldAccessTokenDAO.getTokenBinding().getBindingReference());
        } else {
            insertintoaudittable.setString(21, NONE);
        }
        insertintoaudittable.setString(22, Boolean.toString(oldAccessTokenDAO.isConsentedToken()));
        insertintoaudittable.setString(23, oldAccessTokenDAO.getAuthorizedOrganizationId());
        insertintoaudittable.setInt(24, oldAccessTokenDAO.getIdpId());

        insertintoaudittable.execute();
        if (log.isDebugEnabled()) {
            log.debug(
                    "Successfully saved old access token in audit table. Token ID: " + oldAccessTokenDAO.getTokenId());
        }
    }

    private void removeTokenFromMainTable(String oldAccessTokenID, Connection connection)
            throws SQLException {

        connection.setAutoCommit(false);
        try {
            PreparedStatement deletefromaccesstokentable =
                    connection.prepareStatement(SQLQueries.DELETE_OLD_TOKEN_BY_ID);
            deletefromaccesstokentable.setString(1, oldAccessTokenID);
            deletefromaccesstokentable.executeUpdate();
            if (log.isDebugEnabled()) {
                log.debug(
                        "Successfully old access token deleted from access token table. Token ID: " + oldAccessTokenID);
            }
            connection.commit();
        } catch (SQLException e) {
            connection.rollback();
            log.error("SQL error occurred while remove token from main table", e);
        }
    }

    public void cleanupTokensInBatch(List<String> oldTokens, Connection connection) throws SQLException {
        for (String token : oldTokens) {
            cleanupTokenByTokenValue(token, connection);
        }
    }

    /**
     * Cleans up the refresh token by its token value.
     *
     * @param token      The refresh token value to be cleaned up.
     * @param connection The database connection to use for the operation.
     * @throws SQLException If an error occurs while cleaning up the refresh token.
     */
    public void cleanupRefreshTokenByTokenValue(String token, Connection connection) throws SQLException {

        removeTokenFromMainTableByValue(token, connection);
    }

    private void removeTokenFromMainTableByValue(String token, Connection connection)
            throws SQLException {

        // Use try-with-resources to ensure the PreparedStatement is closed automatically
        try (PreparedStatement deleteStmt = connection.prepareStatement(
                SQLQueries.RefreshTokenPersistenceSQLQueries.DELETE_OLD_TOKEN_BY_VALUE)) {

            // Set the parameter for the query
            deleteStmt.setString(1, token);
            // Execute the delete operation
            int rowsAffected = deleteStmt.executeUpdate();
            // Log success if debug level is enabled
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully deleted old access token from access token table. " +
                        "Token value: %s, Rows affected: %d", token, rowsAffected));
            }
            // Commit the transaction if no errors occurred
            connection.commit();

        } catch (SQLException e) {
            // Rollback in case of an error
            connection.rollback();
            log.error("SQL error occurred while removing token from main table", e);
        }
    }

    public void cleanupRefreshTokenByTokenId(String tokenId, Connection connection) throws SQLException {

        removeTokenFromMainTableById(tokenId, connection);
    }

    private void removeTokenFromMainTableById(String tokenId, Connection connection)
            throws SQLException {

        // Use try-with-resources to automatically close the PreparedStatement
        try (PreparedStatement deleteStmt =
                     connection.prepareStatement(SQLQueries.RefreshTokenPersistenceSQLQueries.DELETE_OLD_TOKEN_BY_ID)) {

            // Set the tokenId parameter
            deleteStmt.setString(1, tokenId);
            // Execute the update and check how many rows were affected
            int rowsAffected = deleteStmt.executeUpdate();
            // Log the success message if debug logging is enabled
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully deleted old access token from access token table. " +
                        "Token id: %s, Rows affected: %d", tokenId, rowsAffected));
            }
            // Commit the transaction if the operation was successful
            connection.commit();

        } catch (SQLException e) {
            // Rollback the transaction in case of an error
            connection.rollback();
            log.error("SQL error occurred while removing token from the main table. Token id: " + tokenId, e);
        }
    }

    /**
     * Cleans up the refresh tokens associated with a specific application identified by its consumer key.
     *
     * @param consumerKey The consumer key of the application for which to clean up refresh tokens.
     * @param connection  The database connection to use for the operation.
     * @throws SQLException If an error occurs while cleaning up the refresh tokens.
     */
    public void cleanupRefreshTokenByApp(String consumerKey, Connection connection) throws SQLException {

        // Use try-with-resources to automatically close the PreparedStatement
        try (PreparedStatement preparedStatement = connection.prepareStatement(
                SQLQueries.RefreshTokenPersistenceSQLQueries.DELETE_APP_REFRESH_TOKEN)) {

            // Set parameters for the DELETE query
            preparedStatement.setString(1, consumerKey);
            preparedStatement.setString(2, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);

            // Execute the query
            int rowsAffected = preparedStatement.executeUpdate();

            // Log success if debug level is enabled
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully deleted refresh tokens from table for Consumer Id: %s, " +
                        "Rows affected: %d", consumerKey, rowsAffected));
            }
            // Commit the transaction if the operation was successful
            connection.commit();

        } catch (SQLException e) {
            // Rollback in case of an error
            connection.rollback();

            log.error("SQL error occurred while removing refresh token for Consumer Id: " + consumerKey, e);
        }
    }

    /**
     * Cleans up the refresh tokens associated with a specific user in a given tenant and user store domain.
     *
     * @param authorizedUser The authorized user whose refresh tokens are to be cleaned up.
     * @param tenantId       The tenant ID of the user.
     * @param userDomain     The user store domain of the authorized user.
     * @param connection     The database connection to use for the operation.
     * @throws SQLException If an error occurs while cleaning up the refresh tokens.
     */
    public void cleanupRefreshTokenByUser(String authorizedUser, int tenantId, String userDomain,
                                          Connection connection)  throws SQLException {

        // Use try-with-resources to automatically close the PreparedStatement
        try (PreparedStatement deleteStmt = connection.prepareStatement(
                SQLQueries.RefreshTokenPersistenceSQLQueries.DELETE_USER_REFRESH_TOKEN)) {

            // Set parameters for the delete query
            deleteStmt.setString(1, authorizedUser);
            deleteStmt.setInt(2, tenantId);
            deleteStmt.setString(3, userDomain);

            // Execute the delete operation
            int rowsAffected = deleteStmt.executeUpdate();
            // Log the success if debug level logging is enabled
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully deleted refresh tokens for user Id: %s, " +
                        "Rows affected: %d", authorizedUser, rowsAffected));
            }
            // Commit the transaction if the operation was successful
            connection.commit();

        } catch (SQLException e) {
            // Rollback the transaction in case of error
            connection.rollback();
            log.error("SQL error occurred while removing refresh token for user Id.", e);
        }
    }
}
