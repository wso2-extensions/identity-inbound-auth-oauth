/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;

public class OAuthConsumerSecretDAO {

    private static final Log LOG = LogFactory.getLog(OAuthConsumerSecretDAO.class);
    private TokenPersistenceProcessor persistenceProcessor;
    private final TokenPersistenceProcessor hashingPersistenceProcessor;

    public OAuthConsumerSecretDAO() {
        hashingPersistenceProcessor = new HashingPersistenceProcessor();
        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextPersistenceProcessor");
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }
    }

    /**
     * Add a new OAuth consumer secret.
     *
     * @param consumerSecretDO OAuthConsumerSecretDO containing the details of the consumer secret to be added
     * @throws IdentityOAuthAdminException if an error occurs while adding the consumer secret.
     */
    public void addOAuthConsumerSecret(OAuthConsumerSecretDO consumerSecretDO) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String processedClientSecret =
                    persistenceProcessor.getProcessedClientSecret(consumerSecretDO.getSecretValue());
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER_SECRET)) {
                prepStmt.setString(1, consumerSecretDO.getSecretId());
                prepStmt.setString(2, consumerSecretDO.getDescription());
                prepStmt.setString(3, consumerSecretDO.getClientId());
                prepStmt.setString(4, processedClientSecret);
                prepStmt.setString(5, hashingPersistenceProcessor
                        .getProcessedAccessTokenIdentifier(consumerSecretDO.getSecretValue()));
                if (consumerSecretDO.getExpiresAt() != null) {
                    prepStmt.setLong(6, consumerSecretDO.getExpiresAt());
                } else {
                    prepStmt.setNull(6, java.sql.Types.BIGINT); // inserts NULL into EXPIRY_TIME
                }
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw handleError("Error occurred while adding OAuth consumer secret for client id : "
                        + consumerSecretDO.getClientId(), e);
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while processing the client secret by TokenPersistenceProcessor",
                    e);
        } catch (SQLException e) {
            throw handleError("Error occurred while obtaining a connection from the identity database", e);
        }
    }

    /**
     * Remove an OAuth consumer secret.
     *
     * @param secretId ID of the secret to be removed.
     * @throws IdentityOAuthAdminException if an error occurs while removing the consumer secret.
     */
    public void removeOAuthConsumerSecret(String secretId) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.REMOVE_OAUTH_CONSUMER_SECRET)) {
                prepStmt.setString(1, secretId);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            }
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries
                    .REMOVE_OAUTH_CONSUMER_SECRET, e);
        }
    }

    public List<OAuthConsumerSecretDO> getOAuthConsumerSecrets(String consumerKey) throws IdentityOAuthAdminException {

        List<OAuthConsumerSecretDO> consumerSecrets = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_OAUTH_CONSUMER_SECRETS_OF_CLIENT)) {
                prepStmt.setString(1, consumerKey);
                try (ResultSet resultSet = prepStmt.executeQuery()) {
                    while (resultSet.next()) {
                        OAuthConsumerSecretDO secret = new OAuthConsumerSecretDO();
                        secret.setSecretId(resultSet.getString(1));
                        secret.setDescription(resultSet.getString(2));
                        secret.setClientId(resultSet.getString(3));
                        secret.setSecretValue(resultSet.getString(4));
                        secret.setExpiresAt(resultSet.getLong(5));
                        consumerSecrets.add(secret);
                    }
                }
            }
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries
                    .GET_OAUTH_CONSUMER_SECRETS_OF_CLIENT, e);
        }
        return consumerSecrets;
    }
}
