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
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;

public class OAuthConsumerSecretDAO {

    private static final Log LOG = LogFactory.getLog(OAuthConsumerSecretDAO.class);
    private TokenPersistenceProcessor persistenceProcessor;

    public OAuthConsumerSecretDAO() {
        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextPersistenceProcessor");
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }
    }

    public void addOAuthConsumerSecret(OAuthConsumerSecretDO consumerSecretDO) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String processedClientSecret =
                    persistenceProcessor.getProcessedClientSecret(consumerSecretDO.getSecretValue());
            long expiryTime = System.currentTimeMillis() + consumerSecretDO.getExpiryTime() * 1000;
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER_SECRET)) {
                prepStmt.setString(1, consumerSecretDO.getSecretId());
                prepStmt.setString(2, consumerSecretDO.getDescription());
                prepStmt.setString(3, consumerSecretDO.getClientId());
                prepStmt.setString(4, processedClientSecret);
                prepStmt.setLong(5, expiryTime);
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
}
