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

import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.model.OldAccessTokenDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * This is DAO class for cleaning old Tokens. When new tokens is generated ,refreshed or revoked old access token
 * will be moved to Audit table and deleted from the Access token table. Token cleaning process can be enable or
 * disable and old tokens can retain enable or disable by the configuration setting.
 */
public class OldTokensCleanDAO {

    private static Log log = LogFactory.getLog(OldTokensCleanDAO.class);

    public void cleanupTokenByTokenId(String tokenId, Connection connection) throws SQLException {
        if (OAuthServerConfiguration.getInstance().useRetainOldAccessTokens()) {
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.RETRIEVE_AND_STORE_IN_AUDIT);
            prepStmt.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
            prepStmt.setString(2, tokenId);
            prepStmt.executeUpdate();
        }
        removeTokenFromMainTable(tokenId, connection);
    }

    public void cleanupTokenByTokenValue(String token, Connection connection) throws SQLException {
        OldAccessTokenDO oldAccessTokenObject = new OldAccessTokenDO();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.RETRIEVE_OLD_TOKEN_BY_TOKEN_HASH);
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
        }
        if (OAuthServerConfiguration.getInstance().useRetainOldAccessTokens()) {
            saveTokenInAuditTable(oldAccessTokenObject, connection);
        }
        removeTokenFromMainTable(oldAccessTokenObject.getTokenId(), connection);
    }

    private void saveTokenInAuditTable(OldAccessTokenDO oldAccessTokenDAO, Connection connection) throws SQLException {
        PreparedStatement insertintoaudittable = connection.prepareStatement(SQLQueries.STORE_OLD_TOKEN_IN_AUDIT);
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
        insertintoaudittable.execute();
        if (log.isDebugEnabled()) {
            log.debug("Successfully saved old access token in audit table. Token ID: " + oldAccessTokenDAO.getTokenId());
        }
    }

    private void removeTokenFromMainTable(String oldAccessTokenID, Connection connection)
            throws SQLException {
        PreparedStatement deletefromaccesstokentable = connection.prepareStatement(SQLQueries.DELETE_OLD_TOKEN_BY_ID);
        deletefromaccesstokentable.setString(1, oldAccessTokenID);
        deletefromaccesstokentable.executeUpdate();
        if (log.isDebugEnabled()) {
            log.debug("Successfully old access token deleted from access token table. Token ID: " + oldAccessTokenID);
        }
    }

    public void cleanupTokensInBatch(List<String> oldTokens, Connection connection) throws SQLException {
        for (String token : oldTokens) {
            cleanupTokenByTokenValue(token, connection);
        }
    }
}

