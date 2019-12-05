/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

/**
 * Implementation of abstract DAO layer.
 */
public class CibaMgtDAOImpl implements CibaMgtDAO {

    private static final Log log = LogFactory.getLog(CibaMgtDAOImpl.class);

    @Override
    public void updateStatus(String authCodeKey, Enum authenticationStatus) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS)) {

                prepStmt.setString(1, authenticationStatus.toString());
                prepStmt.setString(2, authCodeKey);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authentication status: " + authenticationStatus +
                            " identified by authCodeKey: " + authCodeKey);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException(
                        "Error occurred in persisting authentication status for the authCodeKey: " + authCodeKey, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException(
                    "Error occurred in persisting authentication status for the authCodeKey: " + authCodeKey, e);
        }
    }

    @Override
    public void persistAuthenticationSuccess(String authCodeKey, AuthenticatedUser authenticatedUser)
            throws CibaCoreException {

        // Obtain authenticated identity provider's identifier.
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authenticatedUser);

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    UPDATE_AUTHENTICATION_SUCCESS)) {

                int authenticatedTenant = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
                prepStmt.setString(1, authenticatedUser.getUserName());
                prepStmt.setString(2, authenticatedUser.getUserStoreDomain());
                prepStmt.setInt(3, authenticatedTenant);
                prepStmt.setString(4, authenticatedIDP);
                prepStmt.setInt(5, authenticatedTenant);
                prepStmt.setString(6, AuthReqStatus.AUTHENTICATED.toString());
                prepStmt.setString(7, authCodeKey);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated the authentication request status to 'AUTHENTICATED' for the " +
                            "request identified by authCodeKey: " + authCodeKey);
                }
            } catch (SQLException | IdentityOAuth2Exception e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in persisting the successful authentication identified by" +
                        " authCodeKey: " + authCodeKey, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in persisting the successful authentication identified by " +
                    "authCodeKey: " + authCodeKey, e);
        }
    }

    @Override
    public String getCibaAuthCodeKey(String authReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_CIBA_AUTH_CODE_KEY_BY_CIBA_AUTH_REQ_ID)) {

                prepStmt.setString(1, authReqId);
                try (ResultSet resultSet = prepStmt.executeQuery()) {
                    if (resultSet.next()) {
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "Successfully returning Ciba AuthCodeKey : " + resultSet.getString(1) + "for the " +
                                            "ciba auth_req_id : " + authReqId);
                        }
                        return resultSet.getString(1);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("No authCodeKey found for the provided auth_req_id: " + authReqId);
                        }
                        return null;
                    }
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(
                    "Error occurred when searching for  authCodeKey for the auth_req_id: " + authReqId, e);
        }
    }

    @Override
    public void updateLastPollingTime(String authCodeKey, Timestamp lastPolledTime) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME)) {

                prepStmt.setTimestamp(1, lastPolledTime, Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)));
                prepStmt.setString(2, authCodeKey);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated lastPollingTime of TokenRequest  with authCodeKey : " +
                            authCodeKey);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in updating lastPollingTime of TokenRequest identified by" +
                        " authCodeKey: " + authCodeKey, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in updating lastPollingTime of TokenRequest identified by " +
                    "authCodeKey: " + authCodeKey, e);
        }
    }

    @Override
    public void updatePollingInterval(String authCodeKey, long newInterval) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL)) {

                prepStmt.setLong(1, newInterval);
                prepStmt.setString(2, authCodeKey);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated pollingInterval of TokenRequest  with authCodeKey : " +
                            authCodeKey);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in updating pollingInterval of TokenRequest identified by" +
                        " authCodeKey: " + authCodeKey, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in updating pollingInterval of TokenRequest identified by " +
                    "authCodeKey: " + authCodeKey, e);
        }
    }

    @Override
    public AuthenticatedUser getAuthenticatedUser(String authCodeKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER)) {

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                prepStmt.setString(1, authCodeKey);
                try (ResultSet resultSet = prepStmt.executeQuery()) {
                    if (resultSet.next()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully obtained authenticatedUser of TokenRequest  with " +
                                    "authCodeKey : " + authCodeKey);
                        }
                        authenticatedUser.setUserName(resultSet.getString(1));
                        authenticatedUser.setUserStoreDomain(resultSet.getString(2));
                        authenticatedUser.setTenantDomain(OAuth2Util.getTenantDomain(resultSet.getInt(3)));
                        return authenticatedUser;
                    } else {
                        throw new CibaCoreException(
                                "No record found for authenticatedUser of TokenRequest identified by " +
                                        "authCodeKey: " + authCodeKey);
                    }
                }
            } catch (IdentityOAuth2Exception e) {
                throw new CibaCoreException("Error occurred in obtaining authenticatedUser of TokenRequest identified" +
                        " by authCodeKey: " + authCodeKey, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in obtaining authenticatedUser of TokenRequest identified by " +
                    "authCodeKey: " + authCodeKey, e);
        }
    }

    @Override
    public void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.STORE_CIBA_AUTH_CODE)) {

                prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeKey());
                prepStmt.setString(2, cibaAuthCodeDO.getAuthReqId());
                prepStmt.setString(3, cibaAuthCodeDO.getConsumerKey());
                prepStmt.setTimestamp(4, cibaAuthCodeDO.getIssuedTime(), Calendar
                        .getInstance(TimeZone.getTimeZone(CibaConstants.UTC)));
                prepStmt.setTimestamp(5, cibaAuthCodeDO.getLastPolledTime(),
                        Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)));
                prepStmt.setLong(6, cibaAuthCodeDO.getInterval());
                prepStmt.setLong(7, cibaAuthCodeDO.getExpiresIn());
                prepStmt.setString(8, cibaAuthCodeDO.getAuthReqStatus().toString());
                prepStmt.execute();

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted cibaAuthCodeDO for unique CibaAuthCodeKey : " +
                            cibaAuthCodeDO.getCibaAuthCodeKey());
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred while persisting cibaAuthCode for the application with " +
                        "consumer key: " + cibaAuthCodeDO.getConsumerKey() + " and with authCodeKey: " +
                        cibaAuthCodeDO.getCibaAuthCodeKey(), e);
            }

            try (PreparedStatement prepStmtForScope =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.STORE_SCOPES)) {

                for (String singleScopeValue : cibaAuthCodeDO.getScopes()) {

                    prepStmtForScope.setString(1, cibaAuthCodeDO.getCibaAuthCodeKey());
                    prepStmtForScope.setString(2, singleScopeValue);
                    prepStmtForScope.addBatch();
                }
                prepStmtForScope.executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted scopes for unique authCodeKey : " +
                            cibaAuthCodeDO.getCibaAuthCodeKey());
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred while persisting scopes for the application with " +
                        "consumer key: " + cibaAuthCodeDO.getConsumerKey() + " and with authCodeKey: " +
                        cibaAuthCodeDO.getCibaAuthCodeKey(), e);
            }

            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred while persisting cibaAuthCode for the application with " +
                    "consumer key: " + cibaAuthCodeDO.getConsumerKey() + " and with authCodeKey: " +
                    cibaAuthCodeDO.getCibaAuthCodeKey(), e);
        }
    }

    @Override
    public CibaAuthCodeDO getCibaAuthCode(String authCodeKey) throws CibaCoreException {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_AUTH_CODE)) {

                prepStmt.setString(1, authCodeKey);
                try (ResultSet resultSet = prepStmt.executeQuery()) {
                    if (resultSet.next()) {
                        cibaAuthCodeDO.setCibaAuthCodeKey(resultSet.getString(1));
                        cibaAuthCodeDO.setAuthReqId(resultSet.getString(2));
                        cibaAuthCodeDO.setConsumerKey(resultSet.getString(3));
                        cibaAuthCodeDO.setLastPolledTime(
                                resultSet.getTimestamp(4,
                                        Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC))));
                        cibaAuthCodeDO.setInterval(resultSet.getLong(5));
                        cibaAuthCodeDO.setExpiresIn(resultSet.getLong(6));
                        cibaAuthCodeDO.setAuthReqStatus(AuthReqStatus.valueOf(resultSet.getString(7)));
                        cibaAuthCodeDO.setIssuedTime(
                                resultSet.getTimestamp(8,
                                        Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC))));
                    } else {
                        return null;
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained cibaAuthCode for unique authCodeKey : " + authCodeKey);
                    }
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error in obtaining cibaAuthCode for unique authCodeKey : " + authCodeKey, e);
        }
        return cibaAuthCodeDO;
    }

    @Override
    public List<String> getScopes(String authCodeKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_SCOPE)) {

                ArrayList<String> scopeArrayList = new ArrayList<>();
                prepStmt.setString(1, authCodeKey);
                try (ResultSet resultSet = prepStmt.executeQuery()) {
                    while (resultSet.next()) {
                        scopeArrayList.add(resultSet.getString(1));
                    }
                    return scopeArrayList;
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(
                    "Error in retrieving scopes for the authCodeKey: " + authCodeKey, e);
        }
    }
}
