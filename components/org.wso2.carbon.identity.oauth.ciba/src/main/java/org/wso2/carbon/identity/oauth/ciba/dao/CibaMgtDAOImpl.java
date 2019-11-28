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
import java.util.TimeZone;

/**
 * Implementation of abstract DAO layer.
 */
public class CibaMgtDAOImpl implements CibaMgtDAO {

    private static final Log log = LogFactory.getLog(CibaMgtDAOImpl.class);

    @Override
    public void updateStatus(String key, Enum authenticationStatus) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS)) {

                prepStmt.setString(1, authenticationStatus.toString());
                prepStmt.setString(2, key);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authentication status: " + authenticationStatus +
                            " identified by CibaAuthCodeKey: " + key);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException(
                        "Error occurred in persisting authentication status for the authCodeKey: " + key, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException(
                    "Error occurred in persisting authentication status for the authCodeKey: " + key, e);
        }
    }

    @Override
    public void persistAuthenticatedUser(String key, AuthenticatedUser authenticatedUser, int tenantID)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    UPDATE_AUTHENTICATED_USER)) {

                prepStmt.setString(1, authenticatedUser.getUserName());
                prepStmt.setString(2, authenticatedUser.getUserStoreDomain());
                prepStmt.setInt(3, tenantID);
                prepStmt.setString(4, key);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authenticated_user identified by AuthCodeDOKey : " +
                            key);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException(
                        "Error occurred in persisting the authenticated user: " + authenticatedUser.getUserName() +
                                " identified by AuthCodeDOKey: " + key, e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException(
                    "Error occurred in persisting the authenticated user: " + authenticatedUser.getUserName() +
                            " identified by AuthCodeDOKey: " + key, e);
        }
    }

    @Override
    public void persistAuthenticationSuccess(String key, AuthenticatedUser authenticatedUser, int tenantID)
            throws CibaCoreException {

        // Obtain authenticated identity provider's identifier.
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authenticatedUser);
        int idpID = getIdpID(authenticatedIDP);

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    UPDATE_AUTHENTICATION_SUCCESS)) {

                prepStmt.setString(1, authenticatedUser.getUserName());
                prepStmt.setString(2, authenticatedUser.getUserStoreDomain());
                prepStmt.setInt(3, tenantID);
                prepStmt.setInt(4, idpID);
                prepStmt.setString(5, AuthReqStatus.AUTHENTICATED.toString());
                prepStmt.setString(6, key);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the successful authentication identified by AuthCodeDOKey: " +
                            key);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in persisting the successful authentication.", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in persisting the successful authentication.", e);
        }
    }

    @Override
    public boolean isAuthReqIdExist(String authReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    CHECK_IF_AUTH_REQ_ID_EXISTS)) {

                prepStmt.setString(1, authReqId);
                ResultSet resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                    //do nothing
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully checked whether provided auth_req_id : " + authReqId +
                                " exists.Provided AuthReqId exists.It is from a valid auth_req_id.");
                    }
                    return true;
                } else {
                    return false;
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Unsuccessful in checking whether provided auth_req_id: " + authReqId +
                    " exists.", e);
        }
    }

    @Override
    public String getCibaAuthCodeKey(String authReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_CIBA_AUTH_CODE_KEY_BY_CIBA_AUTH_REQ_ID)) {

                prepStmt.setString(1, authReqId);
                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning CibaAuthCodeKey : " + resultSet.getString(1) + "for the " +
                                "ciba auth_req_id : " + authReqId);
                    }
                    return resultSet.getString(1);
                } else {
                    throw new CibaCoreException("No auth_req_id found.");
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred when searching for CibaAuthCode.", e);
        }
    }

    @Override
    public void updateLastPollingTime(String key, Timestamp lastPolledTime) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME)) {

                prepStmt.setTimestamp(1, lastPolledTime, Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)));
                prepStmt.setString(2, key);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated lastPollingTime of TokenRequest  with cibaAuthCodeKey : " +
                            key);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in updating lastPollingTime of TokenRequest", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in updating lastPollingTime of TokenRequest", e);
        }
    }

    @Override
    public void updatePollingInterval(String key, long newInterval) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL)) {

                prepStmt.setLong(1, newInterval);
                prepStmt.setString(2, key);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated pollingInterval of TokenRequest  with CibaAuthCodeKey : " +
                            key);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in updating pollingInterval of TokenRequest", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in updating pollingInterval of TokenRequest", e);
        }
    }

    @Override
    public AuthenticatedUser getAuthenticatedUser(String CibaAuthCodeKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER)) {

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                prepStmt.setString(1, CibaAuthCodeKey);
                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained authenticatedUser of TokenRequest  with " +
                                "CibaAuthCodeKey : " + CibaAuthCodeKey);
                    }
                    authenticatedUser.setUserName(resultSet.getString(1));
                    authenticatedUser.setUserStoreDomain(resultSet.getString(2));
                    authenticatedUser.setTenantDomain(OAuth2Util.getTenantDomain(resultSet.getInt(3)));
                    return authenticatedUser;
                } else {
                    throw new CibaCoreException("No record found for authenticatedUser of TokenRequest.");
                }
            } catch (IdentityOAuth2Exception e) {
                throw new CibaCoreException("Error occurred in obtaining authenticatedUser of TokenRequest", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in obtaining authenticatedUser of TokenRequest", e);
        }
    }

    @Override
    public void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.STORE_CIBA_AUTH_CODE)) {

                prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeKey());
                prepStmt.setString(2, cibaAuthCodeDO.getAuthReqID());
                prepStmt.setString(3, cibaAuthCodeDO.getConsumerAppKey());
                prepStmt.setTimestamp(4, cibaAuthCodeDO.getIssuedTime(), Calendar
                        .getInstance(TimeZone.getTimeZone(CibaConstants.UTC)));
                prepStmt.setTimestamp(5, cibaAuthCodeDO.getLastPolledTime(),
                        Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)));
                prepStmt.setLong(6, cibaAuthCodeDO.getInterval());
                prepStmt.setLong(7, cibaAuthCodeDO.getExpiresIn());
                prepStmt.setString(8, cibaAuthCodeDO.getAuthenticationStatus().toString());
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted cibaAuthCodeDO for unique CibaAuthCodeKey : " +
                            cibaAuthCodeDO.getCibaAuthCodeKey());
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred while persisting cibaAuthCodeDO.", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred while persisting cibaAuthCodeDO.", e);
        }
    }

    @Override
    public CibaAuthCodeDO getCibaAuthCodeWithAuthReqID(String authReqID) throws CibaCoreException {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_AUTH_CODE_FROM_CIBA_AUTH_REQ_ID)) {

                prepStmt.setString(1, authReqID);
                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    cibaAuthCodeDO.setCibaAuthCodeKey(resultSet.getString(1));
                    cibaAuthCodeDO.setAuthReqID(resultSet.getString(2));
                    cibaAuthCodeDO.setConsumerAppKey(resultSet.getString(3));
                    cibaAuthCodeDO.setLastPolledTime(
                            resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC))));
                    cibaAuthCodeDO.setInterval(resultSet.getLong(5));
                    cibaAuthCodeDO.setExpiresIn(resultSet.getLong(6));
                    cibaAuthCodeDO.setAuthenticationStatus(AuthReqStatus.valueOf(resultSet.getString(7)));
                    cibaAuthCodeDO.setIssuedTime(
                            resultSet.getTimestamp(8, Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC))));
                }

                if (log.isDebugEnabled()) {
                    log.debug("Successfully obtained cibaAuthCode for unique CibaAuthCodeKey : " +
                            authReqID);
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error in obtaining cibaAuthCode.", e);
        }
        return cibaAuthCodeDO;
    }

    @Override
    public void storeScope(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.STORE_SCOPES)) {

                for (String singleScopeValue : cibaAuthCodeDO.getScope()) {
                    prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeKey());
                    prepStmt.setString(2, singleScopeValue);
                    prepStmt.execute();
                    IdentityDatabaseUtil.commitTransaction(connection);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error in persisting scopes.", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error in persisting scopes.", e);
        }
    }

    @Override
    public String[] getScope(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_SCOPE)) {

                ArrayList<String> scopeArrayList = new ArrayList<>();
                prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeKey());
                ResultSet resultSet = prepStmt.executeQuery();
                while (resultSet.next()) {
                    scopeArrayList.add(resultSet.getString(1));
                }
                return scopeArrayList.toArray(new String[scopeArrayList.size()]);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error in retrieving scopes.", e);
        }
    }

    @Override
    public void updateStatusWithAuthReqID(String authReqID, Enum authenticationStatus) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS_WITH_AUTH_REQ_ID)) {

                prepStmt.setString(1, authenticationStatus.toString());
                prepStmt.setString(2, authReqID);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authentication status: " + authenticationStatus +
                            " identified by auth_req_id: " + authReqID);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CibaCoreException("Error occurred in persisting authentication status.", e);
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in persisting authentication status.", e);
        }
    }

    private int getIdpID(String idpName) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.GET_IDP_ID_FROM_IDP_NAME)) {

                prepStmt.setString(1, idpName);
                prepStmt.execute();
                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    return resultSet.getInt(1);
                } else {
                    throw new CibaCoreException("Record not found.");
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException("Error occurred in obtaining IDP ID.", e);
        }
    }
}
