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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.device.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

/**
 * This class contains override methods of DeviceFlowDAO.
 */
public class DeviceFlowDAOImpl implements DeviceFlowDAO {

    private static final Log log = LogFactory.getLog(DeviceFlowDAOImpl.class);

    @Override
    public void insertDeviceFlowParameters(String deviceCode, String userCode, String consumerKey, Long expiresIn,
                                           int interval, String scopes) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Persisting device_code: " + deviceCode + " for client: " + consumerKey);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            String codeId = UUID.randomUUID().toString();
            storeIntoDeviceFlow(codeId, deviceCode, userCode, consumerKey, expiresIn, interval, connection);
            storeIntoScopes(codeId, deviceCode, scopes, connection);
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when storing the device flow parameters for consumer_key: " +
                    consumerKey, e);
        }
    }

    @Override
    public String getClientIdByUserCode(String userCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting client_id for user_code: " + userCode);
        }
        String clientId = null;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_CONSUMER_KEY_FOR_USER_CODE)) {
                ResultSet resultSet;
                prepStmt.setString(1, userCode);
                resultSet = prepStmt.executeQuery();

                while (resultSet.next()) {
                    clientId = resultSet.getString(1);
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting client id for user_code: " + userCode, e);
        }
        return clientId;
    }

    @Override
    public void setAuthenticationStatus(String userCode, String status) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Set authentication status: " + status + " for user_code: " + userCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.SET_AUTHENTICATION_STATUS)) {
                prepStmt.setString(1, status);
                prepStmt.setString(2, userCode);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error when setting user has authenticated for user_code: " +
                                                  userCode, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting user has authenticated for user_code: " + userCode,
                                              e);
        }
    }

    @Override
    public DeviceFlowDO getAuthenticationDetails(String deviceCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting authentication details for device_code: " + deviceCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            ResultSet resultSet;
            AuthenticatedUser user;
            int tenantId = 0;
            String userName = null;
            boolean checked = false;
            String userDomain = null;
            String authenticatedIDP = null;
            DeviceFlowDO deviceFlowDO = new DeviceFlowDO();
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_AUTHENTICATION_STATUS)) {
                prepStmt.setString(1, deviceCode);
                resultSet = prepStmt.executeQuery();

                while (resultSet.next()) {
                    deviceFlowDO.setStatus(resultSet.getString(1));
                    deviceFlowDO.setLastPollTime(resultSet.getTimestamp(2,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))));
                    deviceFlowDO.setPollTime(resultSet.getLong(3));
                    deviceFlowDO.setExpiryTime(resultSet.getTimestamp(4,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))));
                    userName = resultSet.getString(5);
                    tenantId = resultSet.getInt(6);
                    userDomain = resultSet.getString(7);
                    authenticatedIDP = resultSet.getString(8);
                    checked = true;
                }
                if (checked) {
                    if (userName != null && tenantId != 0 && userDomain != null) {
                        String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                        user = OAuth2Util.createAuthenticatedUser(userName, userDomain, tenantDomain, authenticatedIDP);
                        deviceFlowDO.setAuthorizedUser(user);
                    }
                    return deviceFlowDO;
                } else {
                    deviceFlowDO.setStatus(Constants.NOT_EXIST);
                    return deviceFlowDO;
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting authentication status for device_code: " +
                    deviceCode, e);
        }
    }

    @Override
    public boolean checkClientIdExist(String clientId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Checking existence of client_id: " + clientId);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.CHECK_CLIENT_ID_EXISTS)) {
                ResultSet resultSet;
                prepStmt.setString(1, clientId);
                resultSet = prepStmt.executeQuery();
                while (resultSet.next()) {
                    String status = resultSet.getString(1);
                    if (status != null) {
                        return true;
                    }
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when check the existence of client_id: " +
                    clientId, e);
        }
        return false;
    }

    @Override
    public String getStatusForUserCode(String userCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting status for user_code: " + userCode);
        }
        String status = null;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_USER_CODE_STATUS)) {
                ResultSet resultSet;
                prepStmt.setString(1, userCode);
                resultSet = prepStmt.executeQuery();
                while (resultSet.next()) {
                    status = resultSet.getString(1);
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting status for user_code: " + userCode, e);
        }
        return status;
    }

    @Override
    public void setLastPollTime(String deviceCode, Timestamp newPollTime) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Setting last_poll_time: " + newPollTime + " for device_code: " + deviceCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.SET_LAST_POLL_TIME)) {
                prepStmt.setTimestamp(1, newPollTime, Calendar.getInstance(TimeZone
                        .getTimeZone(Constants.UTC)));
                prepStmt.setString(2, deviceCode);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error when setting last poll time for device_code: "
                        + deviceCode, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting last poll time for device_code: " + deviceCode, e);
        }
    }

    @Override
    public void setAuthzUserAndStatus(String userCode, String status, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Setting authorize user: " + authenticatedUser.getUserName() + " and status: " + status + " for" +
                    " user_code: " + userCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.SET_AUTHZ_USER_AND_STATUS)) {
                String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authenticatedUser);
                int tenantId = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
                prepStmt.setString(1, authenticatedUser.getUserName());
                prepStmt.setString(2, status);
                prepStmt.setInt(3, tenantId);
                prepStmt.setString(4, OAuth2Util.getUserStoreDomain(authenticatedUser));
                prepStmt.setString(5, authenticatedIDP);
                prepStmt.setInt(6, tenantId);
                prepStmt.setString(7, userCode);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error when setting authenticated user for user_code: " +
                        userCode, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting authenticated user for user_code: " +
                    userCode, e);
        }
    }

    @Override
    public void setDeviceCodeExpired(String deviceCode, String status) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Setting status as EXPIRED for device_code: " + deviceCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.SET_DEVICE_CODE_EXPIRED)) {
                prepStmt.setString(1, status);
                prepStmt.setString(2, deviceCode);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error when setting expired status for device_code: " +
                        deviceCode, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting expired status for device_code: " +
                    deviceCode, e);
        }
    }

    @Override
    public void setCallbackURI(String clientId, String callbackUri) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Setting callback_uri: " + callbackUri + " for client_id: " + clientId);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.SET_CALLBACK_URL)) {
                prepStmt.setString(1, callbackUri);
                prepStmt.setString(2, clientId);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error when setting expired callBackUri for consumer_key: " +
                        clientId, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting expired callBackUri for consumer_key: " +
                    clientId, e);
        }
    }

    @Override
    public String[] getScopesForUserCode(String userCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting scopes for user_code: " + userCode);
        }
        List<String> scopeSet = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_SCOPES_FOR_USER_CODE)) {
                ResultSet resultSet;
                prepStmt.setString(1, userCode);
                resultSet = prepStmt.executeQuery();
                while (resultSet.next()) {
                    scopeSet.add(resultSet.getString(1));
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting scopes for user_code: " + userCode, e);
        }
        return scopeSet.toArray(new String[scopeSet.size()]);
    }

    @Override
    public String[] getScopesForDeviceCode(String deviceCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting scopes for device_code: " + deviceCode);
        }
        List<String> scopeSet = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_SCOPES_FOR_DEVICE_CODE)) {
                ResultSet resultSet;
                prepStmt.setString(1, deviceCode);
                resultSet = prepStmt.executeQuery();
                while (resultSet.next()) {
                    scopeSet.add(resultSet.getString(1));
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting scopes for device_code: " + deviceCode, e);
        }
        return scopeSet.toArray(new String[scopeSet.size()]);
    }

    /**
     * Store into device flow database.
     *
     * @param codeId      Internal mapping UUID.
     * @param deviceCode  Code that is used to identify the device.
     * @param userCode    Code that is used to correlate user and device.
     * @param consumerKey Consumer key of the client application.
     * @param expiresIn   Expiry time.
     * @param interval    Interval between poll requests.
     * @param connection  Database connection.
     * @throws IdentityOAuth2Exception Error while storing parameters.
     */
    private void storeIntoDeviceFlow(String codeId, String deviceCode, String userCode, String consumerKey,
                                     long expiresIn, long interval, Connection connection) throws
            IdentityOAuth2Exception {

        try (PreparedStatement prepStmt =
                     connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.STORE_DEVICE_CODE)) {
            Date date = new Date();
            Timestamp timeCreated = new Timestamp(date.getTime());
            long timeExpired = timeCreated.getTime() + expiresIn;
            Timestamp expiredTime = new Timestamp(timeExpired);
            prepStmt.setString(1, codeId);
            prepStmt.setString(2, deviceCode);
            prepStmt.setString(3, userCode);
            prepStmt.setTimestamp(4, timeCreated, Calendar.getInstance(TimeZone
                    .getTimeZone(Constants.UTC)));
            prepStmt.setTimestamp(5, timeCreated, Calendar.getInstance(TimeZone
                    .getTimeZone(Constants.UTC)));
            prepStmt.setTimestamp(6, expiredTime, Calendar.getInstance(TimeZone
                    .getTimeZone(Constants.UTC)));
            prepStmt.setLong(7, interval);
            prepStmt.setString(8, Constants.PENDING);
            prepStmt.setString(9, consumerKey);
            prepStmt.execute();

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing the device flow parameters for consumer_key: " +
                    consumerKey, e);
        }
    }

    /**
     * Store into device flow scopes database.
     *
     * @param codeId     Internal mapping UUID.
     * @param deviceCode Code that is used to identify the device.
     * @param scope Scopes to be stored
     * @param connection Database connection.  @throws IdentityOAuth2Exception Error while storing scopes.
     */
    private void storeIntoScopes(String codeId, String deviceCode, String scope, Connection connection) throws
            IdentityOAuth2Exception {

        String[] scopeSet = OAuth2Util.buildScopeArray(scope);
        try (PreparedStatement prepStmt =
                     connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.STORE_DEVICE_FLOW_SCOPES)) {
            for (String scopes : scopeSet) {
                prepStmt.setString(1, codeId);
                prepStmt.setString(2, scopes);
                prepStmt.execute();
            }

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing scopes for device_code: " +
                    deviceCode, e);
        }
    }
}
