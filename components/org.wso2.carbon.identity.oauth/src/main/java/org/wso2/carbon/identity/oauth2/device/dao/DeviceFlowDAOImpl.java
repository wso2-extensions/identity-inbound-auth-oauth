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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.codegenerator.GenerateKeys;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.device.util.DeviceFlowUtil;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.TimeZone;
import java.util.UUID;

/**
 * This class contains override methods of DeviceFlowDAO.
 */
public class DeviceFlowDAOImpl implements DeviceFlowDAO {

    private static final Log log = LogFactory.getLog(DeviceFlowDAOImpl.class);

    @Override
    public String insertDeviceFlowParametersWithQuantifier(String deviceCode, String userCode, long quantifier,
        String consumerKey, String scopes) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Persisting device code: " + deviceCode + " for client: " + consumerKey);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            String codeId = UUID.randomUUID().toString();
            int keyLength = OAuthServerConfiguration.getInstance().getDeviceCodeKeyLength();
            int pollingInterval = OAuthServerConfiguration.getInstance().getDeviceCodePollingInterval();
            String uniqueUserCode =
                    storeIntoDeviceFlow(codeId, deviceCode, userCode, quantifier, consumerKey, connection, 0, keyLength,
                            pollingInterval);
            storeIntoScopes(codeId, deviceCode, scopes, connection);
            IdentityDatabaseUtil.commitTransaction(connection);
            return uniqueUserCode;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when storing the device flow parameters for consumer_key: " +
                    consumerKey, e);
        }
    }

    @Override
    @Deprecated
    public void insertDeviceFlowParameters(String deviceCode, String userCode, String consumerKey, Long expiresIn,
                                           int interval, String scopes) throws IdentityOAuth2Exception {

        insertDeviceFlowParametersWithQuantifier(deviceCode, userCode, GenerateKeys.getCurrentQuantifier(), consumerKey,
                scopes);
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
    public void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Set authentication status: " + Constants.USED + " for user_code: " + userCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.SET_AUTHENTICATION_STATUS)) {
                prepStmt.setString(1, Constants.USED);
                prepStmt.setString(2, userCode);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error when setting the authentication status for the user_code: " +
                        DigestUtils.sha256Hex(userCode), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting the authentication status for the user_code: " +
                    DigestUtils.sha256Hex(userCode), e);
        }
    }

    @Override
    @Deprecated
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
                throw new IdentityOAuth2Exception("Error when setting the authentication status for the user_code: " +
                        userCode, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when setting the authentication status for the user_code: " +
                    userCode, e);
        }
    }

    @Override
    public DeviceFlowDO getAuthenticationDetails(String deviceCode, String clientId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting authentication details for device_code: " + deviceCode);
        }
        AuthenticatedUser user;
        int tenantId = 0;
        String userName = null;
        String userDomain = null;
        String authenticatedIDP = null;
        String subjectIdentifier = null;
        List<String> scopes = null;
        DeviceFlowDO deviceFlowDO = new DeviceFlowDO();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt =
                     connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_AUTHENTICATION_STATUS)) {
            prepStmt.setString(1, deviceCode);
            prepStmt.setString(2, clientId);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    deviceFlowDO.setStatus(resultSet.getString(1));
                    deviceFlowDO.setLastPollTime(resultSet.getTimestamp(2,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))));
                    deviceFlowDO.setPollTime(resultSet.getLong(3));
                    deviceFlowDO.setExpiryTime(resultSet.getTimestamp(4,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))));
                    userName = resultSet.getString(5);
                    tenantId = resultSet.getInt(6);
                    userDomain = resultSet.getString(7);
                    subjectIdentifier = resultSet.getString(8);
                    authenticatedIDP = resultSet.getString(9);
                    scopes = getScopesForCodeId(resultSet.getString(10), connection);

                    if (StringUtils.isBlank(subjectIdentifier)) {
                        int idpId = UserSessionStore.getInstance().getIdPId(authenticatedIDP, tenantId);
                        subjectIdentifier = UserSessionStore.getInstance().getUserId(userName, tenantId,
                                    userDomain, idpId);
                        log.info("Defaulting to unique userID as subject identifier as the subject identifier " +
                                "column value is empty in the table");
                    }

                    if (StringUtils.isNotBlank(userName) && tenantId != 0 && StringUtils.isNotBlank(userDomain)) {
                        String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                        user = OAuth2Util.createAuthenticatedUser(userName, userDomain, tenantDomain, authenticatedIDP);
                        ServiceProvider serviceProvider;
                        try {
                            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                    getServiceProviderByClientId(clientId, OAuthConstants.Scope.OAUTH2,
                                            tenantDomain);
                        } catch (IdentityApplicationManagementException e) {
                            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 " +
                                    "application data for client id " + clientId, e);
                        }
                        user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                        deviceFlowDO.setAuthorizedUser(user);
                        deviceFlowDO.setScopes(scopes);
                    }
                } else {
                    deviceFlowDO.setStatus(Constants.NOT_EXIST);
                }
                return deviceFlowDO;
            } catch (UserSessionException e) {
                throw new IdentityOAuth2Exception("Error occurred while retrieving subject identifier for device " +
                            "code: " + deviceCode, e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting authentication status for device_code: " +
                    deviceCode, e);
        }
    }

    @Override
    @Deprecated
    public DeviceFlowDO getAuthenticationDetails(String deviceCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting authentication details for device_code: " + deviceCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            ResultSet resultSet;
            AuthenticatedUser user;
            int tenantId = 0;
            String userName = null;
            boolean isMatchingDeviceCodeAndClientId = false; // Check for matching deviceCode and clientId.
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
                    authenticatedIDP = resultSet.getString(9);
                    isMatchingDeviceCodeAndClientId = true;
                }
                if (isMatchingDeviceCodeAndClientId) {
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
            log.debug("Setting authorize user: " + authenticatedUser.getLoggableUserId() + " and status: " + status
                    + " for user_code: " + userCode);
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
                prepStmt.setString(7, authenticatedUser.getAuthenticatedSubjectIdentifier());
                prepStmt.setString(8, userCode);
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
    public Optional<String> getDeviceCodeForUserCode(String userCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting device code for user_code: " + userCode);
        }
        String deviceCode = null;
        try (
                Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                PreparedStatement prepStmt = connection
                        .prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_DEVICE_CODE_FOR_USER_CODE)
        ) {
            prepStmt.setString(1, userCode);
            ResultSet resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                deviceCode = resultSet.getString(1);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting device code for user_code: " + userCode, e);
        }
        if (StringUtils.isBlank(deviceCode)) {
            return Optional.empty();
        }
        return Optional.of(deviceCode);
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
     * @param quantifier  Quantized time period user_code belongs.
     * @param consumerKey Consumer key of the client application.
     * @param retryAttempt No. of times user_code uniqueness checks.
     * @return Unique user_code.
     * @throws IdentityOAuth2Exception Error while storing parameters.
     */
    private String storeIntoDeviceFlow(String codeId, String deviceCode, String userCode, long quantifier,
                                       String consumerKey, Connection connection, int retryAttempt, int keyLength,
                                       int pollingInterval)
            throws IdentityOAuth2Exception, SQLException {

        if (retryAttempt < Constants.DEFAULT_DEVICE_TOKEN_PERSIST_RETRY_COUNT) {
            String tempUserCode;
            long currentQuantifier;
            long timeExpired;
            PreparedStatement prepStmt = null;
            ResultSet rs = null;
            try {
                if (isUserCodeAndQuantifierExists(userCode, quantifier, connection)) {
                    tempUserCode = GenerateKeys.getKey(keyLength);
                    currentQuantifier = GenerateKeys.getCurrentQuantifier();
                    return storeIntoDeviceFlow(codeId, deviceCode, tempUserCode, currentQuantifier, consumerKey,
                            connection, ++retryAttempt, keyLength, pollingInterval);
                }
                prepStmt = connection.prepareStatement(
                        SQLQueries.DeviceFlowDAOSQLQueries.STORE_DEVICE_CODE_WITH_QUANTIFIER);
                Date date = new Date();
                Timestamp timeCreated = new Timestamp(date.getTime());
                timeExpired = timeCreated.getTime() + (DeviceFlowUtil.getConfiguredExpiryTime() * 1000);
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
                prepStmt.setLong(7, pollingInterval);
                prepStmt.setString(8, Constants.PENDING);
                prepStmt.setLong(9, quantifier);
                prepStmt.setString(10, consumerKey);
                prepStmt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                // Handle constrain violation issue in JDBC drivers which does not throw
                // SQLIntegrityConstraintViolationException.
                if (e instanceof SQLIntegrityConstraintViolationException ||
                        StringUtils.containsIgnoreCase(e.getMessage(), Constants.USERCODE_QUANTIFIER_CONSTRAINT)) {
                    tempUserCode = GenerateKeys.getKey(keyLength);
                    currentQuantifier = GenerateKeys.getCurrentQuantifier();
                    return storeIntoDeviceFlow(codeId, deviceCode, tempUserCode, currentQuantifier, consumerKey,
                            connection, ++retryAttempt, keyLength, pollingInterval);
                }
                throw new IdentityOAuth2Exception("Error when storing the device flow parameters for consumer_key: "
                        + consumerKey, e);
            } finally {
                if (prepStmt != null && rs != null) {
                    prepStmt.close();
                    rs.close();
                }
            }
            return userCode;
        }
        throw new IdentityOAuth2Exception("user_code for consumer_key: " + consumerKey + " already exists.");
    }

    /**
     * Check the existence of userCode and quantifier.
     *
     * @param userCode   Code that is used to correlate user and device.
     * @param quantifier Quantized time period user_code belongs.
     * @throws IdentityOAuth2Exception Error while comparing parameters.
     */
    private boolean isUserCodeAndQuantifierExists(String userCode, long quantifier, Connection connection)
            throws IdentityOAuth2Exception {

        try {
            ResultSet resultSet;
            PreparedStatement prepStmt = connection.prepareStatement(
                    SQLQueries.DeviceFlowDAOSQLQueries.CHECK_UNIQUE_USER_CODE_AND_QUANTIFIER);
            prepStmt.setString(1, userCode);
            prepStmt.setLong(2, quantifier);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getBoolean(1);
            }
            return false;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when checking the existence for user_code: " +
                    DigestUtils.sha256Hex(userCode) + " and quantifier: " + quantifier, e);
        }
    }

    /**
     * Store into device flow scopes database.
     *
     * @param codeId     Internal mapping UUID.
     * @param deviceCode Code that is used to identify the device.
     * @param scope      Scopes to be stored
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
                prepStmt.addBatch();
            }
            prepStmt.executeBatch();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing scopes for device_code: " +
                    deviceCode, e);
        }
    }

    @Override
    public DeviceFlowDO getDetailsForUserCode(String userCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting authentication details for user_code: " + userCode);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            ResultSet resultSet;
            DeviceFlowDO deviceFlowDO = null;
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_AUTHENTICATION_DETAILS)) {
                prepStmt.setString(1, userCode);
                resultSet = prepStmt.executeQuery();

                while (resultSet.next()) {
                    deviceFlowDO = new DeviceFlowDO();
                    deviceFlowDO.setStatus(resultSet.getString(1));
                    deviceFlowDO.setExpiryTime(resultSet.getTimestamp(2,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))));
                    deviceFlowDO.setDeviceCode(resultSet.getString(3));
                    deviceFlowDO.setScopes(getScopesForCodeId(resultSet.getString(4), connection));
                    deviceFlowDO.setConsumerKey(resultSet.getString(5));
                }
            }
            return deviceFlowDO;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting authentication details for user_code(hashed): " +
                    DigestUtils.sha256Hex(userCode), e);
        }
    }

    private List<String> getScopesForCodeId(String codeId, Connection connection) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting scopes for codeId: " + codeId);
        }
        List<String> scopeSet = new ArrayList<>();
        try (PreparedStatement prepStmt =
                     connection.prepareStatement(SQLQueries.DeviceFlowDAOSQLQueries.GET_SCOPES_FOR_CODE_ID)) {
            ResultSet resultSet;
            prepStmt.setString(1, codeId);
            resultSet = prepStmt.executeQuery();
            while (resultSet.next()) {
                scopeSet.add(resultSet.getString(1));
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when getting scopes for codeId: " + codeId, e);
        }
        return scopeSet;
    }
}
