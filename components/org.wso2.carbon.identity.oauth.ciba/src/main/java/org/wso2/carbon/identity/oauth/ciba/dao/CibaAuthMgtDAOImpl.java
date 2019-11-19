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
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Implementation of abstract DAO layer.
 */
public class CibaAuthMgtDAOImpl implements CibaAuthMgtDAO {

    private static final Log log = LogFactory.getLog(CibaAuthMgtDAOImpl.class);

    private CibaAuthMgtDAOImpl() {

    }

    private static CibaAuthMgtDAOImpl cibaAuthMgtDAOImplImplInstance = new CibaAuthMgtDAOImpl();

    static CibaAuthMgtDAOImpl getInstance() {

        if (cibaAuthMgtDAOImplImplInstance == null) {

            synchronized (CibaAuthMgtDAOImpl.class) {

                if (cibaAuthMgtDAOImplImplInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthMgtDAOImplImplInstance = new CibaAuthMgtDAOImpl();
                }
            }
        }
        return cibaAuthMgtDAOImplImplInstance;

    }

    /**
     * Persists the status of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey       Identifier for CibaAuthCodeDOKey.
     * @param cibaAuthentcationStatus Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistStatus(String cibaAuthCodeDOKey, String cibaAuthentcationStatus) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS)) {

                prepStmt.setString(1, cibaAuthentcationStatus);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authentication_status identified by AuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in persisting the authentication_status identified by AuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR,
                    "SQL exception in persisting authenticated_status. " + e.getMessage());
        }
    }

    /**
     * Persists the authenticated_user of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey     Identifier for CibaAuthCode.
     * @param cibaAuthenticatedUser Authenticated_user of the relevant CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistUser(String cibaAuthCodeDOKey, String cibaAuthenticatedUser) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    UPDATE_CIBA_AUTHENTICATED_USER)) {
                prepStmt.setString(1, cibaAuthenticatedUser);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authenticated_user identified by AuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in persisting the authenticated_user identified by AuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR,
                    "SQL exception in persisting authenticated_user." + e.getMessage());
        }
    }

    /**
     * Checks whether hash of CibaAuthCode exists.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqID.
     * @return boolean Returns whether given HashedAuthReqId present or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public boolean isHashedAuthReqIDExists(String hashedCibaAuthReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    CHECK_IF_AUTH_REQ_ID_HASH_EXISTS)) {
                prepStmt.setString(1, hashedCibaAuthReqId);

                ResultSet resultSet = prepStmt.executeQuery();

                int count;

                while (resultSet.next()) {
                    count = (resultSet.getInt(1));

                    if (count >= 1) {
                        //do nothing
                        prepStmt.close();

                        if (log.isDebugEnabled()) {
                            log.debug("Successfully checked whether provided hashedAuthReqId : " + hashedCibaAuthReqId +
                                    "exists.");
                            log.debug("Provided hashedAuthReqId exists.It is from a valid auth_req_id.");
                        }
                        return true;

                    } else {
                        prepStmt.close();
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully checked whether provided hashedAuthReqId : " + hashedCibaAuthReqId +
                                    "exists.");
                            log.debug("Provided hashedAuthReqId does not exist. hashedAuthReqId is not from valid " +
                                    "auth_req_id.");
                        }
                        return false;
                    }
                }

                return false;
            }
        } catch (SQLException e) {

            if (log.isDebugEnabled()) {
                log.debug("Unsuccessful in checking whether provided hashedAuthReqId : " + hashedCibaAuthReqId +
                        "exists.");
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Returns CibaAuthCodeDOkey for the hash of CibaAuthReqId.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqId.
     * @return String Returns CibaAuthCodeDOKey.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getCibaAuthCodeDOKey(String hashedCibaAuthReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_CIBA_AUTH_CODE_DO_KEY_BY_CIBA_AUTH_REQ_ID_HASH)) {
                prepStmt.setString(1, hashedCibaAuthReqId);

                ResultSet resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning CibaAuthCodeDOKey : " + resultSet.getString(1) + "for the " +
                                "hashedCibaAuthReqId : " + hashedCibaAuthReqId);
                    }
                    return resultSet.getString(1);
                } else {

                    if (log.isDebugEnabled()) {
                        log.debug("Could not find CibaAuthCodeDOKey for the hashedCibaAuthReqId : " +
                                hashedCibaAuthReqId);
                    }
                    return null;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occured when finding CibaAuthCodeDOKey for the hashedCibaAuthReqId : " +
                        hashedCibaAuthReqId);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * Returns the lastPolledTime of tokenRequest with CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCodeDO.
     * @return long Returns lastPolledTime.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public long getLastPolledTime(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_LAST_POLLED_TIME)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {

                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning lastPolledTime of TokenRequest : " + resultSet.getLong(1) +
                                "for the " + "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return resultSet.getLong(1);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for lastPolledTime of TokenRequest : " + resultSet.getLong(1) +
                                "for the " + "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return 0;
                }
            }

        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in retrieving lastPolledTime of TokenRequest for  the " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Returns the pollingInterval of tokenRequest with CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthReqId.
     * @return long Returns pollingInterval of tokenRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public long getPollingInterval(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_POLLING_INTERVAL)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet rs = prepStmt.executeQuery();
                if (rs.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning pollingInterval of TokenRequest : " + rs.getLong(1) +
                                "for the " + "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return rs.getLong(1);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for pollingInterval of TokenRequest with cibaAuthCodeDOKey : " +
                                cibaAuthCodeDOKey);
                    }
                    return 0;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in retrieving pollingInterval of TokenRequest for the " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * Updates the last polled time of tokenRequest with CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCodeDO.
     * @param currentTime       CurrentTime in milliseconds.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void updateLastPollingTime(String cibaAuthCodeDOKey, long currentTime)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME)) {
                prepStmt.setLong(1, currentTime);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated lastPollingTime of TokenRequest  with cibaAuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating lastPollingTime of TokenRequest  with cibaAuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Updates the polling Interval of tokenRequest with cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode.
     * @param newInterval       Updated polling frequency.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void updatePollingInterval(String cibaAuthCodeDOKey, long newInterval)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL)) {
                prepStmt.setLong(1, newInterval);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated pollingInterval of TokenRequest  with cibaAuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating pollingInterval of TokenRequest  with cibaAuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Returns authenticationStatus of authenticationRequest with specific cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCodeDO.
     * @return String Returns AuthenticationStatus.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getAuthenticationStatus(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_AUTHENTICATION_STATUS)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {

                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained authenticationStatus of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return resultSet.getString(1);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for authenticationStatus of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return null;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in obtaining authenticationStatus of TokenRequest  with " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Returns the authenticated user of authenticationRequest for cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode
     * @return Returns AuthenticatedUser.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getAuthenticatedUser(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {

            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained authenticatedUser of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return resultSet.getString(1);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for authenticatedUser of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return null;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in obtaining authenticatedUser of TokenRequest  with " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Persists the CibaAuthCodeDO.
     *
     * @param cibaAuthCodeDO Data object that accumulates  CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.STORE_CIBA_AUTH_REQ_CODE)) {
                prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeDOKey());
                prepStmt.setString(2, cibaAuthCodeDO.getHashedCibaAuthReqId());
                prepStmt.setString(3, cibaAuthCodeDO.getAuthenticationStatus());
                prepStmt.setLong(4, cibaAuthCodeDO.getLastPolledTime());
                prepStmt.setLong(5, cibaAuthCodeDO.getInterval());
                prepStmt.setLong(6, cibaAuthCodeDO.getExpiryTime());
                prepStmt.setString(7, cibaAuthCodeDO.getBindingMessage());
                prepStmt.setString(8, cibaAuthCodeDO.getTransactionContext());
                prepStmt.setString(9, cibaAuthCodeDO.getScope());
                prepStmt.execute();
                connection.commit();

                if (log.isDebugEnabled()) {
                    log.debug(
                            "Successfully persisted cibaAuthCodeDO for unique cibaAuthCodeDOKey : " +
                                    cibaAuthCodeDO.getCibaAuthCodeDOKey());
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Error occurred while persisting cibaAuthCodeDO for unique cibaAuthCodeDOKey : " +
                                cibaAuthCodeDO.getCibaAuthCodeDOKey());
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Returns CibaAuthCodeDO identified by unique cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public CibaAuthCodeDO getCibaAuthCodeDO(String cibaAuthCodeDOKey) throws CibaCoreException {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_AUTH_CODE_DO_FROM_CIBA_AUTH_CODE_DO_KEY)) {

                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    cibaAuthCodeDO.setCibaAuthCodeDOKey(resultSet.getString(1));
                    cibaAuthCodeDO.setHashedCibaAuthReqId(resultSet.getString(2));
                    cibaAuthCodeDO.setAuthenticationStatus(resultSet.getString(3));
                    cibaAuthCodeDO.setLastPolledTime(resultSet.getLong(4));
                    cibaAuthCodeDO.setInterval(resultSet.getLong(5));
                    cibaAuthCodeDO.setAuthenticatedUser(resultSet.getString(6));
                    cibaAuthCodeDO.setExpiryTime(resultSet.getLong(7));
                    cibaAuthCodeDO.setBindingMessage(resultSet.getString(8));
                    cibaAuthCodeDO.setTransactionContext(resultSet.getString(9));
                    cibaAuthCodeDO.setScope(resultSet.getString(10));

                }

                if (log.isDebugEnabled()) {
                    log.debug("Successfully obtained ciba AuthCodeDO for unique cibaAuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Error in obtaining cibaAuthCodeDO for unique cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
        return cibaAuthCodeDO;
    }

}
