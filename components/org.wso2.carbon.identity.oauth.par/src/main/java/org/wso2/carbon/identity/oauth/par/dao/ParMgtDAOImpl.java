/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.par.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * Implementation of abstract DAO layer.
 */
public class ParMgtDAOImpl implements ParMgtDAO {

    private static final Log log = LogFactory.getLog(ParMgtDAOImpl.class);

    @Override
    public void persistParRequestData(String reqUUID, String clientId, long reqMadeAt) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST)) {

                prepStmt.setString(1, reqUUID);
                prepStmt.setString(2, clientId);
                prepStmt.setLong(3, reqMadeAt);
                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                        " uuid: " + reqUUID, e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                    " uuid: " + reqUUID, e);
        }
    }

    @Override
    public void persistParRequestParams(String reqUUID, String paramKey, String paramValue) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST_PARAMS)) {

                prepStmt.setString(1, reqUUID);
                prepStmt.setString(2, paramKey);
                prepStmt.setString(3, paramValue);
                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                        " uuid: " + reqUUID, e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                    " uuid: " + reqUUID, e);
        }
    }

    @Override
    public void persistRequestObject(String reqUUID, String requestObject) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST_OBJECT)) {

                prepStmt.setString(1, reqUUID);
                prepStmt.setString(2, requestObject);
                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting request parameter of the successful PAR " +
                        "request with uuid: " + reqUUID, e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                    " uuid: " + reqUUID, e);
        }
    }

    @Override
    public String getParClientId(String reqUUID) throws ParClientException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_PAR_CLIENT_ID)) {

            prepStmt.setString(1, reqUUID);

            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained client_id of RequestURI with UUID: " + reqUUID);
                    }

                    return resultSet.getString(1);

                } else {
                    // Return an empty optional if the UUID is not found in the database
                    if (log.isDebugEnabled()) {
                        log.debug("PAR request with UUID " + reqUUID + " does not exist");
                    }
                    throw new ParClientException("Error occurred while retrieving client_id from the database.",
                            OAuth2ErrorCodes.INVALID_REQUEST);
                }
            } catch (SQLException e) {
                throw new ParClientException("Error occurred while retrieving client_id from the database.",
                        OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (SQLException e) {
            throw new ParClientException("Error occurred while retrieving client_id from the database.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    @Override
    public HashMap<String, String> getParParamMap(String reqUUID) throws ParClientException {

        HashMap<String, String> paramMap = new HashMap<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_PAR_PARAMS)) {

            prepStmt.setString(1, reqUUID);

            try (ResultSet resultSet = prepStmt.executeQuery()) {
                while (resultSet.next()) {
                    String key = resultSet.getString("PARAM_KEY");
                    String value = resultSet.getString("PARAM_VALUE");
                    paramMap.put(key, value);
                }

                return paramMap;

            } catch (SQLException e) {
                throw new ParClientException("Error occurred while retrieving parameters from the database.",
                        OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (SQLException e) {
            throw new ParClientException("Error occurred while retrieving parameters from the database.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    @Override
    public String getRequestObject(String reqUUID) throws ParClientException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_PAR_CLIENT_ID)) {

            prepStmt.setString(1, reqUUID);

            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained client_id of RequestURI with UUID: " + reqUUID);
                    }

                    return resultSet.getString(1);

                } else {
                    // Return an empty optional if the UUID is not found in the database
                    if (log.isDebugEnabled()) {
                        log.debug("PAR request with UUID " + reqUUID + " does not contain request parameter");
                    }
                    return null;
                }
            } catch (SQLException e) {
                throw new ParClientException("Error occurred while retrieving request param from the database.",
                        OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (SQLException e) {
            throw new ParClientException("Error occurred while retrieving request param from the database.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    @Override
    public long getExpiresIn(String reqUUID) throws ParClientException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_REQUEST_EXPIRES_IN)) {

            prepStmt.setString(1, reqUUID);

            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained expiryTime of RequestURI with UUID: " + reqUUID);
                    }

                    return resultSet.getLong(1);

                } else {
                    // Return an empty optional if the UUID is not found in the database
                    if (log.isDebugEnabled()) {
                        log.debug("PAR request with UUID " + reqUUID + " does not exist");
                    }
                    throw new ParClientException("Request URI does not exist",
                            OAuth2ErrorCodes.INVALID_REQUEST);
                }
            } catch (SQLException e) {
                throw new ParClientException("Error occurred while retrieving expiryTime from the database.",
                        OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (SQLException e) {
            throw new ParClientException("Error occurred while retrieving expiryTime from the database.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }
}
