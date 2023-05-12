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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    public void persistParRequest(String reqUUID, String clientId, long scheduledExpiryTime,
                                  HashMap<String, String> parameters) throws ParCoreException {

        ObjectMapper objectMapper = new ObjectMapper();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST)) {

                String jsonString = objectMapper.writeValueAsString(parameters);

                prepStmt.setString(1, reqUUID);
                prepStmt.setString(2, clientId);
                prepStmt.setLong(3, scheduledExpiryTime);
                prepStmt.setString(4, jsonString);

                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                        " uuid: " + reqUUID, e);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred converting PAR request with" +
                    " uuid: " + reqUUID + " to JSON", e);
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

        ObjectMapper objectMapper = new ObjectMapper();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_PAR_JSON_PARAMS)) {

            prepStmt.setString(1, reqUUID);

            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained client_id of RequestURI with UUID: " + reqUUID);
                    }

                    String jsonString = resultSet.getString(1);
                    return objectMapper.readValue(jsonString, new TypeReference<HashMap<String, String>>() {});

                } else {
                    // Return an empty optional if the UUID is not found in the database
                    if (log.isDebugEnabled()) {
                        log.debug("PAR request with UUID " + reqUUID + " does not contain request parameter");
                    }
                    return null;
                }
            } catch (SQLException | JsonProcessingException e) {
                throw new ParClientException("Error occurred while retrieving parameters from the database.",
                        OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (SQLException e) {
            throw new ParClientException("Error occurred while retrieving parameters from the database.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    @Override
    public long getScheduledExpiry(String reqUUID) throws ParClientException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_SCHEDULED_EXPIRY)) {

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
            throw new ParClientException("Error occurred while retrieving scheduled expiry time from the database.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    //TODO:
    @Override
    public void deleteParRequestData(String reqUUID) throws ParClientException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.DELETE_IDN_OAUTH_PAR_REQUEST)) {

            prepStmt.setString(1, reqUUID);

            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
            //System.out.println("Record deleted from DB!");

        } catch (SQLException e) {
            throw new ParClientException("Error occurred while deleting PAR request from Database",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }
}
