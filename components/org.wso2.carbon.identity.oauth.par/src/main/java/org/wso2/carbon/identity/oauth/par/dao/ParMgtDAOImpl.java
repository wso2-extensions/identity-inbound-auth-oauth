/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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
import org.wso2.carbon.identity.oauth.par.common.SQLQueries;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

/**
 * Implementation of abstract DAO layer.
 */
public class ParMgtDAOImpl implements ParMgtDAO {

    private static final Log log = LogFactory.getLog(ParMgtDAOImpl.class);
    ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void persistParRequest(String reqUriUUID, String clientId, long scheduledExpiryTime,
                                  Map<String, String> parameters) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST)) {

                prepStmt.setString(1, reqUriUUID);
                prepStmt.setString(2, clientId);
                prepStmt.setLong(3, scheduledExpiryTime);
                prepStmt.setString(4, getJsonParams(parameters));

                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                        " uuid: " + reqUriUUID);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful PAR request with" +
                    " uuid: " + reqUriUUID);
        }
    }

    @Override
    public ParRequestDO getParRequest(String uuid) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.RETRIEVE_PAR_REQUEST)) {

            prepStmt.setString(1, uuid);

            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained client_id of RequestURI with UUID: " + uuid);
                    }
                    String jsonParams = resultSet.getString("JSON_PARAMS");
                    long scheduledExpiry = resultSet.getLong("SCHEDULED_EXPIRY");
                    String clientId = resultSet.getString("CLIENT_ID");

                    return new ParRequestDO(getParams(jsonParams), scheduledExpiry, clientId);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("PAR request with UUID " + uuid + " does not exist");
                    }
                    throw new ParCoreException("uuid does not exist");
                }
            } catch (SQLException e) {
                throw new ParCoreException("Error occurred while retrieving client_id from the database.");
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred while retrieving client_id from the database.");
        }
    }

    @Override
    public void removeParRequestData(String reqUUID) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries
                     .ParSQLQueries.REMOVE_IDN_OAUTH_PAR_REQUEST)) {
            prepStmt.setString(1, reqUUID);
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred while removing PAR request from Database");
        }
    }

    private String getJsonParams(Map<String, String> params) throws ParCoreException {

        try {
            return objectMapper.writeValueAsString(params);
        } catch (JsonProcessingException e) {
            throw new ParCoreException("Error occurred while serializing parameter map to JSON");
        }
    }

    private Map<String, String> getParams(String jsonParams) throws ParCoreException {

        try {
            return objectMapper.readValue(jsonParams, new TypeReference<Map<String, String>>() { });
        } catch (JsonProcessingException e) {
            throw new ParCoreException("Error occurred while serializing JSON string map to Map");
        }
    }
}
