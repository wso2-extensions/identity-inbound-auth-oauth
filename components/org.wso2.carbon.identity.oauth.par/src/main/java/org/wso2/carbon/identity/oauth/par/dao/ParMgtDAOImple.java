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
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParDataRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * Implementation of abstract DAO layer.
 */
public class ParMgtDAOImple implements ParMgtDAO {

    private static final Log log = LogFactory.getLog(ParMgtDAOImple.class);

    @Override
    public void persistParRequest(String reqUUID, String parameters, long reqMadeAt) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)){

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST)) {

                prepStmt.setString(1, reqUUID.substring(reqUUID.length() - 36));
                prepStmt.setString(2, parameters);
                prepStmt.setLong(3, reqMadeAt);
                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful authentication identified by" +
                        " authCodeKey: " + parameters, e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful authentication identified by " +
                    "authCodeKey: " + parameters, e);
        }
    }

    @Override
    public ParDataRecord getParRequestRecord(String reqUUID) throws ParCoreException {

        try(Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.ParSQLQueries.RETRIEVE_PAR_REQUEST_DATA)) {

                prepStmt.setString(1, reqUUID);
                try (ResultSet resultSet = prepStmt.executeQuery()){
                    if (resultSet.next()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully obtained PAR request of RequestURI  with " +
                                    "UUID : " + reqUUID);
                        }

                        ObjectMapper objectMapper = new ObjectMapper();
                        String jsonString = resultSet.getString(1);

                        HashMap<String, String> params;
                        params = objectMapper.readValue(jsonString, HashMap.class);

                        Long requestMadeAt = Long.valueOf(resultSet.getString(2));
                        ParDataRecord record = new ParDataRecord(params, requestMadeAt);
                        return record;
                    } else {
                        throw new ParCoreException(
                                "No record found for ParRequestData of requestURI identified by " +
                                        "UUID: " + reqUUID);
                    }
                } catch (JsonMappingException e) {
                    throw new RuntimeException(e);
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }

            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in obtaining request data relevant to uuid: " + reqUUID);
        }
    }

}
