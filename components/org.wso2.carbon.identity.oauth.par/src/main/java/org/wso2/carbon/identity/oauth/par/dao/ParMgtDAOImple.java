package org.wso2.carbon.identity.oauth.par.dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.minidev.json.JSONObject;
import org.apache.catalina.util.ParameterMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParDataRecord;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;

import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class ParMgtDAOImple implements ParMgtDAO{

    private static final Log log = LogFactory.getLog(ParMgtDAOImple.class);

    @Override
    public void persistParRequest(String reqUUID, String paramMap, long reqMadeAt) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)){

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST)) {

                prepStmt.setString(1, reqUUID.substring(reqUUID.length() - 36));
                prepStmt.setString(2, paramMap);
                prepStmt.setLong(3, reqMadeAt);
                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful authentication identified by" +
                        " authCodeKey: " + paramMap, e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful authentication identified by " +
                    "authCodeKey: " + paramMap, e);
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
            throw new ParCoreException("Error occurred in obtaining authenticatedUser of TokenRequest identified by " +
                    "authCodeKey: " + e);
        }
    }

}
