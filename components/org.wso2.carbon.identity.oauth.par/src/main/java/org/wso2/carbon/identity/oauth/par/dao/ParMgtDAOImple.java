package org.wso2.carbon.identity.oauth.par.dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.core.jackson.Log4jJsonObjectMapper;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.graalvm.compiler.lir.alloc.lsra.LinearScan;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParDataRecord;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.awt.image.RescaleOp;
import java.io.Serializable;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class ParMgtDAOImple implements ParMgtDAO{

    private static final Log log = LogFactory.getLog(ParMgtDAOImple.class);

    @Override
    public void persistParRequest(String reqUUID, String oauthRequest, long reqMadeAt) throws ParCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)){

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    ParSQLQueries.STORE_PAR_REQUEST)) {

                List<Object> testObject = new ArrayList<>();
                testObject.add("String");
                testObject.add(new Integer(1234));

                prepStmt.setString(1, reqUUID.substring(reqUUID.length() - 36));
                prepStmt.setString(2, oauthRequest);
                prepStmt.setLong(3, reqMadeAt);
                prepStmt.execute();
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new ParCoreException("Error occurred in persisting the successful authentication identified by" +
                        " authCodeKey: " + oauthRequest, e);
            }
        } catch (SQLException e) {
            throw new ParCoreException("Error occurred in persisting the successful authentication identified by " +
                    "authCodeKey: " + oauthRequest, e);
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
                        OAuthAuthzRequest parAuthRequest = objectMapper.readValue(jsonString, OAuthAuthzRequest.class);

                        Long requestMadeAt = Long.valueOf(resultSet.getString(2));
                        ParDataRecord record = new ParDataRecord(parAuthRequest, requestMadeAt);
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
