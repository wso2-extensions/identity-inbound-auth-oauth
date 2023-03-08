package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.model.ParDataRecord;

import java.io.Serializable;
import java.sql.*;

public class DataRecordWriter {


    public static Statement getConnection() throws Exception {

        try {
            String driver = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
            String url = "jdbc:sqlserver://localhost:1433;databaseName=wso2isdb";
            String username = "sa";
            String password = "wso2carbon12345@";
            Class.forName(driver);
            Connection conn = DriverManager.getConnection(url, username, password);

            // Step 2: Allocate a 'Statement' object in the Connection
            Statement stmt = conn.createStatement();
            return stmt;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void writeObject(String reqUUID, String parAuthRequest, long reqMade) throws Exception {

        ParDAOFactory.getInstance().getParAuthMgtDAO().persistParRequest(reqUUID, parAuthRequest, reqMade);
    }


    public static ParDataRecord readRecord(String uuid) throws Exception {

        ParDataRecord record = ParDAOFactory.getInstance().getParAuthMgtDAO().getParRequestRecord(uuid);
        return record;
    }
}
