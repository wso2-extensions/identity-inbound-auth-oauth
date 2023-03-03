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

        ParDAOFactory.getInstance().getParAuthMgtDAO()
                .persistParRequest(reqUUID, parAuthRequest, reqMade);

//        --------------------------------------------------------------------------------------------------------------

//        Serializable obj = new ParDataRecord(parAuthRequest, reqMade);
//
//        try {
//            // INSERT a record
//            String sqlInsert = "insert into IDN_OAUTH_PAR values ('" + reqUUID.substring(reqUUID.length() - 36) + "', '" + parAuthRequest + "', '" + reqMade + "')";
//            int countInserted = getConnection().executeUpdate(sqlInsert);
//        } catch (SQLException e) {
//            e.printStackTrace();
//        }
    }


    public static ParDataRecord readRecord(String uuid) throws Exception {

        ParDataRecord record = ParDAOFactory.getInstance().getParAuthMgtDAO().getParRequestRecord(uuid);
        return record;

//        try {
//            String strSelect = "select AUTH_REQ_OBJ, REQ_MADE from IDN_OAUTH_PAR where REQ_URI_UUID = '" + reqUUID.substring(reqUUID.length() - 36) + "'";
//            ResultSet rset = getConnection().executeQuery(strSelect);
//
//            ParDataRecord record = new ParDataRecord((OAuthAuthzRequest) rset.getObject("AUTH_REQ_OBJ"), (Long) rset.getObject("REQ_MADE"));
//            return record;
//        } catch (SQLException e) {
//            e.printStackTrace();
//        }
//
//        return null;
    }

//    private ParDataRecord parDataRecord;
//
//    static final String WRITE_OBJECT_SQL =
//            "INSERT INTO IDN_OAUTH_PAR(REQ_URI_UUID, AUTH_REQ_OBJ, REQ_MADE) VALUES (?, ?, ?)";
//
//    static final String READ_OBJECT_SQL = "SELECT AUTH_REQ_OBJ FROM IDN_OAUTH_PAR WHERE id = ?";

//    public void buildParDataRecord(String reqUriUUID, OAuthAuthzRequest parAuthRequest, long reqMade) {
//
//        this.parDataRecord = new ParDataRecord(reqUriUUID, parAuthRequest, reqMade);
//    }

//    public static Connection getConnection() throws Exception {
//
//        String driver = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
//        String url = "jdbc:sqlserver://localhost:1433;databaseName=wso2isdb";
//        String username = "sa";
//        String password = "wso2carbon12345@";
//        Class.forName(driver);
//        Connection conn = DriverManager.getConnection(url, username, password);
//        return conn;
//    }
//
//    public static void writeObject(Connection conn, String reqUUID, OAuthAuthzRequest parAuthRequest) throws Exception {
//
//        String className = parAuthRequest.getClass().getName();
//        PreparedStatement pstmt = conn.prepareStatement(WRITE_OBJECT_SQL);
//
//        pstmt.setString(1, reqUUID);
//         pstmt.setObject(2, parAuthRequest);
//        pstmt.executeUpdate();
//
//        pstmt.close();
//    }

}
