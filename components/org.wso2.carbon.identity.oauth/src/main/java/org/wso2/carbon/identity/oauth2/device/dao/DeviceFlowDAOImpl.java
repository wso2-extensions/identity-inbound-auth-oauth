package org.wso2.carbon.identity.oauth2.device.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.TimeZone;

public class DeviceFlowDAOImpl extends AbstractOAuthDAO implements DeviceFlowDAO {

    private static final Log log = LogFactory.getLog(DeviceFlowDAOImpl.class);

    private static final String IDN_OAUTH2_DEVICE_FLOW = "IDN_OAUTH2_DEVICE_FLOW";
    private String clientId;
    private String status;
    private String scope;

    @Override
    public void insertDeviceFlow(String deviceCode, String userCode, String consumerKey, String scope,
                                 Long expiresIn) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        Date date = new Date();

        try {
            String sql;
            sql = SQLQueries.DeviceFlowDAOSQLQueries.STORE_DEVICE_CODE;
            Timestamp timeCreated = new Timestamp(date.getTime());
            long timeExpired = timeCreated.getTime() + expiresIn;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, "1");
            prepStmt.setString(2, deviceCode);
            prepStmt.setString(3, userCode);
            prepStmt.setString(4, scope);
            prepStmt.setTimestamp(5, timeCreated, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            prepStmt.setTimestamp(6, timeCreated, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            prepStmt.setLong(7, timeExpired);
            prepStmt.setLong(8, 5000);
            prepStmt.setString(9, "PENDING");
            prepStmt.setString(10, null);
            prepStmt.setString(11, getPersistenceProcessor().getProcessedClientId(consumerKey));

            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
//            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing the device flow parameters for consumer key : " +
                    consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    @Override
    public String getClientIdByUSerCode(String userCode) throws IdentityOAuth2Exception {

//        if (log.isDebugEnabled()) {
//            log.debug("Retrieving authorization codes of user: " + authenticatedUser.toString());
//        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            String sqlQuery = SQLQueries.DeviceFlowDAOSQLQueries.GET_CONSUMER_KEY_FOR_USER_CODE;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, userCode);
            rs = ps.executeQuery();

            while (rs.next()) {
                clientId = getPersistenceProcessor().getPreprocessedClientId(rs.getString(1));
                log.info("client id is " + clientId);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return clientId;
    }

    @Override
    public void setUserAuthenticated(String userCode, String status) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            String sql;
            sql = SQLQueries.DeviceFlowDAOSQLQueries.SET_USER_HAS_AUTHENTICATED;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, status);
            prepStmt.setString(2, userCode);
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

    }

    @Override
    public String getClientIdByDeviceCode(String deviceCode) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            String sqlQuery = SQLQueries.DeviceFlowDAOSQLQueries.GET_CONSUMER_KEY_FOR_DEVICE_CODE;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, deviceCode);
            rs = ps.executeQuery();

            while (rs.next()) {
                clientId = getPersistenceProcessor().getPreprocessedClientId(rs.getString(1));
                log.info("client id is " + clientId);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return clientId;
    }

    @Override
    public HashMap getAuthenticationStatus(String deviceCode) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;
        log.info("getting authentication status");
        boolean checked = false;
        String status = null;
        HashMap<String, String> result = new HashMap<>();

        try {
            String sqlQuery = SQLQueries.DeviceFlowDAOSQLQueries.GET_AUTHENTICATION_STATUS;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, deviceCode);
            rs = ps.executeQuery();

            while (rs.next()) {
                try {
                    result.put(Constants.STATUS, getPersistenceProcessor().getPreprocessedClientId(rs.getString(1)));
                    result.put(Constants.LAST_POLL_TIME, rs.getTimestamp(2).toString());
                    result.put(Constants.POLL_TIME, Long.toString(rs.getLong(3)));
                    result.put(Constants.EXPIRY_TIME, Long.toString(rs.getLong(4)));
                    result.put(Constants.SCOPE, rs.getString(5));
                    result.put(Constants.AUTHZ_USER, rs.getString(6));
                    checked = true;
                } catch (NullPointerException e) {
                    result.put(Constants.STATUS, Constants.NOT_EXIST);
                    return result;
                }
            }

        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        if (checked) {
            return result;
        } else {
            result.put(Constants.STATUS, Constants.NOT_EXIST);
            return result;
        }
    }

    @Override
    public boolean checkClientIdExist(String clientId) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            String sqlQuery = SQLQueries.DeviceFlowDAOSQLQueries.CHECK_CLIENT_ID_EXISTS;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, clientId);
            rs = ps.executeQuery();
            while (rs.next()) {
                status = rs.getString(1);
                if (status != null) {
                    log.info("id exist");
                    return true;
                } else {
                    return false;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        // TODO what will happen when user request again before device code expire
        return false;

    }

    @Override
    public String getScopeForDevice(String userCode) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            String sqlQuery = SQLQueries.DeviceFlowDAOSQLQueries.GET_SCOPE_FOR_USER_CODE;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, userCode);
            rs = ps.executeQuery();
            while (rs.next()) {
                scope = rs.getString(1);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return scope;
    }

    @Override
    public String getStatusForUserCode(String userCode) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            String sqlQuery = SQLQueries.DeviceFlowDAOSQLQueries.GET_USER_CODE_STATUS;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, userCode);
            rs = ps.executeQuery();
            while (rs.next()) {
                status = rs.getString(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return status;
    }

    @Override
    public void setLastPollTime(String deviceCode, Timestamp newPOllTime) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            String sql;
            sql = SQLQueries.DeviceFlowDAOSQLQueries.SET_LAST_POLL_TIME;
            ps = connection.prepareStatement(sql);
            ps.setTimestamp(1, newPOllTime);
            ps.setString(2, deviceCode);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    @Override
    public void setAuthzUser(String userCode, String userName) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            String sql;
            sql = SQLQueries.DeviceFlowDAOSQLQueries.SET_AUTHZ_USER;
            ps = connection.prepareStatement(sql);
            ps.setString(1, userName);
            ps.setString(2, userCode);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    @Override
    public void setDeviceCodeExpired(String deviceCode, String status) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            String sql;
            sql = SQLQueries.DeviceFlowDAOSQLQueries.SET_DEVICE_CODE_EXPIRED;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, status);
            prepStmt.setString(2, deviceCode);
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

    }
}
