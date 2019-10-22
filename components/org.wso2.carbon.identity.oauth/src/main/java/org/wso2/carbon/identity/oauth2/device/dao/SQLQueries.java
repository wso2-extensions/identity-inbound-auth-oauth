package org.wso2.carbon.identity.oauth2.device.dao;

public class SQLQueries {

    private SQLQueries() {

    }

    public static class DeviceFlowDAOSQLQueries {

        public static final String STORE_DEVICE_CODE = "INSERT INTO IDN_OAUTH2_DEVICE_FLOW " +
                "(CODE_ID, DEVICE_CODE, USER_CODE, CONSUMER_KEY_ID, SCOPE, TIME_CREATED, LAST_POLL_TIME, EXPIRY_TIME," +
                " POLL_TIME, STATUS, AUTHZ_USER) SELECT ?,?,?,ID,?,?,?,?,?,?,? FROM IDN_OAUTH_CONSUMER_APPS WHERE " +
                "CONSUMER_KEY=?";

        public static final String GET_CONSUMER_KEY_FOR_USER_CODE = "SELECT CONSUMER_KEY FROM IDN_OAUTH2_DEVICE_FLOW " +
                "INNER JOIN IDN_OAUTH_CONSUMER_APPS ON CONSUMER_KEY_ID = ID WHERE USER_CODE = " +
                "?";

        public static final String REMOVE_DEVICE_CODE = "DELETE FROM IDN_OAUTH2_DEVICE_FLOW WHERE DEVICE_CODE=?";

        public static final String SET_USER_HAS_AUTHENTICATED = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET " +
                "STATUS = ? WHERE USER_CODE = ?";

        public static final String GET_CONSUMER_KEY_FOR_DEVICE_CODE = "SELECT JOIN_TABLE.CONSUMER_KEY FROM ((SELECT *" +
                " FROM IDN_OAUTH_CONSUMER_APPS JOIN IDN_OAUTH2_DEVICE_FLOW WHERE IDN_OAUTH_CONSUMER_APPS.ID = " +
                "IDN_OAUTH2_DEVICE_FLOW.CONSUMER_KEY_ID) AS JOIN_TABLE) WHERE JOIN_TABLE.DEVICE_CODE=?";

        public static final String GET_AUTHENTICATION_STATUS = "SELECT STATUS, LAST_POLL_TIME, POLL_TIME, EXPIRY_TIME, " +
                "SCOPE, AUTHZ_USER FROM IDN_OAUTH2_DEVICE_FLOW WHERE DEVICE_CODE = ?";

        public static final String CHECK_CLIENT_ID_EXISTS = "select consumer_key from IDN_OAUTH_CONSUMER_APPS where " +
                "consumer_key = ?";

        public static final String GET_SCOPE_FOR_USER_CODE = "SELECT SCOPE FROM IDN_OAUTH2_DEVICE_FLOW WHERE " +
                "USER_CODE = ?";

        public static final String GET_USER_CODE_STATUS = "SELECT STATUS FROM IDN_OAUTH2_DEVICE_FLOW WHERE " +
                "USER_CODE = ?";

        public static final String SET_LAST_POLL_TIME = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET " +
                "LAST_POLL_TIME = ? WHERE DEVICE_CODE = ?";

        public static final String SET_AUTHZ_USER = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET " +
                "AUTHZ_USER = ? WHERE USER_CODE = ?";

        public static final String SET_DEVICE_CODE_EXPIRED = "UPDATE IDN_OAUTH2_DEVICE_FLOW SET " +
                "STATUS = ? WHERE DEVICE_CODE = ?";

    }

}
