package org.wso2.carbon.identity.oauth.par.dao;

/**
 * SQL queries related to data access layer of CIBA.
 */
public class SQLQueries {

    private SQLQueries() {

    }

    /**
     * SQL queries.
     */

    public static class ParSQLQueries {
        public static final String STORE_PAR_REQUEST = "INSERT INTO IDN_OAUTH_PAR_PARAMS " +
                "(REQ_URI_UUID, PARAM_MAP, REQ_MADE) VALUES (?,?,?)";

        public static final String RETRIEVE_PAR_REQUEST_DATA =
                "SELECT PARAM_MAP, REQ_MADE FROM IDN_OAUTH_PAR_PARAMS " +
                        " WHERE REQ_URI_UUID = ? ";
    }
}
