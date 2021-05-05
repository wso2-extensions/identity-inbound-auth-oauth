/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.openidconnect.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * This class contains unit tests for RequestObjectDAOImplTest..
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
@PrepareForTest({IdentityDatabaseUtil.class, OAuthTokenPersistenceFactory.class, AccessTokenDAO.class})
public class RequestObjectDAOImplTest extends PowerMockTestCase {

    private static final Log log = LogFactory.getLog(AuthorizationCodeDAOImpl.class);
    private final String consumerKey = "ca19a540f544777860e44e75f605d927";
    private final String sessionDataKey = "d43e8da324a33bdc941b9b95cad6a6a2";
    private final String tokenId = "2sa9a678f890877856y66e75f605d456";
    private final String newToken = "a8f78c8420cb48ad91cbac72691d4597";
    private final String codeId = "a5eb9b95ca8ea324a63bdc911d6a6a2";
    private final String consumerId = "1";
    private static final String DB_NAME = "testOpenid";

    private RequestObjectDAO requestObjectDAO;
    private List<List<RequestedClaim>> requestedEssentialClaims;

    protected Connection connection;
    protected BasicDataSource dataSource;
    private static final Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    @Mock
    OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory;

    @Mock
    AccessTokenDAO tokenDAO;

    @BeforeClass
    public void setUp() throws Exception {

        requestObjectDAO = new RequestObjectDAOImpl();
        requestedEssentialClaims = new ArrayList<>();
        List lstRequestedClams = new ArrayList<>();
        List values = new ArrayList<>();

        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName("email");
        requestedClaim.setType("userinfo");
        requestedClaim.setValue("value1");
        requestedClaim.setEssential(true);
        requestedClaim.setValues(values);
        values.add("val1");
        values.add("val2");
        requestedClaim.setValues(values);
        lstRequestedClams.add(requestedClaim);
        requestedEssentialClaims.add(lstRequestedClams);

        initiateH2Base(DB_NAME);
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @Test
    public void testInsertRequestObject() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            doNothing().when(IdentityDatabaseUtil.class, "closeAllConnections", any(), any(), any());
            requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                    requestedEssentialClaims);
            String[] dataMap = getData(sessionDataKey, connection);
            Assert.assertEquals(dataMap[0], consumerId);
            Assert.assertEquals(requestObjectDAO.getRequestedClaimsbySessionDataKey(sessionDataKey,
                    true).get(0).getName(), "email");
        }
    }

    @Test
    public void testUpdateRequestObjectReferenceByToken() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            doNothing().when(IdentityDatabaseUtil.class, "closeAllConnections", any(), any(), any());
            requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionDataKey, tokenId);
            Assert.assertEquals(getData(sessionDataKey, connection)[2], tokenId);
        }
    }

    @Test
    public void testUpdateRequestObjectReferenceByCodeId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            doNothing().when(IdentityDatabaseUtil.class, "closeAllConnections", any(), any(), any());
            insertCodeId(codeId, 1);
            requestObjectDAO.updateRequestObjectReferencebyCodeId(sessionDataKey, codeId);
            Assert.assertEquals(getData(sessionDataKey, connection)[1], codeId);
        }
    }

    @Test
    public void testRefreshRequestObjectReference() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                    requestedEssentialClaims);
            requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionDataKey, tokenId);
            requestObjectDAO.refreshRequestObjectReference(tokenId, newToken);
            Assert.assertEquals(getData(sessionDataKey, connection)[2], newToken);
        }
    }

    @Test
    public void testGetRequestedClaims() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            mockStatic(OAuthTokenPersistenceFactory.class);
            when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(oAuthTokenPersistenceFactory);
            when(oAuthTokenPersistenceFactory.getAccessTokenDAO()).thenReturn(tokenDAO);
            when(tokenDAO.getTokenIdByAccessToken(anyString())).thenReturn(tokenId);
            requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                    requestedEssentialClaims);
            requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionDataKey, tokenId);
            Assert.assertEquals(requestObjectDAO.getRequestedClaims(tokenId,
                    true).get(0).getName(), "email");
        }
    }

    @Test
    public void testDeleteRequestObjectReferenceByTokenId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.deleteRequestObjectReferenceByTokenId(newToken);
        }
        try (Connection connection = getConnection(DB_NAME)) {
            String query = "SELECT * FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE TOKEN_ID=?";
            PreparedStatement statement = connection.prepareStatement(query);
            statement.setString(1, newToken);
            ResultSet resultSet = statement.executeQuery();
            int resultSize = 0;
            if (resultSet.next()) {
                resultSize = resultSet.getRow();
            }
            Assert.assertEquals(resultSize, 0);
        }
    }

    @Test
    public void testDeleteRequestObjectReferenceByCode() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.deleteRequestObjectReferenceByCode(codeId);
        }
        try (Connection connection = getConnection(DB_NAME)) {
            String query = "SELECT * FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE CODE_ID=?";
            PreparedStatement statement = connection.prepareStatement(query);
            statement.setString(1, codeId);
            ResultSet resultSet = statement.executeQuery();
            int resultSize = 0;
            if (resultSet.next()) {
                resultSize = resultSet.getRow();
            }
            Assert.assertEquals(resultSize, 0);
        }
    }

    protected void insertCodeId(String codeId, int consumerKeyId) throws Exception {
        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            String sql = "INSERT INTO IDN_OAUTH2_AUTHORIZATION_CODE (CODE_ID, CONSUMER_KEY_ID) VALUES (?,?)";
            ps = connection.prepareStatement(sql);
            ps.setString(1, codeId);
            ps.setInt(2, consumerKeyId);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String errorMsg = "Can not update refreshed token id of the table ."
                    + OIDCConstants.IDN_OIDC_REQ_OBJECT_REFERENCE;
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    protected String[] getData(String sessionDataKey, Connection connection) throws Exception {
        String[] dataMap = new String[3];

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = "SELECT CONSUMER_KEY_ID, CODE_ID, TOKEN_ID FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE " +
                    "SESSION_DATA_KEY=?";

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, sessionDataKey);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                dataMap = new String[]{resultSet.getString(1), resultSet.getString(2), resultSet.getString(3)};
            }
        } catch (SQLException e) {
            log.error("Error when retrieving inserted request object.", e);
            throw new IdentityOAuth2Exception("Error when retrieving request object", e);
        }
        return dataMap;
    }

    protected void initiateH2Base(String databaseName) throws Exception {

        dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + databaseName);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" +
                    getFilePath("h2_with_application_and_token.sql") + "'");
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath("h2.sql") + "'");
        }
        dataSourceMap.put(databaseName, dataSource);
    }

    protected void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    public static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

}
