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
import org.junit.Assert;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * This class contains unit tests for RequestObjectDAOImplTest..
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
@PrepareForTest({IdentityDatabaseUtil.class})
public class RequestObjectDAOImplTest extends PowerMockTestCase {

    private final String sessionDataKey = "d43e8da324a33bdc941b9b95cad6a6a2";
    private final String accessTokenId = "5b6ae5e6-08c2-36d4-9dfe-baff099ddb29";
    private static final String DB_NAME = "testOpenid";

    private RequestObjectDAO requestObjectDAO;
    private List<List<RequestedClaim>> requestedEssentialClaims;

    protected Connection connection;
    protected BasicDataSource dataSource;
    private static final Map<String, BasicDataSource> dataSourceMap = new HashMap<>();


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
            doNothing().when(IdentityDatabaseUtil.class, "closeAllConnections", any(), any(), any());
            requestObjectDAO.insertRequestObjectData("consumerKey", "sessionDataKey",
                    requestedEssentialClaims);
            when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            requestObjectDAO.getRequestedClaimsbySessionDataKey("sessionDataKey", true);
            Assert.assertEquals(requestObjectDAO.getRequestedClaimsbySessionDataKey("sessionDataKey",
                    true).size(), 1);
        }
    }

    @Test
    public void testUpdateRequestObjectReferencebyCodeId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.updateRequestObjectReferencebyCodeId(sessionDataKey, "codeId");
        }
    }

    @Test
    public void testUpdateRequestObjectReferencebyTokenId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionDataKey, accessTokenId);
        }
    }

    @Test
    public void testRefreshRequestObjectReference() throws Exception {

        String newAccessToken = "8c5ee7e5-36d4-08c2-baff-bdfe29aff099";
        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.refreshRequestObjectReference(accessTokenId, newAccessToken);
        }
    }

    @Test
    public void testDeleteRequestObjectReferenceByTokenId() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.deleteRequestObjectReferenceByTokenId(accessTokenId);
        }
    }

    @Test
    public void testDeleteRequestObjectReferenceByCode() throws Exception {

        String code = "d43e8da324a33bdc941b9b95cad6a6a2";
        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            requestObjectDAO.deleteRequestObjectReferenceByCode(code);
        }
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
