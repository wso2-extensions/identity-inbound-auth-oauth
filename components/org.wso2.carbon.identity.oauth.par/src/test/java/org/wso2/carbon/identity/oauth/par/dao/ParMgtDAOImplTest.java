/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for ParMgtDAOImpl.
 */
@PrepareForTest({IdentityDatabaseUtil.class})
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
public class ParMgtDAOImplTest extends PowerMockTestCase {

    private static final Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private final ParMgtDAOImpl parMgtDAO = new ParMgtDAOImpl();
    private static final String REQUEST_URI_1 = "urn:ietf:params:oauth:par:request_uri:c0143cb3-7ae0-43a3" +
            "-a023b7218c7182df";
    private static final String REQUEST_URI_2 =
            "urn:ietf:params:oauth:par:request_uri:c148b480-3eb6-43fe-82d9-62680e4d3611";
    private static final String REQUEST_URI_3 =
            "urn:ietf:params:oauth:par:request_uri:9b1deb4d-3b7d-4abd-82f0-1e7e2a2c5b9b";
    private static final String REQUEST_URI_4 =
            "urn:ietf:params:oauth:par:request_uri:5b8df4d5-2c36-49a6-97bb-5f8b6b8448c5";
    private static final Long EXPIRY_TIME = 60L;
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String RESPONSE_TYPE = "code";
    private static final String DB_NAME = "testParRequest";
    private final Map<String, String> paramMap = new HashMap<>();
    private ParRequestDO parRequestDO;

    @BeforeClass
    public void setUp() throws Exception {

        paramMap.put(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        paramMap.put(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);
        paramMap.put(OAuth.OAUTH_RESPONSE_TYPE, RESPONSE_TYPE);

        parRequestDO = new ParRequestDO(paramMap, EXPIRY_TIME, CLIENT_ID_VALUE);

        initiateH2Base(getFilePath("h2.sql"));
    }

    @DataProvider(name = "testProvidePersistRequestData")
    public Object[][] testProvidePersistRequestData() {

        return new Object[][]{

                {REQUEST_URI_1, CLIENT_ID_VALUE, EXPIRY_TIME, paramMap},
                {REQUEST_URI_2, CLIENT_ID_VALUE, EXPIRY_TIME, paramMap},
                {REQUEST_URI_3, CLIENT_ID_VALUE, EXPIRY_TIME, new HashMap<>()},
                {REQUEST_URI_4, CLIENT_ID_VALUE, EXPIRY_TIME, null}
        };
    }

    @Test(dataProvider = "testProvidePersistRequestData")
    public void testPersistRequestData(String requestUri, String clientId, Long expiryTime,
                                       Map<String, String> paramMapObj) throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            prepareConnection(connection, true);
            parMgtDAO.persistRequestData(requestUri, clientId, expiryTime, paramMapObj);
        }
    }

    @Test(dependsOnMethods = {"testPersistRequestData"})
    public void testGetRequestDataSuccess() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            prepareConnection(connection, false);
            Optional<ParRequestDO> parRequestDO = parMgtDAO.getRequestData(REQUEST_URI_1);
            parRequestDO.ifPresent(
                    requestDO -> assertEquals(requestDO.getParams(), this.parRequestDO.getParams()));
        }
    }

    @DataProvider(name = "testProvideGetRequestData")
    public Object[][] testProvideGetRequestData() {

        return new Object[][]{

                {REQUEST_URI_3},
                {REQUEST_URI_4},
                {StringUtils.EMPTY},
                {null}
        };
    }

    @Test(dataProvider = "testProvideGetRequestData", dependsOnMethods = {"testPersistRequestData"})
    public void testGetRequestData(String requestUri) throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            prepareConnection(connection, false);
            Optional<ParRequestDO> parRequestDO = parMgtDAO.getRequestData(requestUri);
            parRequestDO.ifPresent(
                    requestDO -> assertNotNull(requestDO.getParams()));
        }
    }

    @Test(dependsOnMethods = {"testPersistRequestData"})
    public void testRemoveRequestData() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            prepareConnection(connection, true);
            parMgtDAO.removeRequestData(REQUEST_URI_2);
        }
    }

    public static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }

    private void prepareConnection(Connection connection, boolean shouldApplyTransaction) {

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(shouldApplyTransaction)).thenReturn(connection);
    }

    protected void initiateH2Base(String scriptPath) throws Exception {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + ParMgtDAOImplTest.DB_NAME);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + scriptPath + "'");
        }
        dataSourceMap.put(ParMgtDAOImplTest.DB_NAME, dataSource);
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }
}
