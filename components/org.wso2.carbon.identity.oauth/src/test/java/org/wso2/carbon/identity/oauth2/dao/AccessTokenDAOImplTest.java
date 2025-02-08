/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.org).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class AccessTokenDAOImplTest {

    private AccessTokenDAOImpl accessTokenDAO;
    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    public static final String H2_SCRIPT_NAME = "identity.sql";
    public static final String H2_SCRIPT2_NAME = "insert_token_binding.sql";
    public static final String DB_NAME = "AccessTokenDB";
    Connection connection = null;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    @BeforeClass
    public void initTest() throws Exception {

        try {
            DAOUtils.initializeBatchDataSource(DB_NAME, H2_SCRIPT_NAME, H2_SCRIPT2_NAME);
        } catch (Exception e) {
            throw new IdentityOAuth2Exception("Error while initializing the data source", e);
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.isTokenCleanupEnabled()).thenReturn(true);
        accessTokenDAO = new AccessTokenDAOImpl();
    }

    @AfterMethod
    public void closeup() throws Exception {

        if (connection != null) {
            connection.close();
        }
        identityDatabaseUtil.close();
        oAuthServerConfiguration.close();
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base(DB_NAME);
    }

    @Test
    public void getSessionIdentifierByTokenId() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);
        assertEquals(accessTokenDAO.getSessionIdentifierByTokenId("2sa9a678f890877856y66e75f605d456"),
                    "4503eb1561bfd6bf237b7e05c15afaff21f511d81135423015a747ee7e3f0bc0");
    }

    private static void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    @Test
    public void testRevokeAccessTokensIndividually() throws Exception {

        String[] tokens = {};
        boolean isHashedToken = false;

        Connection mockConnection = mock(Connection.class);
        DatabaseMetaData mockDatabaseMetaData = mock(DatabaseMetaData.class);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        when(mockDatabaseMetaData.getDriverName()).thenReturn("Microsoft SQL Server");
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(mockConnection);
        accessTokenDAO.revokeAccessTokensIndividually(tokens, isHashedToken);
    }

    @Test
    public void testRevokeAccessTokensInBatch() throws Exception {

        String[] tokens = {"token1", "token2"};
        boolean isHashedToken = true;

        Connection mockConnection = mock(Connection.class);
        PreparedStatement preparedStatement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
        when(mockConnection.prepareStatement(anyString())).thenReturn(preparedStatement);

        DatabaseMetaData mockDatabaseMetaData = mock(DatabaseMetaData.class);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        when(mockDatabaseMetaData.getDriverName()).thenReturn("Microsoft SQL Server");
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(mockConnection);

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.getHashAlgorithm()).thenReturn("SHA-256");

        accessTokenDAO.revokeAccessTokensInBatch(tokens, isHashedToken);
    }
}
