/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dao;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.IdentityOAuthClientException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.Error.DUPLICATE_OAUTH_CLIENT;

/*
 * Unit tests for OAuthAppDAO
 */

public class OAuthAppDAOTest extends TestOAuthDAOBase {

    public static final int TENANT_ID = 7777;
    public static final int TENANT_ID_2 = 8888;
    public static final String GRANT_TYPES = "password code";
    private static final String USER_NAME = "user1";
    private static final String USER_NAME_2 = "user2";
    private static final String USER_STORE_DOMAIN = "USER_STORE_DOMAIN_NAME";
    private static final String TENANT_DOMAIN = "TENANT_DOMAIN";
    private static final String TENANT_DOMAIN_2 = "TENANT_DOMAIN_2";
    private static final String CONSUMER_KEY = "ca19a540f544777860e44e75f605d927";
    private static final String CONSUMER_SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String[] SCOPE_VALIDATORS = {"org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator",
            "org.wso2.carbon.identity.oauth2.validators.XACMLScopeValidator"};
    private static final int USER_ACCESS_TOKEN_EXPIRY_TIME = 3000;
    private static final int APPLICATION_ACCESS_TOKEN_EXPIRY_TIME = 2000;
    private static final int REFRESH_TOKEN_EXPIRY_TIME = 10000;
    private static final int ID_TOKEN_EXPIRY_TIME = 5000;

    private static final String DB_NAME = "OAuthAppDAO";

    private static final String DELETE_ALL_CONSUMER_APPS = "DELETE FROM IDN_OAUTH_CONSUMER_APPS WHERE 1=1";

    private static final String COUNT_APPS = "SELECT count(*) FROM IDN_OAUTH_CONSUMER_APPS WHERE APP_NAME=? and " +
            "TENANT_ID=?";

    private static final String ADD_OAUTH2_ACC_TOKEN = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN " +
            "(TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID, USER_DOMAIN, " +
            "USER_TYPE, GRANT_TYPE, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, TOKEN_STATE, TOKEN_STATE_ID, SUBJECT_IDENTIFIER, " +
            "ACCESS_TOKEN_HASH, REFRESH_TOKEN_HASH, IDP_ID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String DELETE_ALL_OAUTH2_ACC_TOKENS = "DELETE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE 1=1";

    private static final String BACKCHANNEL_LOGOUT = "https://localhost:8090/playground2/backChannelLogout";

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private OAuthComponentServiceHolder mockedOAuthComponentServiceHolder;

    @Mock
    Tenant mockTenant;

    @Mock
    UserRealm mockUserRealmFromRealmService;

    @Mock
    AbstractUserStoreManager mockAbstractUserStoreManager;

    @Mock
    OAuthComponentServiceHolder mockOAuthComponentServiceHolder;

    @BeforeClass
    public void setUp() throws Exception {
        initMocks(this);
        initiateH2Base(DB_NAME, getFilePath("identity.sql"));
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
        // Clean all OAuth apps from IDN_OAUTH_CONSUMER_APPS after a test is completed
        cleanUpOAuthConsumerApps(DB_NAME);
    }

    @Test
    public void testAddOAuthApplication() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            OAuthAppDO appDO = getDefaultOAuthAppDO();
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);
                addOAuthApplication(appDO, TENANT_ID);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    /**
     * Add an OAuth app. This method will be reused in other tests where an OAuth app is required to be present
     * before the actual test can take place.
     *
     * @param appDO OAuthAppDO to be added to the database
     */
    private void addOAuthApplication(OAuthAppDO appDO, int tenantId) {
        try {
            new OAuthAppDAO().addOAuthApplication(appDO);
            // Check whether our app was added correctly
            assertTrue(isAppAvailable(DB_NAME, APP_NAME, tenantId),
                    "OAuth app was not added successfully to the database.");
        } catch (Exception e) {
            fail("Error while adding oauth app to database.", e);
        }
    }

    /**
     * Test adding two OAuth apps with same name.
     */
    @Test
    public void testAddDuplicateOAuthApplication() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);

            OAuthAppDO appDO = getDefaultOAuthAppDO();
            OAuthAppDAO appDAO = new OAuthAppDAO();
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                addOAuthApplication(appDO, TENANT_ID);

                try {
                    // This should throw an exception
                    OAuthAppDO secondApp = getDefaultOAuthAppDO();
                    secondApp.setOauthConsumerKey("secondClientID");
                    secondApp.setOauthConsumerSecret("secondClientSecret");

                    appDAO.addOAuthApplication(secondApp);
                    fail("Application creation with duplicate name did not fail as expected.");
                } catch (Exception e) {
                    assertTrue(e instanceof IdentityOAuthClientException);
                    assertEquals(((IdentityOAuthClientException) e).getErrorCode(),
                            DUPLICATE_OAUTH_CLIENT.getErrorCode());
                }
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    /**
     * Test adding two OAuth apps with same clientID to the same tenant.
     */
    @Test
    public void testAddOAuthApplicationWithDuplicateClientId() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);

            OAuthAppDAO appDAO = new OAuthAppDAO();

            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                OAuthAppDO firstApp = getDefaultOAuthAppDO();
                addOAuthApplication(firstApp, TENANT_ID);

                try {
                    // Change the name of the second app.
                    OAuthAppDO secondApp = getDefaultOAuthAppDO();
                    secondApp.setApplicationName(UUID.randomUUID().toString());
                    // This should throw an exception
                    appDAO.addOAuthApplication(secondApp);
                    fail("Application creation with duplicate clientID did not fail as expected.");
                } catch (Exception e) {
                    assertTrue(e instanceof IdentityOAuthClientException);
                    assertEquals(((IdentityOAuthClientException) e).getErrorCode(),
                            DUPLICATE_OAUTH_CLIENT.getErrorCode());
                }
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddOAuthApplicationWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);

            OAuthAppDO appDO = getDefaultOAuthAppDO();
            try (Connection connection = getConnection(DB_NAME)) {
                // Spy the original connection to throw an exception during commit
                Connection connection1 = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(connection1, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.addOAuthApplication(appDO);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testAddOAuthConsumer() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDAO appDAO = new OAuthAppDAO();
                String[] consumerKeySecretPair = appDAO.addOAuthConsumer(USER_NAME, TENANT_ID, TENANT_DOMAIN);
                assertNotNull(consumerKeySecretPair);
                assertEquals(consumerKeySecretPair.length, 2);
                // Assert consumer key is not blank or empty.
                assertTrue(StringUtils.isNotBlank(consumerKeySecretPair[0]));
                // Assert consumer secret is not blank or empty.
                assertTrue(StringUtils.isNotBlank(consumerKeySecretPair[1]));
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddOAuthConsumerWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(exceptionThrowingConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.addOAuthConsumer(USER_NAME, TENANT_ID, TENANT_DOMAIN);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testUpdateConsumerApplication() throws Exception {
        final String modifiedCallbackUrl = "http://idp.wso2.com/callback";
        final String modifiedGrantTypes = "password";
        final String modifiedAppName = "MODIFIED_APP_NAME";
        final String[] modifiedScopeValidators = {"org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator"};
        final long modifiedApplicationAccessTokenExpiryTime = 1000;
        final long modifiedUserAccessTokenExpiryTime = 8000;
        final long modifiedRefreshTokenExpiryTime = 18000;

        final String getAppFields = "SELECT APP_NAME,GRANT_TYPES,CALLBACK_URL," +
                "APP_ACCESS_TOKEN_EXPIRE_TIME,USER_ACCESS_TOKEN_EXPIRE_TIME,REFRESH_TOKEN_EXPIRE_TIME, " +
                "ID_TOKEN_EXPIRE_TIME, PKCE_MANDATORY, PKCE_SUPPORT_PLAIN, ID " +
                "FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=? AND TENANT_ID=?";

        final String getScopeValidators = "SELECT SCOPE_VALIDATOR FROM IDN_OAUTH2_SCOPE_VALIDATORS " +
                "WHERE APP_ID=?";

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            mockUserstore(oAuthComponentServiceHolder);
            try (Connection connection = getConnection(DB_NAME);
                 PreparedStatement preparedStatement = connection.prepareStatement(getAppFields);
                 PreparedStatement preparedStatementGetValidators = connection.prepareStatement(getScopeValidators);
            ) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDAO appDAO = new OAuthAppDAO();
                OAuthAppDO appDO = getDefaultOAuthAppDO();
                addOAuthApplication(appDO, TENANT_ID);

                preparedStatement.setString(1, CONSUMER_KEY);
                preparedStatement.setInt(2, TENANT_ID);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    assertTrue(resultSet.next());
                    assertEquals(resultSet.getString(1), APP_NAME);
                    assertEquals(resultSet.getString(2), GRANT_TYPES);
                    assertEquals(resultSet.getString(3), CALLBACK);
                    assertEquals(resultSet.getLong(4), APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);
                    assertEquals(resultSet.getLong(5), USER_ACCESS_TOKEN_EXPIRY_TIME);
                    assertEquals(resultSet.getLong(6), REFRESH_TOKEN_EXPIRY_TIME);
                    assertEquals(resultSet.getLong(7), ID_TOKEN_EXPIRY_TIME);
                    assertEquals(resultSet.getBoolean(8), false);
                    assertEquals(resultSet.getBoolean(9), false);
                    appDO.setId(resultSet.getInt(10));
                }
                preparedStatementGetValidators.setInt(1, appDO.getId());
                List<String> scopeValidators = new ArrayList<>();
                try (ResultSet rs = preparedStatementGetValidators.executeQuery()) {
                    while (rs.next()) {
                        scopeValidators.add(rs.getString(1));
                    }
                }
                assertEquals(scopeValidators.toArray(new String[scopeValidators.size()]), SCOPE_VALIDATORS);

                // Modify the app
                appDO.setApplicationName(modifiedAppName);
                appDO.setCallbackUrl(modifiedCallbackUrl);
                appDO.setGrantTypes(modifiedGrantTypes);
                appDO.setScopeValidators(modifiedScopeValidators);
                appDO.setApplicationAccessTokenExpiryTime(modifiedApplicationAccessTokenExpiryTime);
                appDO.setUserAccessTokenExpiryTime(modifiedUserAccessTokenExpiryTime);
                appDO.setRefreshTokenExpiryTime(modifiedRefreshTokenExpiryTime);
                // Enable PKCE related configs
                appDO.setPkceMandatory(true);
                appDO.setPkceSupportPlain(true);

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                appDO.setAppOwner(authenticatedUser);
                appDO.getAppOwner().setUserName("testUser");
                appDO.getAppOwner().setTenantDomain(TENANT_DOMAIN);
                appDAO.updateConsumerApplication(appDO);

                preparedStatement.setString(1, CONSUMER_KEY);
                preparedStatement.setInt(2, TENANT_ID);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    assertTrue(resultSet.next());
                    assertEquals(resultSet.getString(1), modifiedAppName);
                    assertEquals(resultSet.getString(2), modifiedGrantTypes);
                    assertEquals(resultSet.getString(3), modifiedCallbackUrl);
                    assertEquals(resultSet.getLong(4), modifiedApplicationAccessTokenExpiryTime);
                    assertEquals(resultSet.getLong(5), modifiedUserAccessTokenExpiryTime);
                    assertEquals(resultSet.getLong(6), modifiedRefreshTokenExpiryTime);
                    assertEquals(resultSet.getBoolean(7), true);
                    assertEquals(resultSet.getBoolean(8), true);
                }
                preparedStatementGetValidators.setInt(1, appDO.getId());
                scopeValidators = new ArrayList<>();
                try (ResultSet rs = preparedStatementGetValidators.executeQuery()) {
                    while (rs.next()) {
                        scopeValidators.add(rs.getString(1));
                    }
                }
                assertEquals(scopeValidators.toArray(new String[scopeValidators.size()]), modifiedScopeValidators);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testUpdateConsumerApplicationWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            mockUserstore(oAuthComponentServiceHolder);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
                addOAuthApplication(oAuthAppDO, TENANT_ID);

                Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(exceptionThrowingConnection, identityDatabaseUtil);

                oAuthAppDO.setCallbackUrl("CHANGED_CALL_BACK");
                oAuthAppDO.setBackChannelLogoutUrl("CHANGED_BACKCHANNEL_LOGOUT");

                OAuthAppDAO appDAO = new OAuthAppDAO();
                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                oAuthAppDO.setAppOwner(authenticatedUser);
                oAuthAppDO.getAppOwner().setUserName("testUser");
                appDAO.updateConsumerApplication(oAuthAppDO);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testRemoveConsumerApplication() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {

            final String getSecretSql = "SELECT * FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.removeConsumerApplication(CONSUMER_KEY);

                // Try to retrieve the deleted app
                PreparedStatement statement = connection.prepareStatement(getSecretSql);
                statement.setString(1, CONSUMER_KEY);
                try (ResultSet resultSet = statement.executeQuery()) {
                    assertFalse(resultSet.next());
                }
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }


    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testRemoveConsumerApplicationWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(exceptionThrowingConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.removeConsumerApplication(CONSUMER_KEY);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testUpdateOAuthConsumerApp() throws Exception {

        String getAppSql = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {

            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.updateOAuthConsumerApp(APP_NAME, CONSUMER_KEY);

                PreparedStatement statement = connection.prepareStatement(getAppSql);
                statement.setString(1, CONSUMER_KEY);
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (resultSet.next()) {
                        assertEquals(resultSet.getString(1), APP_NAME, "Checking whether the table " +
                                "is updated with the passed appName.");
                    }
                }
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityApplicationManagementException.class)
    public void testUpdateOAuthConsumerAppWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                Connection errorConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(errorConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.updateOAuthConsumerApp(APP_NAME, CONSUMER_KEY);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @DataProvider(name = "appStateProvider")
    public Object[][] provideAppStateData() {
        return new Object[][]{
                {OAuthConstants.OauthAppStates.APP_STATE_ACTIVE},
                {OAuthConstants.OauthAppStates.APP_STATE_REVOKED},
                {null},
                {""}
        };
    }

    @Test(dataProvider = "appStateProvider")
    public void testGetConsumerAppState(String appState) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
                oAuthAppDO.setState(appState);
                addOAuthApplication(oAuthAppDO, TENANT_ID);

                OAuthAppDAO appDAO = new OAuthAppDAO();

                // Whatever the state we set for the app during the app creation it will always be ACTIVE
                assertEquals(appDAO.getConsumerAppState(CONSUMER_KEY), OAuthConstants.OauthAppStates.APP_STATE_ACTIVE,
                        "Checking APP_STATE failed.");
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetConsumerAppStateWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(exceptionThrowingConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.getConsumerAppState(CONSUMER_KEY);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testUpdateConsumerAppState() throws Exception {

        String getAppStateSql = "SELECT APP_STATE FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME);
                 PreparedStatement statement = connection.prepareStatement(getAppStateSql)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                // Add an OAuth app. The app state will be ACTIVE always
                addOAuthApplication(getDefaultOAuthAppDO(), TENANT_ID);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                // Update the app state to REVOKED
                appDAO.updateConsumerAppState(CONSUMER_KEY, OAuthConstants.OauthAppStates.APP_STATE_REVOKED);
                statement.setString(1, CONSUMER_KEY);
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (resultSet.next()) {
                        assertEquals(resultSet.getString(1), OAuthConstants.OauthAppStates.APP_STATE_REVOKED,
                                "APP_STATE has not updated successfully.");
                    }
                }
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @DataProvider(name = "booleanTests")
    public Object[][] booleanTest() throws Exception {
        return new Object[][]{
                {true},
                {false},
        };
    }

    @Test(dataProvider = "booleanTests")
    public void testGetOAuthConsumerAppsOfUser(Boolean isSensitive) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {

            setupMocksForTest(isSensitive, oAuthServerConfiguration, identityTenantUtil, identityUtil,
                    oAuthComponentServiceHolder);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDO appDO = getDefaultOAuthAppDO();
                addOAuthApplication(appDO, TENANT_ID);

                OAuthAppDO anotherAppDO = getDefaultOAuthAppDO();
                anotherAppDO.setApplicationName("ANOTHER_APP");
                anotherAppDO.setOauthConsumerKey(UUID.randomUUID().toString());
                anotherAppDO.setOauthConsumerSecret(UUID.randomUUID().toString());
                addOAuthApplication(anotherAppDO, TENANT_ID);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                String username = IdentityUtil.addDomainToName(USER_NAME, USER_STORE_DOMAIN);
                OAuthAppDO[] oAuthConsumerAppsOfUser = appDAO.getOAuthConsumerAppsOfUser(username, TENANT_ID);
                assertNotNull(oAuthConsumerAppsOfUser);
                assertEquals(oAuthConsumerAppsOfUser.length, 2);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(dataProvider = "booleanTests", expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthConsumerAppsOfUserWithExceptions(Boolean isUsernameCaseSensitive) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(isUsernameCaseSensitive, oAuthServerConfiguration, identityTenantUtil, identityUtil,
                    oAuthComponentServiceHolder);
            try (Connection connection = getConnection(DB_NAME)) {
                Connection errorConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(errorConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.getOAuthConsumerAppsOfUser(USER_NAME, TENANT_ID);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testGetAppInformation() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                addOAuthApplication(getDefaultOAuthAppDO(), TENANT_ID);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                assertNotNull(appDAO.getAppInformation(CONSUMER_KEY));
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(dataProvider = "booleanTests")
    public void testGetAppInformationWithOIDCProperties(Boolean isRenewRefreshEnabled) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                OAuthAppDO defaultOAuthAppDO = getDefaultOAuthAppDO();

                final String backChannelLogoutUrl = "https://dummy.com/logout";
                // Add OIDC properties.
                defaultOAuthAppDO.setAudiences(new String[]{"DUMMY"});
                defaultOAuthAppDO.setIdTokenEncryptionEnabled(true);
                defaultOAuthAppDO.setRequestObjectSignatureValidationEnabled(true);
                defaultOAuthAppDO.setBackChannelLogoutUrl(backChannelLogoutUrl);
                defaultOAuthAppDO.setRenewRefreshTokenEnabled(String.valueOf(isRenewRefreshEnabled));

                addOAuthApplication(defaultOAuthAppDO, TENANT_ID);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                OAuthAppDO oAuthAppDO = appDAO.getAppInformation(CONSUMER_KEY);
                assertNotNull(oAuthAppDO);
                assertEquals(oAuthAppDO.isIdTokenEncryptionEnabled(), true);
                assertEquals(oAuthAppDO.isRequestObjectSignatureValidationEnabled(), true);
                assertEquals(oAuthAppDO.getBackChannelLogoutUrl(), backChannelLogoutUrl);
                assertEquals(oAuthAppDO.getRenewRefreshTokenEnabled(), String.valueOf(isRenewRefreshEnabled));
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @DataProvider(name = "testGetAppInformationWithOIDCPropertiesForImpersonationData")
    public Object[][] testGetAppInformationWithOIDCPropertiesForImpersonationData() {

        return new Object[][]{
                {true, 3600},
                {false, 600},
        };
    }
    @Test(dataProvider = "testGetAppInformationWithOIDCPropertiesForImpersonationData")
    public void testGetAppInformationWithOIDCPropertiesForImpersonationTest
            (boolean subjectTokenEnabled, int subjectTokenExpiryTime) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            mockUserstore(oAuthComponentServiceHolder);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);
                OAuthAppDO defaultOAuthAppDO = getDefaultOAuthAppDO();

                // Add Impersonation OIDC properties.
                defaultOAuthAppDO.setSubjectTokenEnabled(subjectTokenEnabled);
                defaultOAuthAppDO.setSubjectTokenExpiryTime(subjectTokenExpiryTime);
                addOAuthApplication(defaultOAuthAppDO, TENANT_ID);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                OAuthAppDO oAuthAppDO = appDAO.getAppInformation(CONSUMER_KEY);
                assertNotNull(oAuthAppDO);
                assertEquals(oAuthAppDO.isSubjectTokenEnabled(), subjectTokenEnabled);
                assertEquals(oAuthAppDO.getSubjectTokenExpiryTime(), subjectTokenExpiryTime);

                // Update Impersonation OIDC properties.
                oAuthAppDO.setSubjectTokenEnabled(!subjectTokenEnabled);

                appDAO.updateConsumerApplication(oAuthAppDO);
                OAuthAppDO retrievedOAuthAppDO = appDAO.getAppInformation(CONSUMER_KEY);
                assertNotNull(retrievedOAuthAppDO);
                assertEquals(retrievedOAuthAppDO.isSubjectTokenEnabled(), !subjectTokenEnabled);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAppInformationWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                addOAuthApplication(getDefaultOAuthAppDO(), TENANT_ID);

                Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(exceptionThrowingConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                assertNotNull(appDAO.getAppInformation(CONSUMER_KEY));
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testGetAppInformationWithClientIdAndTenant() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                addOAuthApplication(getDefaultOAuthAppDO(), TENANT_ID);

                // Add another oauth app with the same client ID.
                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(USER_NAME_2);
                authenticatedUser.setTenantDomain(TENANT_DOMAIN_2);
                authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
                OAuthAppDO anotherAppDO = getDefaultOAuthAppDO();
                anotherAppDO.setAppOwner(authenticatedUser);
                CommonTestUtils.initPrivilegedCarbonContext(TENANT_DOMAIN_2, TENANT_ID_2, USER_NAME_2);
                addOAuthApplication(anotherAppDO, TENANT_ID_2);

                // Reset the carbon context to the original tenant.
                resetPrivilegedCarbonContext();
                CommonTestUtils.initPrivilegedCarbonContext(TENANT_DOMAIN, TENANT_ID, USER_NAME);

                OAuthAppDO resultAppDO = new OAuthAppDAO().getAppInformation(CONSUMER_KEY, TENANT_ID_2);
                assertNotNull(resultAppDO);
                assertEquals(resultAppDO.getAppOwner().getTenantDomain(), TENANT_DOMAIN_2);
            } finally {
                resetPrivilegedCarbonContext();
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testGetAppInformationWithTokenDO() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                AccessTokenDO accessTokenDO = new AccessTokenDO();
                accessTokenDO.setTokenId("2sa9a678f890877856y66e75f605d456");
                accessTokenDO.setAccessToken("d43e8da324a33bdc941b9b95cad6a6a2");
                accessTokenDO.setRefreshToken("2881c5a375d03dc0ba12787386451b29");
                accessTokenDO.setConsumerKey(CONSUMER_KEY);
                accessTokenDO.setTokenState("ACTIVE");

                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                addOAuthApplication(getDefaultOAuthAppDO(), TENANT_ID);
                int appId = getOAuthApplication(CONSUMER_KEY, TENANT_ID).getId();
                mockOAuth2TokenTable(accessTokenDO, appId);

                assertNotNull(new OAuthAppDAO().getAppInformation(CONSUMER_KEY, accessTokenDO));
            } finally {
                cleanUpOAuth2TokenTable();
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testGetAppsForConsumerKey() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                addOAuthApplication(getDefaultOAuthAppDO(), TENANT_ID);

                // Add another oauth app with the same client ID.
                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(USER_NAME_2);
                authenticatedUser.setTenantDomain(TENANT_DOMAIN_2);
                authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
                OAuthAppDO anotherAppDO = getDefaultOAuthAppDO();
                anotherAppDO.setAppOwner(authenticatedUser);
                CommonTestUtils.initPrivilegedCarbonContext(TENANT_DOMAIN_2, TENANT_ID_2, USER_NAME_2);
                addOAuthApplication(anotherAppDO, TENANT_ID_2);

                // Reset the carbon context to the original tenant.
                resetPrivilegedCarbonContext();
                CommonTestUtils.initPrivilegedCarbonContext(TENANT_DOMAIN, TENANT_ID, USER_NAME);

                OAuthAppDO[] resultAppDOs = new OAuthAppDAO().getAppsForConsumerKey(CONSUMER_KEY);
                assertEquals(resultAppDOs.length, 2);
                assertNotNull(resultAppDOs[0]);
                assertNotNull(resultAppDOs[1]);
            } finally {
                resetPrivilegedCarbonContext();
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test
    public void testGetAppInformationByAppName() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {
                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;

                OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
                addOAuthApplication(oAuthAppDO, TENANT_ID);

                OAuthAppDO actualAppDO = new OAuthAppDAO().getAppInformationByAppName(APP_NAME);
                assertNotNull(actualAppDO);
                assertEquals(actualAppDO.getApplicationName(), APP_NAME);
                assertEquals(actualAppDO.getOauthConsumerKey(), CONSUMER_KEY);
                assertEquals(actualAppDO.getOauthConsumerSecret(), CONSUMER_SECRET);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAppInformationByAppNameWithExceptions() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
            try (Connection connection = getConnection(DB_NAME)) {

                mockIdentityUtilDataBaseConnection(connection, identityDatabaseUtil);;
                OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
                addOAuthApplication(oAuthAppDO, TENANT_ID);

                Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
                mockIdentityDataBaseUtilConnection(exceptionThrowingConnection, identityDatabaseUtil);

                OAuthAppDAO appDAO = new OAuthAppDAO();
                appDAO.getAppInformationByAppName(APP_NAME);
            }
        } finally {
            resetPrivilegedCarbonContext();
        }
    }

    private OAuthAppDO getDefaultOAuthAppDO() {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setApplicationName(APP_NAME);
        appDO.setOauthConsumerKey(CONSUMER_KEY);
        appDO.setOauthConsumerSecret(CONSUMER_SECRET);
        appDO.setUser(authenticatedUser);
        appDO.setCallbackUrl(CALLBACK);
        appDO.setBackChannelLogoutUrl(BACKCHANNEL_LOGOUT);
        appDO.setGrantTypes(GRANT_TYPES);
        appDO.setScopeValidators(SCOPE_VALIDATORS);
        appDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_1A);
        appDO.setApplicationAccessTokenExpiryTime(APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);
        appDO.setUserAccessTokenExpiryTime(USER_ACCESS_TOKEN_EXPIRY_TIME);
        appDO.setRefreshTokenExpiryTime(REFRESH_TOKEN_EXPIRY_TIME);
        appDO.setIdTokenExpiryTime(ID_TOKEN_EXPIRY_TIME);
        return appDO;
    }

    private void setupMocksForTest(boolean isUsernameCaseSensitive,
                                   MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration,
                                   MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                   MockedStatic<IdentityUtil> identityUtil,
                                   MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder)
            throws Exception {

        setupMocksForTest(oAuthServerConfiguration, identityTenantUtil, identityUtil);
        identityUtil.when(() -> IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME))
                .thenReturn(isUsernameCaseSensitive);
        identityUtil.when(() -> IdentityUtil.addDomainToName(USER_NAME, USER_STORE_DOMAIN))
                .thenReturn(USER_STORE_DOMAIN + "/" + USER_NAME);
        identityUtil.when(() -> IdentityUtil.extractDomainFromName(USER_STORE_DOMAIN + "/" + USER_NAME))
                .thenReturn(USER_STORE_DOMAIN);

        oAuthComponentServiceHolder.when(
                OAuthComponentServiceHolder::getInstance).thenReturn(mockedOAuthComponentServiceHolder);
        when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
    }

    private void setupMocksForTest(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration,
                                   MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                   MockedStatic<IdentityUtil> identityUtil) throws Exception {
        
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockedServerConfig);

        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID_2)).thenReturn(TENANT_DOMAIN_2);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_2)).thenReturn(TENANT_ID_2);
        identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(TENANT_ID);

        CommonTestUtils.initPrivilegedCarbonContext(TENANT_DOMAIN, TENANT_ID, USER_NAME);

        identityUtil.when(() -> IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME, TENANT_ID))
                .thenReturn(false);
        identityUtil.when(() -> IdentityUtil.addDomainToName(USER_NAME, USER_STORE_DOMAIN))
                .thenReturn(USER_STORE_DOMAIN + "/" +
                        USER_NAME);
        identityUtil.when(() -> IdentityUtil.extractDomainFromName(USER_STORE_DOMAIN + "/" + USER_NAME))
                .thenReturn(USER_STORE_DOMAIN);
    }

    private void mockIdentityDataBaseUtilConnection(Connection connection,
                                                    MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil) {

        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
    }

    private void mockIdentityUtilDataBaseConnection(Connection connection,
                                                    MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil)
            throws SQLException {
        Connection connection1 = spy(connection);
        doNothing().when(connection1).close();
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection1);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection1);
    }

    private Connection getExceptionThrowingConnection(Connection connection) throws SQLException {
        // Spy the original connection to throw an exception during commit
        Connection exceptionThrowingConnection = spy(connection);
        doNothing().when(exceptionThrowingConnection).close();
        doThrow(new SQLException()).when(exceptionThrowingConnection).prepareStatement(anyString());
        return exceptionThrowingConnection;
    }

    /**
     * Delete all consumer apps from a particular database.
     *
     * @param databaseName
     * @throws Exception
     */
    private void cleanUpOAuthConsumerApps(String databaseName) throws Exception {
        try (Connection connection = getConnection(databaseName);
             PreparedStatement preparedStatement = connection.prepareStatement((DELETE_ALL_CONSUMER_APPS))) {
            preparedStatement.executeUpdate();
        }
    }

    /**
     * Count OAuth Consumer apps in IDN_OAUTH_CONSUMER_APPS. This is an easy way to check whether an APP was created
     * during a test since we always start with a fresh table before the test.
     */
    private boolean isAppAvailable(String databaseName,
                                   String appName,
                                   int tenantId) throws Exception {
        try (Connection connection = getConnection(databaseName);
             PreparedStatement preparedStatement = connection.prepareStatement(COUNT_APPS)) {
            preparedStatement.setString(1, appName);
            preparedStatement.setInt(2, tenantId);
            try (ResultSet resultSet = preparedStatement.executeQuery();) {
                if (resultSet.next()) {
                    return resultSet.getInt(1) == 1;
                }
            }
        }
        return false;
    }

    private void mockUserstore(MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder) throws Exception {

        oAuthComponentServiceHolder.when(OAuthComponentServiceHolder::getInstance)
                .thenReturn(mockOAuthComponentServiceHolder);
        when(mockOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenant(anyInt())).thenReturn(mockTenant);
        when(mockTenant.getAssociatedOrganizationUUID()).thenReturn(null);

        when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealmFromRealmService);
        when(mockUserRealmFromRealmService.getUserStoreManager()).thenReturn(mockAbstractUserStoreManager);
    }

    private OAuthAppDO getOAuthApplication(String consumerKey, int tenantId) {

        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(consumerKey, tenantId);
            assertNotNull(oAuthAppDO.getOauthConsumerKey());
        } catch (Exception e) {
            fail("Error while retrieving oauth app from database.", e);
        }
        return oAuthAppDO;
    }

    private void mockOAuth2TokenTable(AccessTokenDO accessTokenDO, int appId) throws SQLException {

        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement ps = connection.prepareStatement(ADD_OAUTH2_ACC_TOKEN)) {
            ps.setString(1, accessTokenDO.getTokenId());
            ps.setString(2, accessTokenDO.getAccessToken());
            ps.setString(3, accessTokenDO.getRefreshToken());
            ps.setInt(4, appId);
            ps.setString(5, USER_NAME);
            ps.setInt(6, TENANT_ID);
            ps.setString(7, "PRIMARY");
            ps.setString(8, "APPLICATION_USER");
            ps.setString(9, "password");
            ps.setTimestamp(10, new Timestamp(System.currentTimeMillis()));
            ps.setTimestamp(11, new Timestamp(System.currentTimeMillis()));
            ps.setInt(12, 3600);
            ps.setInt(13, 14400);
            ps.setString(14, "369db21a386ae433e65c0ff34d35708d");
            ps.setString(15, accessTokenDO.getTokenState());
            ps.setString(16, "NONE");
            ps.setString(17, USER_NAME);
            ps.setString(18, null);
            ps.setString(19, null);
            ps.setInt(20, 1);
            ps.execute();
        }
    }

    private void cleanUpOAuth2TokenTable() throws Exception {
        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement preparedStatement = connection.prepareStatement((DELETE_ALL_OAUTH2_ACC_TOKENS))) {
            preparedStatement.executeUpdate();
        }
    }

    public static void resetPrivilegedCarbonContext() throws Exception {
        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
        PrivilegedCarbonContext.endTenantFlow();
    }
}
