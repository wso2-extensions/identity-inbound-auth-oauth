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
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/*
 * Unit tests for OAuthAppDAO
 */
@PrepareForTest(
        {
                IdentityDatabaseUtil.class,
                OAuthServerConfiguration.class,
                OAuthUtil.class,
                OAuth2ServiceComponentHolder.class,
                IdentityTenantUtil.class,
                IdentityUtil.class,
                MultitenantUtils.class,
                OAuthComponentServiceHolder.class
        }
)
@PowerMockIgnore({"javax.*", "org.w3c.*", "org.xml.*"})
public class OAuthAppDAOTest extends TestOAuthDAOBase {

    public static final int TENANT_ID = 7777;
    public static final String GRANT_TYPES = "password code";
    private static final String USER_NAME = "user1";
    private static final String USER_STORE_DOMAIN = "USER_STORE_DOMAIN_NAME";
    private static final String TENANT_DOMAIN = "TENANT_DOMAIN";
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

    private static final String BACKCHANNEL_LOGOUT = "https://localhost:8090/playground2/backChannelLogout";

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private OAuthComponentServiceHolder mockedOAuthComponentServiceHolder;

    @BeforeClass
    public void setUp() throws Exception {
        initMocks(this);
        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
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
        setupMocksForTest();
        OAuthAppDO appDO = getDefaultOAuthAppDO();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            addOAuthApplication(appDO);
        }
    }

    /**
     * Add an OAuth app. This method will be reused in other tests where an OAuth app is required to be present
     * before the actual test can take place.
     *
     * @param appDO OAuthAppDO to be added to the database
     */
    private void addOAuthApplication(OAuthAppDO appDO) {
        try {
            new OAuthAppDAO().addOAuthApplication(appDO);
            // Check whether our app was added correctly
            assertTrue(isAppAvailable(DB_NAME, APP_NAME, TENANT_ID),
                    "OAuth app was not added successfully to the database.");
        } catch (Exception e) {
            fail("Error while adding oauth app to database.", e);
        }
    }

    /**
     * Test adding duplicate OAuth apps.
     */
    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddDuplicateOAuthApplication() throws Exception {
        setupMocksForTest();

        OAuthAppDO appDO = getDefaultOAuthAppDO();
        OAuthAppDAO appDAO = new OAuthAppDAO();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            addOAuthApplication(appDO);
            // This should throw an exception
            appDAO.addOAuthApplication(appDO);
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddOAuthApplicationWithExceptions() throws Exception {
        setupMocksForTest();

        OAuthAppDO appDO = getDefaultOAuthAppDO();
        try (Connection connection = getConnection(DB_NAME)) {
            // Spy the original connection to throw an exception during commit
            Connection connection1 = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(connection1);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.addOAuthApplication(appDO);
        }
    }

    @Test
    public void testAddOAuthConsumer() throws Exception {
        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            String[] consumerKeySecretPair = appDAO.addOAuthConsumer(USER_NAME, TENANT_ID, TENANT_DOMAIN);
            assertNotNull(consumerKeySecretPair);
            assertEquals(consumerKeySecretPair.length, 2);
            // Assert consumer key is not blank or empty.
            assertTrue(StringUtils.isNotBlank(consumerKeySecretPair[0]));
            // Assert consumer secret is not blank or empty.
            assertTrue(StringUtils.isNotBlank(consumerKeySecretPair[1]));
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddOAuthConsumerWithExceptions() throws Exception {
        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(exceptionThrowingConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.addOAuthConsumer(USER_NAME, TENANT_ID, TENANT_DOMAIN);
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
                "FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        final String getScopeValidators = "SELECT SCOPE_VALIDATOR FROM IDN_OAUTH2_SCOPE_VALIDATORS " +
                "WHERE APP_ID=?";

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement preparedStatement = connection.prepareStatement(getAppFields);
             PreparedStatement preparedStatementGetValidators = connection.prepareStatement(getScopeValidators);
        ) {
            mockIdentityUtilDataBaseConnection(connection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            OAuthAppDO appDO = getDefaultOAuthAppDO();
            addOAuthApplication(appDO);

            preparedStatement.setString(1, CONSUMER_KEY);
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
            appDAO.updateConsumerApplication(appDO);

            preparedStatement.setString(1, CONSUMER_KEY);
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
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testUpdateConsumerApplicationWithExceptions() throws Exception {

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
            addOAuthApplication(oAuthAppDO);

            Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(exceptionThrowingConnection);

            oAuthAppDO.setCallbackUrl("CHANGED_CALL_BACK");
            oAuthAppDO.setBackChannelLogoutUrl("CHANGED_BACKCHANNEL_LOGOUT");

            OAuthAppDAO appDAO = new OAuthAppDAO();
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            oAuthAppDO.setAppOwner(authenticatedUser);
            oAuthAppDO.getAppOwner().setUserName("testUser");
            appDAO.updateConsumerApplication(oAuthAppDO);
        }
    }

    @Test
    public void testRemoveConsumerApplication() throws Exception {

        final String getSecretSql = "SELECT * FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.removeConsumerApplication(CONSUMER_KEY);

            // Try to retrieve the deleted app
            PreparedStatement statement = connection.prepareStatement(getSecretSql);
            statement.setString(1, CONSUMER_KEY);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertFalse(resultSet.next());
            }
        }
    }


    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testRemoveConsumerApplicationWithExceptions() throws Exception {

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(exceptionThrowingConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.removeConsumerApplication(CONSUMER_KEY);
        }
    }

    @Test
    public void testUpdateOAuthConsumerApp() throws Exception {

        String getAppSql = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

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
    }

    @Test(expectedExceptions = IdentityApplicationManagementException.class)
    public void testUpdateOAuthConsumerAppWithExceptions() throws Exception {
        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            Connection errorConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(errorConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.updateOAuthConsumerApp(APP_NAME, CONSUMER_KEY);
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

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
            oAuthAppDO.setState(appState);
            addOAuthApplication(oAuthAppDO);

            OAuthAppDAO appDAO = new OAuthAppDAO();

            // Whatever the state we set for the app during the app creation it will always be ACTIVE
            assertEquals(appDAO.getConsumerAppState(CONSUMER_KEY), OAuthConstants.OauthAppStates.APP_STATE_ACTIVE,
                    "Checking APP_STATE failed.");
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetConsumerAppStateWithExceptions() throws Exception {

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(exceptionThrowingConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.getConsumerAppState(CONSUMER_KEY);
        }
    }

    @Test
    public void testUpdateConsumerAppState() throws Exception {

        String getAppStateSql = "SELECT APP_STATE FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement statement = connection.prepareStatement(getAppStateSql)) {
            mockIdentityUtilDataBaseConnection(connection);
            // Add an OAuth app. The app state will be ACTIVE always
            addOAuthApplication(getDefaultOAuthAppDO());

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

        setupMocksForTest(isSensitive);
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            OAuthAppDO appDO = getDefaultOAuthAppDO();
            addOAuthApplication(appDO);

            OAuthAppDO anotherAppDO = getDefaultOAuthAppDO();
            anotherAppDO.setApplicationName("ANOTHER_APP");
            anotherAppDO.setOauthConsumerKey(UUID.randomUUID().toString());
            anotherAppDO.setOauthConsumerSecret(UUID.randomUUID().toString());
            addOAuthApplication(anotherAppDO);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            String username = IdentityUtil.addDomainToName(USER_NAME, USER_STORE_DOMAIN);
            OAuthAppDO[] oAuthConsumerAppsOfUser = appDAO.getOAuthConsumerAppsOfUser(username, TENANT_ID);
            assertNotNull(oAuthConsumerAppsOfUser);
            assertEquals(oAuthConsumerAppsOfUser.length, 2);
        }
    }

    @Test(dataProvider = "booleanTests", expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthConsumerAppsOfUserWithExceptions(Boolean isUsernameCaseSensitive) throws Exception {

        setupMocksForTest(isUsernameCaseSensitive);
        try (Connection connection = getConnection(DB_NAME)) {
            Connection errorConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(errorConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.getOAuthConsumerAppsOfUser(USER_NAME, TENANT_ID);
        }
    }

    @Test
    public void testGetAppInformation() throws Exception {
        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            addOAuthApplication(getDefaultOAuthAppDO());

            OAuthAppDAO appDAO = new OAuthAppDAO();
            assertNotNull(appDAO.getAppInformation(CONSUMER_KEY));
        }
    }

    @Test(dataProvider = "booleanTests")
    public void testGetAppInformationWithOIDCProperties(Boolean isRenewRefreshEnabled) throws Exception {
        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            OAuthAppDO defaultOAuthAppDO = getDefaultOAuthAppDO();

            final String backChannelLogoutUrl = "https://dummy.com/logout";
            // Add OIDC properties.
            defaultOAuthAppDO.setAudiences(new String[] {"DUMMY"});
            defaultOAuthAppDO.setIdTokenEncryptionEnabled(true);
            defaultOAuthAppDO.setRequestObjectSignatureValidationEnabled(true);
            defaultOAuthAppDO.setBackChannelLogoutUrl(backChannelLogoutUrl);
            defaultOAuthAppDO.setRenewRefreshTokenEnabled(String.valueOf(isRenewRefreshEnabled));

            addOAuthApplication(defaultOAuthAppDO);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            OAuthAppDO oAuthAppDO = appDAO.getAppInformation(CONSUMER_KEY);
            assertNotNull(oAuthAppDO);
            assertEquals(oAuthAppDO.isIdTokenEncryptionEnabled(), true);
            assertEquals(oAuthAppDO.isRequestObjectSignatureValidationEnabled(), true);
            assertEquals(oAuthAppDO.getBackChannelLogoutUrl(), backChannelLogoutUrl);
            assertEquals(oAuthAppDO.getRenewRefreshTokenEnabled(), String.valueOf(isRenewRefreshEnabled));
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAppInformationWithExceptions() throws Exception {

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            addOAuthApplication(getDefaultOAuthAppDO());

            Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(exceptionThrowingConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            assertNotNull(appDAO.getAppInformation(CONSUMER_KEY));
        }
    }

    @Test
    public void testGetAppInformationByAppName() throws Exception {

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
            addOAuthApplication(oAuthAppDO);

            OAuthAppDO actualAppDO = new OAuthAppDAO().getAppInformationByAppName(APP_NAME);
            assertNotNull(actualAppDO);
            assertEquals(actualAppDO.getApplicationName(), APP_NAME);
            assertEquals(actualAppDO.getOauthConsumerKey(), CONSUMER_KEY);
            assertEquals(actualAppDO.getOauthConsumerSecret(), CONSUMER_SECRET);
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAppInformationByAppNameWithExceptions() throws Exception {

        setupMocksForTest();
        try (Connection connection = getConnection(DB_NAME)) {

            mockIdentityUtilDataBaseConnection(connection);
            OAuthAppDO oAuthAppDO = getDefaultOAuthAppDO();
            addOAuthApplication(oAuthAppDO);

            Connection exceptionThrowingConnection = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(exceptionThrowingConnection);

            OAuthAppDAO appDAO = new OAuthAppDAO();
            appDAO.getAppInformationByAppName(APP_NAME);
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

    private void setupMocksForTest(boolean isUsernameCaseSensitive) throws Exception {
        setupMocksForTest();
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME)).thenReturn(isUsernameCaseSensitive);
        when(IdentityUtil.addDomainToName(USER_NAME, USER_STORE_DOMAIN)).thenReturn(USER_STORE_DOMAIN + "/" +
                USER_NAME);
        when(IdentityUtil.extractDomainFromName(USER_STORE_DOMAIN + "/" + USER_NAME)).thenReturn(USER_STORE_DOMAIN);

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockedOAuthComponentServiceHolder);
        when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
    }

    private void setupMocksForTest() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);

        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);

        CommonTestUtils.initPrivilegedCarbonContext(TENANT_DOMAIN, TENANT_ID, USER_NAME);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME, TENANT_ID)).thenReturn(false);
        when(IdentityUtil.addDomainToName(USER_NAME, USER_STORE_DOMAIN)).thenReturn(USER_STORE_DOMAIN + "/" +
                USER_NAME);
        when(IdentityUtil.extractDomainFromName(USER_STORE_DOMAIN + "/" + USER_NAME)).thenReturn(USER_STORE_DOMAIN);
    }

    private void mockIdentityDataBaseUtilConnection(Connection connection) {
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
    }

    private void mockIdentityUtilDataBaseConnection(Connection connection) throws SQLException {
        Connection connection1 = spy(connection);
        doNothing().when(connection1).close();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection1);
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
}
