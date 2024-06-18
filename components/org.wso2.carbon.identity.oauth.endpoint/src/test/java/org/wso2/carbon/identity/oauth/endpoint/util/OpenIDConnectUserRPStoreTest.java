/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@Listeners(MockitoTestNGListener.class)
public class OpenIDConnectUserRPStoreTest extends TestOAuthEndpointBase {

    private static final String RETRIEVE_PERSISTED_USER_SQL = "SELECT USER_NAME FROM IDN_OPENID_USER_RPS";

    private AuthenticatedUser user;
    private OpenIDConnectUserRPStore store;
    private String clientId;
    private String secret;
    private String appName;
    private String username;
    private String tenantDomain;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        clientId = "ca19a540f544777860e44e75f605d927";
        secret = "87n9a540f544777860e44e75f605d435";
        appName = "myApp";
        username = "user1";
        tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        user = new AuthenticatedUser();
        user.setTenantDomain(tenantDomain);
        user.setAuthenticatedSubjectIdentifier(username);
        user.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");

        store = OpenIDConnectUserRPStore.getInstance();

        initiateInMemoryH2();
        try {
            createOAuthApp(clientId, secret, username, appName, "ACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            // ignore
        }
    }

    @AfterClass
    public void cleanData() throws Exception {

        super.cleanData();

    }

    @BeforeMethod
    public void setUpBeforeMethod() {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        mockDatabase(identityDatabaseUtil);
    }

    @AfterMethod
    public void tearDownAfterMethod() {

        identityDatabaseUtil.close();
    }

    @DataProvider(name = "provideStoreDataToPut")
    public Object[][] provideStoreDataToPut() {

        return new Object[][]{
                {username, clientId},
                {null, clientId},
                {null, "dummyClientId"}
        };
    }

    @Test(dataProvider = "provideStoreDataToPut")
    public void testPutUserRPToStore(String usernameValue, String consumerKey) throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                mockStatic(OAuthServerConfiguration.class);) {

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(this.mockOAuthServerConfiguration);
            lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString()))
                    .thenAnswer(invocation -> invocation.getArguments()[0]);

            user.setUserName(usernameValue);
            try {
                store.putUserRPToStore(user, appName, true, consumerKey);
            } catch (OAuthSystemException e) {
                // Exception thrown because the app does not exist
                assertTrue(!clientId.equals(consumerKey), "Unexpected exception thrown: " + e.getMessage());
            }

            PreparedStatement statement = null;
            ResultSet rs = null;
            String name = null;
            try {
                statement = getConnection().prepareStatement(RETRIEVE_PERSISTED_USER_SQL);
                rs = statement.executeQuery();
                if (rs.next()) {
                    name = rs.getString(1);
                }
            } finally {
                if (statement != null) {
                    statement.close();
                }
                if (rs != null) {
                    rs.close();
                }
            }
            assertEquals(name, username, "Data not added to the store");
        }
    }

    @DataProvider(name = "provideDataToCheckApproved")
    public Object[][] provideDataToCheckApproved() {

        return new Object[][]{
                {username, clientId, appName, true},
                {null, clientId, appName, true},
                {null, clientId, "dummyAppName", false}
        };
    }

    @Test(dataProvider = "provideDataToCheckApproved", dependsOnMethods = {"testPutUserRPToStore"})
    public void testHasUserApproved(String usernameValue, String consumerKey, String app, boolean expected)
            throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                mockStatic(OAuthServerConfiguration.class);) {

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString()))
                    .thenAnswer(invocation -> invocation.getArguments()[0]);

            user.setUserName(usernameValue);
            boolean result;
            try {
                result = store.hasUserApproved(user, app, consumerKey);
                assertEquals(result, expected);
            } catch (OAuthSystemException e) {
                // Exception thrown because the app does not exist
                assertTrue(!clientId.equals(consumerKey), "Unexpected exception thrown: " + e.getMessage());
            }
        }
    }
}
