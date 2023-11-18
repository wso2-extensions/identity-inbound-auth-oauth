/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyObject;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuthVersions.VERSION_2;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getTenantId;

/**
 * Unit tests for AuthorizationCodeDAOImpl.
 */
@WithCarbonHome
@PrepareForTest({IdentityDatabaseUtil.class, OAuth2Util.class, OAuth2TokenUtil.class, IdentityUtil.class,
        OAuthServerConfiguration.class, IdentityTenantUtil.class, IdentityCoreServiceDataHolder.class})
public class AuthorizationCodeDAOImplTest extends PowerMockIdentityBaseTest {

    public static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    @Mock
    private ServiceProvider mockedServiceProvider;

    @Mock
    private AuthenticatedUser mockedAuthenticatedUser;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    private IdentityCoreServiceDataHolder mockedIdentityCoreServiceDataHolder;

    @Mock
    RealmService mockedRealmService;

    @Mock
    private UserRealm mockedTenantUserRealm;

    @Mock
    private UserStoreManager mockedUserStoreManager;

    private Connection connection;

    private AuthorizationCodeDAOImpl authorizationCodeDAO;
    private String[] scopes;
    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
    private static final int DEFAULT_TENANT_ID = 1234;
    private static final String DEFAULT_TENANT_DOMAIN = "test.tenant";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String DB_NAME = "testAuthzCODEDB";

    @BeforeClass
    public void initTest() throws Exception {

        //Initializing the database.
        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("identity.sql"));
        authorizationCodeDAO = new AuthorizationCodeDAOImpl();
        scopes = new String[]{"sms", "openid", "email"};
        authenticatedUser.setTenantDomain("super.wso2");
        authenticatedUser.setUserName("randomUser");
        authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        storeIDP();
    }

    @BeforeMethod
    public void setup() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
    }

    @AfterMethod
    public void closeup() throws Exception {

        connection.close();
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base(DB_NAME);
    }

    private static void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    private AuthzCodeDO persistAuthorizationCode(String consumerKey, String authzCodeId, String authzCode,
                                                 String status) throws Exception {

        createApplication(consumerKey, UUID.randomUUID().toString(), DEFAULT_TENANT_ID);
        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authenticatedUser, scopes, new Timestamp(System.currentTimeMillis()),
                3600000L, CALLBACK, consumerKey, authzCode, authzCodeId, status, null, null);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(OAuth2Util.getUserStoreDomain(any())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        when(OAuth2Util.getAuthenticatedIDP(any())).thenReturn("LOCAL");
        when(OAuth2Util.isAuthCodePersistenceEnabled()).thenReturn(true);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(IdentityCoreServiceDataHolder.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(DEFAULT_TENANT_ID)).thenReturn(DEFAULT_TENANT_DOMAIN);
        when(IdentityTenantUtil.getLoginTenantId()).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityCoreServiceDataHolder.getInstance()).thenReturn(mockedIdentityCoreServiceDataHolder);
        when(mockedIdentityCoreServiceDataHolder.getRealmService()).thenReturn(mockedRealmService);
        when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedTenantUserRealm);
        when(mockedTenantUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
        authorizationCodeDAO.insertAuthorizationCode(authzCode, consumerKey, CALLBACK, authzCodeDO);
        return authzCodeDO;
    }

    private AuthzCodeDO persistAuthorizationCodeWithModifiedScope(String consumerKey, String authzCodeId,
                                                                  String authzCode, String status, String[] scope)
            throws Exception {

        createApplication(consumerKey, UUID.randomUUID().toString(), DEFAULT_TENANT_ID);
        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authenticatedUser, scope, new Timestamp(System.currentTimeMillis()),
                3600000L, CALLBACK, consumerKey, authzCode, authzCodeId, status, null, null);
        authorizationCodeDAO.insertAuthorizationCode(authzCode, consumerKey, CALLBACK, authzCodeDO);
        return authzCodeDO;
    }

    @Test
    public void testInsertAuthorizationCode() throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        String authzCodeID = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        AuthzCodeDO authzCodeDO = persistAuthorizationCode(consumerKey, authzCodeID, authzCode,
                OAuthConstants.AuthorizationCodeState.ACTIVE);

        Assert.assertEquals(authorizationCodeDAO.getCodeIdByAuthorizationCode(authzCode),
                authzCodeDO.getAuthzCodeId());
        Assert.assertNull(authorizationCodeDAO.getCodeIdByAuthorizationCode(UUID.randomUUID().toString()));
    }

    @Test
    public void testInsertAuthorizationCodeWithTenant() throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        String authzCodeID = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);

        createApplication(consumerKey, UUID.randomUUID().toString(), DEFAULT_TENANT_ID);
        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authenticatedUser, scopes,
                new Timestamp(System.currentTimeMillis()), 3600000L, CALLBACK, consumerKey, authzCode,
                authzCodeID, OAuthConstants.AuthorizationCodeState.ACTIVE, null,
                null);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(OAuth2Util.getUserStoreDomain(any())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        when(OAuth2Util.getAuthenticatedIDP(any())).thenReturn("LOCAL");
        mockStatic(IdentityTenantUtil.class);
        mockStatic(IdentityCoreServiceDataHolder.class);
        when(IdentityTenantUtil.getTenantId(DEFAULT_TENANT_DOMAIN)).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(DEFAULT_TENANT_ID)).thenReturn(DEFAULT_TENANT_DOMAIN);
        when(IdentityTenantUtil.getLoginTenantId()).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityCoreServiceDataHolder.getInstance()).thenReturn(mockedIdentityCoreServiceDataHolder);
        when(mockedIdentityCoreServiceDataHolder.getRealmService()).thenReturn(mockedRealmService);
        when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedTenantUserRealm);
        when(mockedTenantUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
        when(OAuth2Util.isAuthCodePersistenceEnabled()).thenReturn(true);
        authorizationCodeDAO.insertAuthorizationCode(authzCode, consumerKey, DEFAULT_TENANT_DOMAIN,
                CALLBACK, authzCodeDO);

        Assert.assertEquals(authorizationCodeDAO.getCodeIdByAuthorizationCode(authzCode),
                authzCodeDO.getAuthzCodeId());
        Assert.assertNull(authorizationCodeDAO.getCodeIdByAuthorizationCode(UUID.randomUUID().toString()));
    }

    @Test
    public void testGetAuthorizationCodesByConsumerKey() throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        String authzCodeID = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        AuthzCodeDO authzCodeDO = persistAuthorizationCode(consumerKey, authzCodeID, authzCode,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        Set<String> availableAuthzCodes = new HashSet<>();
        availableAuthzCodes.add(authzCode);

        Assert.assertEquals(authorizationCodeDAO.getAuthorizationCodesByConsumerKey(authzCodeDO.getConsumerKey()),
                    availableAuthzCodes);
        Assert.assertTrue(authorizationCodeDAO.getAuthorizationCodesByConsumerKey(UUID.randomUUID().
                    toString()).isEmpty());
    }

    @Test
    public void testGetActiveAuthorizationCodesByConsumerKey() throws Exception {

        String consumerKey1 = UUID.randomUUID().toString();
        String authzCodeID1 = UUID.randomUUID().toString();
        String authzCode1 = UUID.randomUUID().toString();
        String consumerKey2 = UUID.randomUUID().toString();
        String authzCodeID2 = UUID.randomUUID().toString();
        String authzCode2 = UUID.randomUUID().toString();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(consumerKey1, authzCodeID1, authzCode1,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(consumerKey2, authzCodeID2, authzCode2,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        // If state is EXPIRED/INACTIVE needs to revoke token as well.
        mockStatic(OAuth2TokenUtil.class);
        doNothing().when(OAuth2TokenUtil.class, "postRevokeCode", anyString(), anyString(), anyString());
        authorizationCodeDAO.updateAuthorizationCodeState(authzCodeDO1.getAuthorizationCode(),
                OAuthConstants.AuthorizationCodeState.REVOKED);
        Set<String> availableAuthzCodes = new HashSet<>();
        availableAuthzCodes.add(authzCode2);

        Assert.assertEquals(authorizationCodeDAO.getActiveAuthorizationCodesByConsumerKey
                (authzCodeDO2.getConsumerKey()), availableAuthzCodes);
        Assert.assertTrue(authorizationCodeDAO.getActiveAuthorizationCodesByConsumerKey
                (UUID.randomUUID().toString()).isEmpty());
        Assert.assertTrue(authorizationCodeDAO.getActiveAuthorizationCodesByConsumerKey
                (authzCodeDO1.getConsumerKey()).isEmpty());
    }

    @Test
    public void testGetAuthorizationCodesByUser() throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        String authzCodeID = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        AuthenticatedUser dummyAuthenticatedUser = new AuthenticatedUser();
        dummyAuthenticatedUser.setTenantDomain("super.wso2");
        dummyAuthenticatedUser.setUserName("MockedUser");
        dummyAuthenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(OAuth2Util.getUserStoreDomain(any())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        AuthzCodeDO authzCodeDO = persistAuthorizationCode(consumerKey, authzCodeID, authzCode,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
        when(OAuth2Util.isHashDisabled()).thenReturn(true);
        // Allow the method to pass the validation without wanting to traverse internally.
        when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenReturn(2000L);

        Assert.assertTrue((authorizationCodeDAO.getAuthorizationCodesByUser(authenticatedUser).
                contains(authzCodeDO.getAuthorizationCode())));
        Assert.assertTrue(authorizationCodeDAO.getAuthorizationCodesByUser(dummyAuthenticatedUser).isEmpty());
    }

    @Test
    public void testValidateAuthorizationCode() throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        String authzCodeID = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        AuthzCodeDO authzCodeDO = persistAuthorizationCode(consumerKey, authzCodeID, authzCode,
            OAuthConstants.AuthorizationCodeState.ACTIVE);
        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(false);
        OAuth2ServiceComponentHolder.setApplicationMgtService(mockedApplicationManagementService);
        when(mockedApplicationManagementService.getServiceProviderByClientId(anyString(), any(), anyString())).
                thenReturn(mockedServiceProvider);
        when(OAuth2Util.getTenantDomain(1234)).thenReturn("super.wso2");
        when(OAuth2Util.createAuthenticatedUser(anyString(), anyString(), anyString(), isNull())).
                thenReturn(mockedAuthenticatedUser);
        doNothing().when(mockedAuthenticatedUser, "setAuthenticatedSubjectIdentifier", anyString(), anyObject());

        Assert.assertNotNull(authorizationCodeDAO.validateAuthorizationCode(authzCodeDO.getConsumerKey(),
                authzCodeDO.getAuthorizationCode()));
    }

    @Test
    public void testGetAuthorizationCodeDOSetByConsumerKeyForOpenidScope() throws Exception {

        String consumerKey1 = UUID.randomUUID().toString();
        String authzCodeID1 = UUID.randomUUID().toString();
        String authzCode1 = UUID.randomUUID().toString();
        String consumerKey2 = UUID.randomUUID().toString();
        String authzCodeID2 = UUID.randomUUID().toString();
        String authzCode2 = UUID.randomUUID().toString();
        mockStatic(OAuth2Util.class);
        when(getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(OAuth2Util.isAuthCodePersistenceEnabled()).thenReturn(true);
        persistAuthorizationCode(consumerKey1, authzCodeID1, authzCode1, OAuthConstants.AuthorizationCodeState.ACTIVE);
        String[] tempScope = new String[]{"sms", "email"};
        AuthzCodeDO authzCodeDO = persistAuthorizationCodeWithModifiedScope(consumerKey2, authzCodeID2, authzCode2,
                OAuthConstants.AuthorizationCodeState.ACTIVE, tempScope);

        Assert.assertTrue(authorizationCodeDAO.getAuthorizationCodeDOSetByConsumerKeyForOpenidScope(authzCodeDO.
                    getConsumerKey()).isEmpty());
    }

    @Test
    public void testGetAuthorizationCodesByUserForOpenidScope() throws Exception {

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isAuthCodePersistenceEnabled()).thenReturn(true);
        String consumerKey1 = UUID.randomUUID().toString();
        String authzCodeID1 = UUID.randomUUID().toString();
        String authzCode1 = UUID.randomUUID().toString();
        String consumerKey2 = UUID.randomUUID().toString();
        String authzCodeID2 = UUID.randomUUID().toString();
        String authzCode2 = UUID.randomUUID().toString();
        AuthenticatedUser dummyAuthenticatorUser = new AuthenticatedUser();
        dummyAuthenticatorUser.setTenantDomain("super.wso2");
        dummyAuthenticatorUser.setUserName("MockedUser");
        dummyAuthenticatorUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        persistAuthorizationCode(consumerKey1, authzCodeID1, authzCode1, OAuthConstants.AuthorizationCodeState.ACTIVE);
        String[] tempScope = new String[]{"sms", "email"};
        persistAuthorizationCodeWithModifiedScope(consumerKey2, authzCodeID2, authzCode2,
                OAuthConstants.AuthorizationCodeState.ACTIVE, tempScope);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(OAuth2Util.getUserStoreDomain(any())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        mockStatic(IdentityUtil.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
        when(OAuth2Util.isHashDisabled()).thenReturn(true);
        // Allow the method to pass the validation without wanting to traverse internally.
        when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenReturn(2000L);

        Assert.assertTrue(authorizationCodeDAO.getAuthorizationCodesByUserForOpenidScope(authenticatedUser)
                .isEmpty());
        Assert.assertTrue(authorizationCodeDAO.getAuthorizationCodesByUserForOpenidScope(dummyAuthenticatorUser)
                .isEmpty());
    }

    @Test
    public void testDeactivateAuthorizationCode() throws Exception {

        String consumerKey1 = UUID.randomUUID().toString();
        String authzCodeID1 = UUID.randomUUID().toString();
        String authzCode1 = UUID.randomUUID().toString();
        String consumerKey2 = UUID.randomUUID().toString();
        String authzCodeID2 = UUID.randomUUID().toString();
        String authzCode2 = UUID.randomUUID().toString();
        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(consumerKey1, authzCodeID1, authzCode1,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(consumerKey2, authzCodeID2, authzCode2,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        authzCodeDO1.setOauthTokenId(UUID.randomUUID().toString());
        // If state is EXPIRED/INACTIVE needs to revoke token as well.
        mockStatic(OAuth2TokenUtil.class);
        doNothing().when(OAuth2TokenUtil.class, "postRevokeCode", anyString(), anyString(), anyString());
        when(OAuth2Util.isAuthCodePersistenceEnabled()).thenReturn(true);
        authorizationCodeDAO.deactivateAuthorizationCode(authzCodeDO1);

        Assert.assertTrue(authorizationCodeDAO.getActiveAuthorizationCodesByConsumerKey
                (authzCodeDO1.getConsumerKey()).isEmpty());
        Assert.assertFalse(authorizationCodeDAO.getAuthorizationCodesByConsumerKey(authzCodeDO2.getConsumerKey()).
                isEmpty());
    }

    @Test
    public void testDeactivateAuthorizationCodes() throws Exception {

        String consumerKey1 = UUID.randomUUID().toString();
        String authzCodeID1 = UUID.randomUUID().toString();
        String authzCode1 = UUID.randomUUID().toString();
        String consumerKey2 = UUID.randomUUID().toString();
        String authzCodeID2 = UUID.randomUUID().toString();
        String authzCode2 = UUID.randomUUID().toString();
        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(consumerKey1, authzCodeID1, authzCode1,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(consumerKey2, authzCodeID2, authzCode2,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        authzCodeDO1.setOauthTokenId(UUID.randomUUID().toString());
        // If state is EXPIRED/INACTIVE needs to revoke token as well.
        mockStatic(OAuth2TokenUtil.class);
        doNothing().when(OAuth2TokenUtil.class, "postRevokeCode", anyString(), anyString(), anyString());
        List<AuthzCodeDO> revokeAuthzCodeList = new ArrayList<>();
        revokeAuthzCodeList.add(authzCodeDO1);
        revokeAuthzCodeList.add(authzCodeDO2);
        authorizationCodeDAO.deactivateAuthorizationCodes(revokeAuthzCodeList);

        Assert.assertTrue(authorizationCodeDAO.getActiveAuthorizationCodesByConsumerKey
                (authzCodeDO1.getConsumerKey()).isEmpty());
        Assert.assertTrue(authorizationCodeDAO.getActiveAuthorizationCodesByConsumerKey
                (authzCodeDO2.getConsumerKey()).isEmpty());
    }

    @Test
    public void testGetLatestAuthorizationCodesByTenant() throws Exception {

        String consumerKey1 = UUID.randomUUID().toString();
        String authzCodeID1 = UUID.randomUUID().toString();
        String authzCode1 = UUID.randomUUID().toString();
        String consumerKey2 = UUID.randomUUID().toString();
        String authzCodeID2 = UUID.randomUUID().toString();
        String authzCode2 = UUID.randomUUID().toString();
        persistAuthorizationCode(consumerKey1, authzCodeID1, authzCode1, OAuthConstants.AuthorizationCodeState.ACTIVE);
        // Creating an application outside default tenant.
        createApplication(consumerKey2, UUID.randomUUID().toString(), 100);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        when(OAuth2Util.createAuthenticatedUser(anyString(), anyString(), anyString(), anyString())).
                thenReturn(authenticatedUser);

        Assert.assertFalse(authorizationCodeDAO.getLatestAuthorizationCodesByTenant(DEFAULT_TENANT_ID).isEmpty());
        Assert.assertTrue(authorizationCodeDAO.getLatestAuthorizationCodesByTenant(100).isEmpty());
    }

    private void createApplication(String consumerKey, String consumerSecret, int tenantId) throws Exception {

        try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)) {
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, USER_NAME);
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            prepStmt.setString(6, APP_NAME);
            prepStmt.setString(7, VERSION_2);
            prepStmt.setString(8, CALLBACK);
            prepStmt.setString(9, "refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password " +
                    "client_credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:jwt-bearer");
            prepStmt.setLong(10, 3600L);
            prepStmt.setLong(11, 3600L);
            prepStmt.setLong(12, 84600L);
            prepStmt.setLong(13, 3600L);
            prepStmt.execute();
            connection.commit();
        }
    }

    @Test
    public void testGetAuthorizationCodesDoByUser() throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        String authzCodeID = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        AuthenticatedUser dummyAuthenticatedUser = new AuthenticatedUser();
        dummyAuthenticatedUser.setTenantDomain("super.wso2");
        dummyAuthenticatedUser.setUserName("MockedUser");
        dummyAuthenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(OAuth2Util.getUserStoreDomain(any())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        AuthzCodeDO authzCodeDO = persistAuthorizationCode(consumerKey, authzCodeID, authzCode,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(DEFAULT_TENANT_ID);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
        when(OAuth2Util.isHashDisabled()).thenReturn(true);
        // Allow the method to pass the validation without wanting to traverse internally.
        when(OAuth2Util.getTimeToExpire(anyLong(), anyLong())).thenReturn(2000L);

        Assert.assertTrue((authorizationCodeDAO.getAuthorizationCodesDataByUser(authenticatedUser).size() > 0));
        Assert.assertTrue(authorizationCodeDAO.getAuthorizationCodesByUser(dummyAuthenticatedUser).isEmpty());
    }

    private void storeIDP() throws Exception {

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            String sql = "INSERT INTO IDP (TENANT_ID, NAME, UUID) VALUES (1234, 'LOCAL', 5678)";
            try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {
                prepStmt.execute();
            }
        }
    }
}
