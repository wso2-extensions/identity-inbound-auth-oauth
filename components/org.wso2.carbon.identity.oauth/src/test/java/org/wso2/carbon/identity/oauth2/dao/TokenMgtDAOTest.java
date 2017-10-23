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

package org.wso2.carbon.identity.oauth2.dao;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.dao.util.DAOConstants;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for TokenMgtDAO.
 */
@PrepareForTest({IdentityDatabaseUtil.class, IdentityUtil.class, OAuthServerConfiguration.class})
public class TokenMgtDAOTest extends IdentityBaseTest {

    private static final String DB_NAME = "TOKEN_DB";

    private static final String OAUTH_TOKEN_PERSISTENCE_POOL_SIZE = "OAuth.TokenPersistence.PoolSize";

    private static final String FRAMEWORK_PERSISTENCE_POOL_SIZE = "JDBCPersistenceManager.SessionDataPersist.PoolSize";

    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";

    private static final String CALLBACK_URL = "http://localhost:8080/sample/oauth2client";

    private static final String SAMPLE_TENANT_DOMAIN = "wso2.com";

    private static final int SAMPLE_TENANT_ID = 1;

    private static final String SAMPLE_DOMAIN = "SAMPLE_DOMAIN";

    private static final String INVALID_SCOPE = "INVALID_SCOPE";

    private TokenMgtDAO tokenMgtDAO;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private ServiceProvider mockedServiceProvider;

    @Mock
    private LocalAndOutboundAuthenticationConfig mockedLocalAndOutboundAuthenticationConfig;

    @BeforeClass
    public void initTest() throws Exception {
        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("token.sql"));
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_POOL_SIZE)).thenReturn("0");
        when(IdentityUtil.getProperty(FRAMEWORK_PERSISTENCE_POOL_SIZE)).thenReturn("0");
        when(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT)).thenReturn(null);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        tokenMgtDAO = new TokenMgtDAO();

        OAuthComponentServiceHolder.getInstance().setRealmService(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn
                (MultitenantConstants.SUPER_TENANT_ID);
        when(mockedTenantManager.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);

        when(mockedApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(mockedServiceProvider);
        when(mockedServiceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn
                (mockedLocalAndOutboundAuthenticationConfig);
        OAuth2ServiceComponentHolder.setApplicationMgtService(mockedApplicationManagementService);
    }

    @DataProvider(name = "storeAuthorizationCodeDataProvider")
    public Object[][] storeAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "storeAuthorizationCodeDataProvider")
    public void testStoreAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId, String
            userStoreDomain) throws Exception {
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
    }

    @DataProvider(name = "persistAuthorizationCodeDataProvider")
    public Object[][] persistAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "persistAuthorizationCodeDataProvider")
    public void testPersistAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId,
                                             String userStoreDomain) throws Exception {
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
    }

    @DataProvider(name = "deactivateAuthorizationCodeDataProvider")
    public Object[][] deactivateAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "deactivateAuthorizationCodeDataProvider")
    public void testDeactivateAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId,
                                                String userStoreDomain) throws Exception {
        String authzCode = UUID.randomUUID().toString();
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(), authzCode, callbackUrl,
                tenantDomain, tenantId, userStoreDomain, true, OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.deactivateAuthorizationCode(authzCode, UUID.randomUUID().toString());
        }
        assertTrue("INACTIVE".equals(getAuthzCodeStatusByCode(authzCode)), "Failed to deactivate authz code.");
    }

    @DataProvider(name = "storeAccessTokenDataProvider")
    public Object[][] storeAccessTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IWA_NTLM,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };
    }

    @Test(dataProvider = "storeAccessTokenDataProvider")
    public void testStoreAccessToken(String tenantDomain, int tenantId, String userStoreDomain, String applicationType,
                                     String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);
        AccessTokenDO accessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO.getAccessToken(), consumerKey, accessTokenDO, connection,
                    userStoreDomain);
        }
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> accessTokens = tokenMgtDAO.getAccessTokensForUser(authenticatedUser);
            assertTrue(accessTokens != null && accessTokens.contains(accessTokenDO.getAccessToken()), "Failed to " +
                    "persist access token");
        }
    }

    @Test(dataProvider = "storeAccessTokenDataProvider")
    public void testStoreAccessTokenWhileExpiringTheExisting(String tenantDomain, int tenantId, String userStoreDomain,
                                                             String applicationType, String grantType)
            throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO existingAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(existingAccessTokenDO.getAccessToken(), consumerKey, existingAccessTokenDO,
                    connection, userStoreDomain);
        }

        AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.storeAccessToken(newAccessTokenDO.getAccessToken(), consumerKey, newAccessTokenDO,
                    existingAccessTokenDO, userStoreDomain);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> accessTokens = tokenMgtDAO.getAccessTokensForUser(authenticatedUser);
            assertTrue(accessTokens != null && accessTokens.contains(newAccessTokenDO.getAccessToken()), "Failed to " +
                    "persist access token.");
        }
    }

    @Test(dataProvider = "storeAccessTokenDataProvider")
    public void testPersistAccessToken(String tenantDomain, int tenantId, String userStoreDomain,
                                       String applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO existingAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(existingAccessTokenDO.getAccessToken(), consumerKey, existingAccessTokenDO,
                    connection, userStoreDomain);
        }

        AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            assertTrue(tokenMgtDAO.persistAccessToken(newAccessTokenDO.getAccessToken(), consumerKey, newAccessTokenDO,
                    existingAccessTokenDO, userStoreDomain), "Failed to persist access token.");
        }
    }

    @DataProvider(name = "retrieveLatestAccessTokenDataProvider")
    public Object[][] retrieveLatestAccessTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
        };
    }

    @Test(dataProvider = "retrieveLatestAccessTokenDataProvider")
    public void testRetrieveLatestAccessToken(String tenantDomain, int tenantId, String userStoreDomain,
                                              String applicationType, String grantType, String scope,
                                              boolean includeExpiredTokens) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO expiredAccessToken = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        expiredAccessToken.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(expiredAccessToken.getAccessToken(), consumerKey, expiredAccessToken,
                    connection, userStoreDomain);
        }

        if (includeExpiredTokens) {
            if (!INVALID_SCOPE.equals(scope)) {
                try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                    mockStatic(IdentityDatabaseUtil.class);
                    when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                    AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveLatestAccessToken(consumerKey, authenticatedUser,
                            userStoreDomain, scope, true);
                    assertTrue(accessTokenDO != null && expiredAccessToken.getAccessToken().equals(accessTokenDO
                            .getAccessToken()), "Failed to retrieve latest token.");
                }
            } else {
                try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                    mockStatic(IdentityDatabaseUtil.class);
                    when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                    assertNull(tokenMgtDAO.retrieveLatestAccessToken(consumerKey, authenticatedUser, userStoreDomain,
                            scope, true), "Invalid access token.");
                }
            }
        } else {
            AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                    grantType);
            try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                mockStatic(IdentityDatabaseUtil.class);
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                tokenMgtDAO.persistAccessToken(newAccessTokenDO.getAccessToken(), consumerKey, newAccessTokenDO,
                        expiredAccessToken, userStoreDomain);
            }

            try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                mockStatic(IdentityDatabaseUtil.class);
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveLatestAccessToken(consumerKey, authenticatedUser,
                        userStoreDomain, scope, false);
                assertTrue(newAccessTokenDO.getAccessToken().equals(accessTokenDO.getAccessToken()), "Failed to " +
                        "retrieve latest access token");
            }
        }
    }

    @DataProvider(name = "retrieveAccessTokensDataProvider")
    public Object[][] retrieveAccessTokensData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
        };
    }

    @Test(dataProvider = "retrieveAccessTokensDataProvider")
    public void testRetrieveAccessTokens(String tenantDomain, int tenantId, String userStoreDomain,
                                         String applicationType, String grantType,
                                         boolean includeExpired) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO expiredAccessToken = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        expiredAccessToken.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(expiredAccessToken.getAccessToken(), consumerKey, expiredAccessToken,
                    connection, userStoreDomain);
        }

        AccessTokenDO activeAccessToken1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        expiredAccessToken.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(activeAccessToken1.getAccessToken(), consumerKey, activeAccessToken1,
                    connection, userStoreDomain);
        }

        AccessTokenDO activeAccessToken2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        activeAccessToken2.setScope(new String[]{"scope3", "scope4"});
        expiredAccessToken.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(activeAccessToken2.getAccessToken(), consumerKey, activeAccessToken2,
                    connection, userStoreDomain);
        }

        if (includeExpired) {
            try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                mockStatic(IdentityDatabaseUtil.class);
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                Set<AccessTokenDO> accessTokenDOs = tokenMgtDAO.retrieveAccessTokens(consumerKey, authenticatedUser,
                        userStoreDomain, true);
                assertTrue(accessTokenDOs != null && accessTokenDOs.size() == 3, "Failed to retrieve access tokens.");
            }
        } else {
            try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                mockStatic(IdentityDatabaseUtil.class);
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                Set<AccessTokenDO> accessTokenDOs = tokenMgtDAO.retrieveAccessTokens(consumerKey, authenticatedUser,
                        userStoreDomain, false);
                assertTrue(accessTokenDOs != null && accessTokenDOs.size() == 2, "Failed to retrieve access tokens.");
            }
        }
    }

    @DataProvider(name = "validateAuthorizationCodeDataProvider")
    public Object[][] validateAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "validateAuthorizationCodeDataProvider")
    public void testValidateAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId, String
            userStoreDomain) throws Exception {
        String consumerKey = UUID.randomUUID().toString();
        String authzCode = UUID.randomUUID().toString();
        persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(), authzCode, callbackUrl, tenantDomain,
                tenantId, userStoreDomain, true, OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            AuthzCodeDO authzCodeDO = tokenMgtDAO.validateAuthorizationCode(consumerKey, authzCode);
            assertTrue(authzCodeDO != null && authzCode.equals(authzCodeDO.getAuthorizationCode()), "Failed to " +
                    "validate authorization code");
        }
    }

    @DataProvider(name = "changeAuthzCodeStateDataProvider")
    public Object[][] changeAuthzCodeStateData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.INACTIVE
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.INACTIVE

                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.INACTIVE
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.INACTIVE
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
        };
    }

    @Test(dataProvider = "changeAuthzCodeStateDataProvider")
    public void testChangeAuthzCodeState(String callbackUrl, String tenantDomain, int tenantId, String
            userStoreDomain, String tokenState) throws Exception {
        String authzCode = UUID.randomUUID().toString();
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(), authzCode, callbackUrl,
                tenantDomain, tenantId, userStoreDomain, true, OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.changeAuthzCodeState(authzCode, tokenState);

            assertTrue(tokenState.equals(getAuthzCodeStatusByCode(authzCode)), "Failed to update token state");
        }
    }

    @DataProvider(name = "deactivateAuthorizationCodesDataProvider")
    public Object[][] deactivateAuthorizationCodesData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "deactivateAuthorizationCodesDataProvider")
    public void testDeactivateAuthorizationCodes(String callbackUrl, String tenantDomain, int tenantId, String
            userStoreDomain) throws Exception {

        String consumerKey = UUID.randomUUID().toString();
        List<AuthzCodeDO> authzCodeDOs = new ArrayList<>();
        authzCodeDOs.add(persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(), UUID.randomUUID()
                .toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true, OAuthConstants
                .AuthorizationCodeState.ACTIVE));
        authzCodeDOs.add(persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(), UUID.randomUUID()
                .toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, false, OAuthConstants
                .AuthorizationCodeState.ACTIVE));

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.deactivateAuthorizationCode(authzCodeDOs);
        }

        for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
            assertTrue("INACTIVE".equals(getAuthzCodeStatusByCode(authzCodeDO.getAuthorizationCode())),
                    "Failed to deactivate authorization code.");
        }
    }

    @Test(dataProvider = "changeAuthzCodeStateDataProvider")
    public void doChangeAuthzCodeState(String callbackUrl, String tenantDomain, int tenantId, String
            userStoreDomain, String tokenState) throws Exception {
        String authzCode = UUID.randomUUID().toString();
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(), authzCode, callbackUrl,
                tenantDomain, tenantId, userStoreDomain, true, OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.doChangeAuthzCodeState(authzCode, tokenState);
            assertTrue(tokenState.equals(getAuthzCodeStatusByCode(authzCode)), "Failed to update token state");
        }
    }

    @DataProvider(name = "deactivateAuthorizationCodeByAuthzCodeDODataProvider")
    public Object[][] deactivateAuthorizationCodeByAuthzCodeDOData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "deactivateAuthorizationCodeByAuthzCodeDODataProvider")
    public void testDeactivateAuthorizationCodeByAuthzCodeDO(String callbackUrl, String tenantDomain, int tenantId,
                                                             String userStoreDomain) throws Exception {

        AuthzCodeDO authzCodeDO = persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.deactivateAuthorizationCode(authzCodeDO);
            assertTrue("INACTIVE".equals(getAuthzCodeStatusByCode(authzCodeDO.getAuthorizationCode())), "Failed to " +
                    "update token state");
        }
    }

    @DataProvider(name = "validateRefreshTokenDataProvider")
    public Object[][] validateRefreshTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };
    }

    @Test(dataProvider = "validateRefreshTokenDataProvider")
    public void validateRefreshToken(String tenantDomain, int tenantId, String userStoreDomain, String applicationType,
                                     String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AccessTokenDO accessTokenDO = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId,
                userStoreDomain, applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            RefreshTokenValidationDataDO refreshTokenValidationDataDO = tokenMgtDAO.validateRefreshToken(accessTokenDO
                    .getConsumerKey(), accessTokenDO.getRefreshToken());
            assertTrue(refreshTokenValidationDataDO != null && "ACTIVE".equals(refreshTokenValidationDataDO
                    .getRefreshTokenState()), "Failed to validate refresh token.");
        }
    }

    @DataProvider(name = "retrieveAccessTokenDataProvider")
    public Object[][] retrieveAccessTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                        false
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
        };
    }

    @Test(dataProvider = "retrieveAccessTokenDataProvider")
    public void retrieveAccessToken(String tenantDomain, int tenantId, String userStoreDomain, String applicationType,
                                    String grantType, boolean includeExpired) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AccessTokenDO accessTokenDO;
        if (includeExpired) {
            accessTokenDO = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId, userStoreDomain,
                    applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED, true, null);
        } else {
            accessTokenDO = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId, userStoreDomain,
                    applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            AccessTokenDO retrievedAccessToken = tokenMgtDAO.retrieveAccessToken(accessTokenDO.getAccessToken(),
                    includeExpired);
            assertTrue(retrievedAccessToken != null && accessTokenDO.getAccessToken().equals(retrievedAccessToken
                    .getAccessToken()), "Failed to retrieve access token.");
        }
    }

    @DataProvider(name = "setAccessTokenStateDataProvider")
    public Object[][] setAccessTokenStateData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                },
        };
    }

    @Test(dataProvider = "setAccessTokenStateDataProvider")
    public void testSetAccessTokenState(String tenantDomain, int tenantId, String userStoreDomain,
                                        String applicationType, String grantType, String tokenState) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AccessTokenDO accessTokenDO = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId,
                userStoreDomain, applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.setAccessTokenState(connection, accessTokenDO.getTokenId(), tokenState, UUID.randomUUID()
                    .toString(), userStoreDomain);
            assertTrue(tokenState.equals(getAccessTokenStatusByTokenId(accessTokenDO.getTokenId())), "Failed to set " +
                    "access token status.");
        }
    }

    @DataProvider(name = "revokeTokensDataProvider")
    public Object[][] revokeTokensData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IWA_NTLM,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };
    }

    @Test(dataProvider = "revokeTokensDataProvider")
    public void testRevokeTokens(String tenantDomain, int tenantId, String userStoreDomain, String applicationType,
                                 String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        AccessTokenDO accessTokenDO1 = persistAccessToken(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);
        AccessTokenDO accessTokenDO2 = persistAccessToken(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, false,
                new String[]{"scope3"});

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.revokeTokens(new String[]{accessTokenDO1.getAccessToken(), accessTokenDO2.getAccessToken()});
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO1.getTokenId())), "Failed to revoke access token.");
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO2.getTokenId())), "Failed to revoke access token.");
        }
    }

    @Test(dataProvider = "revokeTokensDataProvider")
    public void testRevokeTokensBatch(String tenantDomain, int tenantId, String userStoreDomain, String applicationType,
                                      String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        AccessTokenDO accessTokenDO1 = persistAccessToken(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);
        AccessTokenDO accessTokenDO2 = persistAccessToken(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, false,
                new String[]{"scope3"});

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.revokeTokensBatch(new String[]{accessTokenDO1.getAccessToken(), accessTokenDO2.getAccessToken()});
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO1.getTokenId())), "Failed to revoke access token.");
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO2.getTokenId())), "Failed to revoke access token.");
        }
    }

    @Test(dataProvider = "revokeTokensDataProvider")
    public void testRevokeTokensIndividual(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        AccessTokenDO accessTokenDO1 = persistAccessToken(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);
        AccessTokenDO accessTokenDO2 = persistAccessToken(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, false,
                new String[]{"scope3"});

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.revokeTokensIndividual(new String[]{accessTokenDO1.getAccessToken(), accessTokenDO2.getAccessToken()});
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO1.getTokenId())), "Failed to revoke access token.");
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO2.getTokenId())), "Failed to revoke access token.");
        }
    }

    @Test(dataProvider = "revokeTokensDataProvider")
    public void testRevokeToken(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AccessTokenDO accessTokenDO = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId,
                userStoreDomain, applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.revokeToken(accessTokenDO.getTokenId(), accessTokenDO.getAuthzUser().toString());
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId
                    (accessTokenDO.getTokenId())), "Failed to revoke access token.");
        }
    }

    @DataProvider(name = "getAccessTokensForUserDataProvider")
    public Object[][] getAccessTokensForUserData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IWA_NTLM,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };
    }

    @Test(dataProvider = "getAccessTokensForUserDataProvider")
    public void testGetAccessTokensForUser(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AccessTokenDO accessTokenDO1 = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId,
                userStoreDomain, applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, null);
        AccessTokenDO accessTokenDO2 = persistAccessToken(UUID.randomUUID().toString(), tenantDomain, tenantId,
                userStoreDomain, applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true,
                new String[]{"scope3"});

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> accessTokens = tokenMgtDAO.getAccessTokensForUser(accessTokenDO1.getAuthzUser());
            assertTrue(accessTokens != null && accessTokens.contains(accessTokenDO1.getAccessToken()) && accessTokens
                    .contains(accessTokenDO2.getAccessToken()), "Failed to retrieve access tokens.");
        }
    }

    @DataProvider(name = "getAuthorizationCodesForUserDataProvider")
    public Object[][] getAuthorizationCodesForUserData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };
    }

    @Test(dataProvider = "getAuthorizationCodesForUserDataProvider")
    public void testGetAuthorizationCodesForUser(String callbackUrl, String tenantDomain, int tenantId,
                                                 String userStoreDomain) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> authzCodes = tokenMgtDAO.getAuthorizationCodesForUser(authzCodeDO1.getAuthorizedUser());
            assertTrue(authzCodes != null && authzCodes.contains(authzCodeDO1.getAuthorizationCode()) && authzCodes
                    .contains(authzCodeDO2.getAuthorizationCode()), "Failed to retrieve authorization codes.");
        }
    }

    @DataProvider(name = "getActiveTokensForConsumerKeyDataProvider")
    public Object[][] getActiveTokensForConsumerKeyData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };
    }

    @Test(dataProvider = "getActiveTokensForConsumerKeyDataProvider")
    public void getActiveTokensForConsumerKey(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{"scope3"});
        AccessTokenDO accessTokenDO3 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO3.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO3.getAccessToken(), consumerKey, accessTokenDO3,
                    connection, userStoreDomain);
        }
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> accessTokens = tokenMgtDAO.getActiveTokensForConsumerKey(consumerKey);
            assertNotNull(accessTokens != null && accessTokens.contains(accessTokenDO1.getAccessToken()) &&
                    accessTokens.contains(accessTokenDO2.getAccessToken()) && !accessTokens.contains(accessTokenDO3
                    .getAccessToken()), "Failed to get active access tokens.");
        }
    }

    @Test(dataProvider = "getActiveTokensForConsumerKeyDataProvider")
    public void getActiveDetailedTokensForConsumerKey(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{"scope3"});
        AccessTokenDO accessTokenDO3 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO3.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO3.getAccessToken(), consumerKey, accessTokenDO3,
                    connection, userStoreDomain);
        }
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<AccessTokenDO> accessTokens = tokenMgtDAO.getActiveDetailedTokensForConsumerKey(consumerKey);
            assertNotNull(accessTokens != null && accessTokens.size() == 2, "Failed to get active access tokens.");
        }
    }

    @Test(dataProvider = "getAuthorizationCodesForUserDataProvider")
    public void testGetAuthorizationCodesForConsumerKey(String callbackUrl, String tenantDomain, int tenantId,
                                                        String userStoreDomain) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, false,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO3 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, false,
                OAuthConstants.AuthorizationCodeState.EXPIRED);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> authzCodes = tokenMgtDAO.getAuthorizationCodesForConsumerKey(consumerKey);
            assertNotNull(authzCodes != null && authzCodes.contains(authzCodeDO1.getAuthorizationCode()) && authzCodes
                    .contains(authzCodeDO2.getAuthorizationCode()) && authzCodes.contains(authzCodeDO3
                    .getAuthorizationCode()), "Failed to get authorization codes.");
        }
    }

    @Test(dataProvider = "getAuthorizationCodesForUserDataProvider")
    public void testGetActiveAuthorizationCodesForConsumerKey(String callbackUrl, String tenantDomain, int tenantId,
                                                              String userStoreDomain) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, false,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO3 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, false,
                OAuthConstants.AuthorizationCodeState.EXPIRED);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> authzCodes = tokenMgtDAO.getActiveAuthorizationCodesForConsumerKey(consumerKey);
            assertNotNull(authzCodes != null && authzCodes.contains(authzCodeDO1.getAuthorizationCode()) && authzCodes
                    .contains(authzCodeDO2.getAuthorizationCode()) && !authzCodes.contains(authzCodeDO3
                    .getAuthorizationCode()), "Failed to get active authorization codes.");
        }
    }

    @Test(dataProvider = "getAuthorizationCodesForUserDataProvider")
    public void testGetAllTimeAuthorizedClientIds(String callbackUrl, String tenantDomain, int tenantId,
                                                  String userStoreDomain) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO3 = persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId, userStoreDomain, true,
                OAuthConstants.AuthorizationCodeState.EXPIRED);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> authzCodes = tokenMgtDAO.getAllTimeAuthorizedClientIds(authzCodeDO1.getAuthorizedUser());
            assertNotNull(authzCodes != null && authzCodes.contains(authzCodeDO1.getAuthorizationCode()) && authzCodes
                    .contains(authzCodeDO2.getAuthorizationCode()) && authzCodes.contains(authzCodeDO3
                    .getAuthorizationCode()), "Failed to get all time authorization codes.");
        }
    }

    @DataProvider(name = "invalidateAndCreateNewTokenDataProvider")
    public Object[][] invalidateAndCreateNewTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
        };
    }

    @Test(dataProvider = "invalidateAndCreateNewTokenDataProvider")
    public void invalidateAndCreateNewToken(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType, String tokenState) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO existingAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(existingAccessTokenDO.getAccessToken(), consumerKey, existingAccessTokenDO,
                    connection, userStoreDomain);
        }

        AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.invalidateAndCreateNewToken(existingAccessTokenDO.getTokenId(), tokenState, consumerKey, UUID
                    .randomUUID().toString(), newAccessTokenDO, userStoreDomain);
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(getAccessTokenStatusByTokenId(newAccessTokenDO
                    .getTokenId())));
            assertTrue(tokenState.equals(getAccessTokenStatusByTokenId(existingAccessTokenDO.getTokenId())));
        }
    }

    @Test(dataProvider = "getAccessTokensForUserDataProvider")
    public void getAccessTokensOfTenant(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{"scope3"});
        AccessTokenDO accessTokenDO3 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO3.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO3.getAccessToken(), consumerKey, accessTokenDO3,
                    connection, userStoreDomain);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<AccessTokenDO> accessTokenDOs = tokenMgtDAO.getAccessTokensOfTenant(tenantId);
            assertNotNull(accessTokenDOs, "Failed to retrieve access token for a tenant");
            boolean success = true;
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                if (accessTokenDO.getTenantID() != tenantId) {
                    success = false;
                }
            }
            assertTrue(success, "Failed to retrieve access token for a tenant");
        }
    }

    @Test(dataProvider = "getAccessTokensForUserDataProvider")
    public void testGetAccessTokensOfUserStore(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{"scope3"});
        AccessTokenDO accessTokenDO3 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO3.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO3.getAccessToken(), consumerKey, accessTokenDO3,
                    connection, userStoreDomain);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<AccessTokenDO> accessTokenDOs = tokenMgtDAO.getAccessTokensOfUserStore(tenantId, userStoreDomain);
            assertNotNull(accessTokenDOs, "Failed to retrieve access token for a tenant");
            boolean success = true;
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                if (!userStoreDomain.equals(accessTokenDO.getAuthzUser().getUserStoreDomain())) {
                    success = false;
                }
            }
            assertTrue(success, "Failed to retrieve access token for a tenant");
        }
    }

    @Test(dataProvider = "retrieveAccessTokenDataProvider")
    public void testRetrieveLatestAccessTokens(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType, boolean includeExpiredTokens) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        String scope1 = UUID.randomUUID().toString();
        String scope2 = UUID.randomUUID().toString();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO1.setScope(new String[]{scope1});
        accessTokenDO1.setIssuedTime(timestamp);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{scope2});
        accessTokenDO2.setIssuedTime(timestamp);
        AccessTokenDO accessTokenDO3 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO3.setScope(new String[]{scope1});
        accessTokenDO3.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        accessTokenDO3.setIssuedTime(timestamp);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO3.getAccessToken(), consumerKey, accessTokenDO3,
                    connection, userStoreDomain);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            List<AccessTokenDO> accessTokenDOs = tokenMgtDAO.retrieveLatestAccessTokens(consumerKey,
                    authenticatedUser, userStoreDomain, scope1, includeExpiredTokens, 3);

            if (includeExpiredTokens) {
                assertTrue(accessTokenDOs != null && accessTokenDOs.size() == 2, "Failed to retrieve latest access " +
                        "tokens");
            } else {
                assertTrue(accessTokenDOs != null && accessTokenDOs.size() == 1, "Failed to retrieve latest access " +
                        "tokens");
            }
        }
    }

    @Test(dataProvider = "retrieveAccessTokenDataProvider")
    public void testRetrieveLatestToken(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType, boolean active) throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        String scope1 = UUID.randomUUID().toString();
        String scope2 = UUID.randomUUID().toString();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO1.setScope(new String[]{scope1});
        accessTokenDO1.setIssuedTime(timestamp);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{scope2});
        accessTokenDO2.setIssuedTime(timestamp);
        AccessTokenDO accessTokenDO3 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO3.setScope(new String[]{scope1});
        accessTokenDO3.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        accessTokenDO3.setIssuedTime(timestamp);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO3.getAccessToken(), consumerKey, accessTokenDO3,
                    connection, userStoreDomain);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveLatestToken(connection, consumerKey,
                    authenticatedUser, userStoreDomain, scope1, active);

            if (active) {
                assertTrue(accessTokenDO != null && accessTokenDO1.getAccessToken().equals(accessTokenDO
                        .getAccessToken()), "Failed to retrieve latest active token.");
            } else {
                assertTrue(accessTokenDO != null && accessTokenDO3.getAccessToken().equals(accessTokenDO
                        .getAccessToken()), "Failed to retrieve latest non active token.");
            }
        }
    }

    @Test(dataProvider = "retrieveAccessTokenDataProvider")
    public void testUpdateAppAndRevokeTokensAndAuthzCodes(String tenantDomain, int tenantId, String userStoreDomain,
                                                        String applicationType, String grantType, boolean isRevoke)
            throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        String scope1 = UUID.randomUUID().toString();
        String scope2 = UUID.randomUUID().toString();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        AccessTokenDO accessTokenDO1 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO1.setScope(new String[]{scope1});
        accessTokenDO1.setIssuedTime(timestamp);
        AccessTokenDO accessTokenDO2 = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO2.setScope(new String[]{scope2});
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO1.getAccessToken(), consumerKey, accessTokenDO1,
                    connection, userStoreDomain);
            tokenMgtDAO.storeAccessToken(accessTokenDO2.getAccessToken(), consumerKey, accessTokenDO2,
                    connection, userStoreDomain);
        }

        AuthzCodeDO authzCodeDO1 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), CALLBACK_URL, tenantDomain, tenantId, userStoreDomain, false,
                OAuthConstants.AuthorizationCodeState.ACTIVE);
        AuthzCodeDO authzCodeDO2 = persistAuthorizationCode(consumerKey, UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), CALLBACK_URL, tenantDomain, tenantId, userStoreDomain, false,
                OAuthConstants.AuthorizationCodeState.ACTIVE);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Properties properties = new Properties();
            if (isRevoke) {
                properties.put(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REVOKE);
                properties.put(OAuthConstants.OAUTH_APP_NEW_STATE, OAuthConstants.OauthAppStates.APP_STATE_REVOKED);
            } else {
                properties.put(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REGENERATE);
                properties.put(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY, UUID.randomUUID().toString());
            }
            tokenMgtDAO.updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties, new String[]{authzCodeDO1
                    .getAuthorizationCode(), authzCodeDO2.getAuthorizationCode()}, new String[]{accessTokenDO1
                    .getAccessToken(), accessTokenDO2.getAccessToken()});

            assertTrue(OAuthConstants.AuthorizationCodeState.REVOKED.equals(getAuthzCodeStatusByCode(authzCodeDO1
                    .getAuthorizationCode())));
            assertTrue(OAuthConstants.AuthorizationCodeState.REVOKED.equals(getAuthzCodeStatusByCode(authzCodeDO2
                    .getAuthorizationCode())));
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId(
                    accessTokenDO1.getTokenId())));
            assertTrue(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(getAccessTokenStatusByTokenId(
                    accessTokenDO2.getTokenId())));
        }
    }

    private AuthzCodeDO persistAuthorizationCode(String consumerKey, String authzCodeId, String authzCode,
                                                 String callbackUrl, String tenantDomain, int tenantId,
                                                 String userStoreDomain, boolean createApplication, String status)
            throws Exception {
        if (createApplication) {
            createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        }
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(userStoreDomain);

        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authenticatedUser, new String[]{"scope1", "scope2"},
                new Timestamp(System.currentTimeMillis()), 3600000L, callbackUrl, consumerKey, authzCode, authzCodeId,
                null, null);
        authzCodeDO.setState(status);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.storeAuthorizationCode(authzCode, consumerKey, callbackUrl, authzCodeDO);
            assertNotNull(tokenMgtDAO.getAuthzCodeByCodeId(authzCodeId), "Failed to persist authorize code.");
        }
        return authzCodeDO;
    }

    private AccessTokenDO persistAccessToken(String consumerKey, String tenantDomain, int tenantId,
                                             String userStoreDomain, String applicationType, String grantType,
                                             String tokenState, boolean createApplication, String[] scope)
            throws Exception {
        if (createApplication) {
            createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        }
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);
        AccessTokenDO accessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        accessTokenDO.setTokenState(tokenState);
        if (scope != null) {
            accessTokenDO.setScope(scope);
        }
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO.getAccessToken(), consumerKey, accessTokenDO, connection,
                    userStoreDomain);
        }
        return accessTokenDO;
    }

    private void createApplication(String consumerKey, String consumerSecret, int tenantId) throws Exception {
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)) {
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, "testUser");
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            prepStmt.setString(6, "oauth2-app");
            prepStmt.setString(7, "OAuth-2.0");
            prepStmt.setString(8, CALLBACK_URL);
            prepStmt.setString(9, "refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password " +
                    "client_credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:jwt-bearer");
            prepStmt.setLong(10, 3600L);
            prepStmt.setLong(11, 3600L);
            prepStmt.setLong(12, 84600L);
            prepStmt.execute();
            connection.commit();
        }
    }

    private String getAccessTokenStatusByTokenId(String accessTokenId) throws Exception {
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(DAOConstants.TOKEN_STATUS_BY_TOKE)) {
            prepStmt.setString(1, accessTokenId);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(1);
                }
            }
        }
        return null;
    }

    private String getAuthzCodeStatusByCode(String authzCode) throws Exception {
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(DAOConstants.AUTHZ_CODE_STATUS_BY_CODE)) {
            prepStmt.setString(1, authzCode);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(1);
                }
            }
        }
        return null;
    }

    private AuthenticatedUser getAuthenticatedUser(String tenantDomain, String userStoreDomain) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        return authenticatedUser;
    }

    private AccessTokenDO getAccessTokenDO(String consumerKey, AuthenticatedUser authenticatedUser, String
            applicationType, int tenantId, String grantType) {
        AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, authenticatedUser, new String[]{"scope1",
                "scope2"}, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()),
                3600L, 3600L, applicationType);
        accessTokenDO.setAccessToken(UUID.randomUUID().toString());
        accessTokenDO.setRefreshToken(UUID.randomUUID().toString());
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTenantID(tenantId);
        accessTokenDO.setTokenId(UUID.randomUUID().toString());
        accessTokenDO.setGrantType(grantType);
        return accessTokenDO;
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
