/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect;

/**
 * Class which tests JWTAccessTokenOIDCClaimsHandler.
 */

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.dao.CacheBackedScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;

@Listeners(MockitoTestNGListener.class)
public class JWTAccessTokenOIDCClaimsHandlerTest {

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT_NAME = "dbScripts/identity.sql";
    public static final String H2_SCRIPT2_NAME = "dbScripts/insert_scope_claim.sql";
    private static final String TENANT_DOMAIN = "foo.com";
    private static final int TENANT_ID = 1234;
    private static final String SERVICE_PROVIDER_NAME = "sampleSP";
    private static final String SERVICE_PROVIDER_RESOURCE_ID = "sampleSPResourceId";
    private static final String DUMMY_CLIENT_ID = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static final String USER_NAME = "peter";
    private static final String USER_STORE_DOMAIN = "H2";
    private static final String TENANT_AWARE_USERNAME = USER_STORE_DOMAIN + DOMAIN_SEPARATOR + USER_NAME;
    private static final String LOCAL_EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String LOCAL_USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String LOCAL_LASTNAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    private static final String LOCAL_GIVEN_NAME_CLAIM_URI = "http://wso2.org/claims/givenname";
    private static final String LOCAL_GROUPS_CLAIM_URI = "http://wso2.org/claims/groups";
    private static final String LOCAL_COUNTRY_CLAIM_URI = "http://wso2.org/claims/country";
    private static final String LOCAL_ADDRESS_CLAIM_URI = "http://wso2.org/claims/addresses";
    private static final String ROLES = "roles";
    private static final String ADDRESS = "address";
    private static final String[] jwtAccessTokenClaims = new String[]{"given_name", "family_name", "email", "address",
            "roles", "groups"};
    private static final Map<String, String> USER_CLAIMS_MAP = new HashMap<String, String>() {{
        put(LOCAL_EMAIL_CLAIM_URI, "peter@example.com");
        put(LOCAL_USERNAME_CLAIM_URI, USER_NAME);
        put(LOCAL_LASTNAME_CLAIM_URI, "Smith");
        put(LOCAL_GIVEN_NAME_CLAIM_URI, "Peter");
        put(LOCAL_GROUPS_CLAIM_URI, "group1,group2");
    }};
    private static final String CARBON_HOME =
            Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
    private static final Log log = LogFactory.getLog(JWTAccessTokenOIDCClaimsHandlerTest.class);
    Connection connection = null;
    @Mock
    private ApplicationManagementService applicationManagementService;
    @Mock
    private RoleManagementService roleManagementService;
    @Mock
    ClaimMetadataHandler mockClaimMetadataHandler;
    private MockedStatic<FrameworkUtils> frameworkUtils;

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            URL url = DefaultOIDCClaimsCallbackHandlerTest.class.getClassLoader().getResource(fileName);
            if (url != null) {
                try {
                    File file = new File(url.toURI());
                    return file.getAbsolutePath();
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException("Could not resolve a file with given path: " +
                            url.toExternalForm());
                }
            }
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        privilegedCarbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
        privilegedCarbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        PrivilegedCarbonContext.endTenantFlow();
        if (connection != null) {
            connection.close();
        }
        frameworkUtils.close();
    }

    @BeforeTest
    public void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;
        System.setProperty(CarbonBaseConstants.CARBON_HOME, CARBON_HOME);
        BasicDataSource dataSource1 = new BasicDataSource();
        dataSource1.setDriverClassName("org.h2.Driver");
        dataSource1.setUsername("username");
        dataSource1.setPassword("password");
        dataSource1.setUrl("jdbc:h2:mem:test" + DB_NAME);
        connection = dataSource1.getConnection();
        try {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT_NAME) + "'");
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT2_NAME) + "'");
        } catch (SQLException e) {
            log.error("Error while running the script: " + H2_SCRIPT2_NAME);
        }

        OpenIDConnectClaimFilterImpl openIDConnectClaimFilter = spy(new OpenIDConnectClaimFilterImpl());
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters().add(openIDConnectClaimFilter);
        ScopeClaimMappingDAOImpl scopeClaimMappingDAO = new ScopeClaimMappingDAOImpl();
        OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(scopeClaimMappingDAO);
        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class, Mockito.CALLS_REAL_METHODS)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(anyString()))
                    .thenAnswer((Answer<Void>) invocation -> null);
            setPrivateField(OAuthTokenPersistenceFactory.getInstance(), "scopeClaimMappingDAO",
                    new CacheBackedScopeClaimMappingDAOImpl());
        }
    }

    @Test
    public void testHandleCustomClaimsWithoutJWTAccessTokenClaimsForOAuthTokenReqMsgContext() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(
                        getoAuthAppDO(new String[0]));
                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertTrue(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    @Test
    public void testHandleCustomClaimsWithoutRegisteredOIDCClaimsForOAuthTokenReqMsgContext() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(this.mockClaimMetadataHandler);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(
                        getoAuthAppDO(jwtAccessTokenClaims));
                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertTrue(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    @Test
    public void testHandleCustomClaimsWithoutUserClaimsForOAuthTokenReqMsgContext() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<AuthzUtil> authzUtil = mockStatic(AuthzUtil.class)) {
                identityUtil.when(IdentityUtil::isGroupsVsRolesSeparationImprovementsEnabled).thenReturn(true);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(
                        getoAuthAppDO(jwtAccessTokenClaims));
                Map<String, String> mappings = getOIDCtoLocalClaimsMapping();
                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
                lenient().when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                        anyString(), isNull(), anyString(), anyBoolean())).thenReturn(mappings);
                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
                mockApplicationManagementService();
                authzUtil.when(() -> AuthzUtil.getUserRoles(any(), anyString())).thenReturn(new ArrayList<>());
                UserRealm userRealm = getUserRealmWithUserClaims(new HashMap<>());
                mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);
                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertTrue(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    @Test
    public void testHandleCustomClaimsForOAuthTokenReqMsgContext() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<AuthzUtil> authzUtil = mockStatic(AuthzUtil.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class, Mockito.CALLS_REAL_METHODS)) {
                identityUtil.when(IdentityUtil::isGroupsVsRolesSeparationImprovementsEnabled).thenReturn(true);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(
                        getoAuthAppDO(jwtAccessTokenClaims));
                Map<String, String> mappings = getOIDCtoLocalClaimsMapping();
                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
                lenient().when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                        anyString(), isNull(), anyString(), anyBoolean())).thenReturn(mappings);
                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
                mockApplicationManagementService();
                authzUtil.when(() -> AuthzUtil.getUserRoles(any(), anyString())).thenReturn(new ArrayList<>());
                UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
                mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);
                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertFalse(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    @Test
    public void testHandleCustomClaimsWithAddressClaimForOAuthTokenReqMsgContext() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class, Mockito.CALLS_REAL_METHODS)) {
                identityUtil.when(IdentityUtil::isGroupsVsRolesSeparationImprovementsEnabled).thenReturn(true);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(
                        getoAuthAppDO(new String[]{"country", "address"}));
                Map<String, String> mappings = getOIDCtoLocalClaimsMapping();
                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
                lenient().when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                        anyString(), isNull(), anyString(), anyBoolean())).thenReturn(mappings);
                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
                mockApplicationManagementService();
                Map<String, String> userClaims = new HashMap<>();
                userClaims.put(LOCAL_COUNTRY_CLAIM_URI, "Sri Lanka");
                userClaims.put(LOCAL_ADDRESS_CLAIM_URI, "Kurunegala");
                UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
                mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);
                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertNotNull(jwtClaimsSet.getClaim(ADDRESS));
            }
        }
    }

    private static Map<String, String> getOIDCtoLocalClaimsMapping() {

        Map<String, String> mappings = new HashMap<>();
        mappings.put("given_name", "http://wso2.org/claims/givenname");
        mappings.put("family_name", "http://wso2.org/claims/lastname");
        mappings.put("email", "http://wso2.org/claims/emailaddress");
        mappings.put("address", "http://wso2.org/claims/addresses");
        mappings.put("roles", "http://wso2.org/claims/roles");
        mappings.put("groups", "http://wso2.org/claims/groups");
        mappings.put("country", "http://wso2.org/claims/country");
        return mappings;
    }

    private ServiceProvider getServiceProvider() {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
        serviceProvider.setApplicationResourceId(SERVICE_PROVIDER_RESOURCE_ID);
        serviceProvider.setTenantDomain(TENANT_DOMAIN);
        PermissionsAndRoleConfig permissionsAndRoleConfig = new PermissionsAndRoleConfig();
        serviceProvider.setPermissionAndRoleConfig(permissionsAndRoleConfig);
        return serviceProvider;
    }

    private UserRealm getUserRealmWithUserClaims(Map<String, String> userClaims) throws UserStoreException {

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        lenient().when(userStoreManager.getUserClaimValues(eq(TENANT_AWARE_USERNAME), any(), eq(null)))
                .thenReturn(userClaims);

        UserRealm userRealm = mock(UserRealm.class);
        lenient().when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        return userRealm;
    }

    private JWTClaimsSet getJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                        OAuthTokenReqMessageContext requestMsgCtx,
                                        MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws IdentityOAuth2Exception {

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        DataSource dataSource = mock(DataSource.class);
        JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);

        try {
            if (connection.isClosed()) {

                BasicDataSource dataSource1 = new BasicDataSource();
                dataSource1.setDriverClassName("org.h2.Driver");
                dataSource1.setUsername("username");
                dataSource1.setPassword("password");
                dataSource1.setUrl("jdbc:h2:mem:test" + DB_NAME);
                Connection connection1 = null;
                connection1 = dataSource1.getConnection();
                lenient().when(dataSource.getConnection()).thenReturn(connection1);

            } else {
                lenient().when(dataSource.getConnection()).thenReturn(connection);
            }
        } catch (Exception e) {
            log.error("Error while obtaining the datasource. ");
        }

        jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
        lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);

        JWTAccessTokenOIDCClaimsHandler jWTAccessTokenOIDCClaimsHandler =
                new JWTAccessTokenOIDCClaimsHandler();
        return jWTAccessTokenOIDCClaimsHandler.handleCustomClaims(jwtClaimsSetBuilder, requestMsgCtx);
    }

    private OAuthTokenReqMessageContext getTokenReqMessageContextForLocalUser() {

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setTenantDomain(TENANT_DOMAIN);
        accessTokenReqDTO.setClientId(DUMMY_CLIENT_ID);

        OAuthTokenReqMessageContext requestMsgCtx = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        requestMsgCtx.setAuthorizedUser(getDefaultAuthenticatedLocalUser());
        return requestMsgCtx;
    }

    private AuthenticatedUser getDefaultAuthenticatedLocalUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setUserId(StringUtils.EMPTY);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN);
        authenticatedUser.setFederatedUser(false);
        return authenticatedUser;
    }

    private OAuthAppDO getoAuthAppDO(String[] jwtAccessTokenClaims) {

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setAccessTokenClaims(jwtAccessTokenClaims);
        return oAuthAppDO;
    }

    private void mockApplicationManagementService() throws Exception {

        ServiceProvider serviceProvider = getServiceProvider();
        when(applicationManagementService.getServiceProviderNameByClientId(anyString(), anyString(), anyString()))
                .thenReturn(SERVICE_PROVIDER_NAME);
        setStaticField(OAuth2ServiceComponentHolder.class, "applicationMgtService", applicationManagementService);
        when(applicationManagementService.getApplicationExcludingFileBasedSPs(SERVICE_PROVIDER_NAME, TENANT_DOMAIN))
                .thenReturn(serviceProvider);
    }

    private void mockUserRealm(String username, UserRealm userRealm,
                               MockedStatic<IdentityTenantUtil> identityTenantUtil) throws IdentityException {

        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(TENANT_DOMAIN, username)).thenReturn(userRealm);
    }

    private void setStaticField(Class classname,
                                String fieldName,
                                Object value)
            throws NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {

        Field declaredField = classname.getDeclaredField(fieldName);
        declaredField.setAccessible(true);

        Method getDeclaredFields0 = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
        getDeclaredFields0.setAccessible(true);
        Field[] fields = (Field[]) getDeclaredFields0.invoke(Field.class, false);
        Field modifiers = null;
        for (Field each : fields) {
            if ("modifiers".equals(each.getName())) {
                modifiers = each;
                break;
            }
        }
        modifiers.setAccessible(true);
        modifiers.setInt(declaredField, declaredField.getModifiers() & ~Modifier.FINAL);

        declaredField.set(null, value);
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

}
