/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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

import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.LocalRole;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2BearerGrantHandlerTest;
import org.wso2.carbon.identity.openidconnect.dao.CacheBackedScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.sql.DataSource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.USER_NOT_FOUND;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.EMAIL_VERIFIED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.PHONE_NUMBER_VERIFIED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.UPDATED_AT;
import static org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler.PREV_ACCESS_TOKEN;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;

/**
 * Class which tests SAMLAssertionClaimsCallback.
 */
@WithCarbonHome
@WithRealmService
@Listeners(MockitoTestNGListener.class)
public class DefaultOIDCClaimsCallbackHandlerTest {

    @Mock
    private ApplicationManagementService applicationManagementService;

    private static final String SAMPLE_ACCESS_TOKEN = "4952b467-86b2-31df-b63c-0bf25cec4f86";
    private static final String SAMPLE_TENANT_DOMAIN = "dummy_domain";
    private static final String DUMMY_CLIENT_ID = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static final String CARBON_HOME =
            Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();

    private static final String OIDC_SCOPE = "openid";
    private static final String[] APPROVED_SCOPES = {OIDC_SCOPE, "testScope1", "testScope2"};

    private static final String USER_NAME = "peter";

    private static final String USER_STORE_DOMAIN = "H2";
    private static final String TENANT_AWARE_USERNAME = USER_STORE_DOMAIN + DOMAIN_SEPARATOR + USER_NAME;
    private static final String TENANT_DOMAIN = "foo.com";
    private static final int TENANT_ID = 1234;
    private static final String SERVICE_PROVIDER_NAME = "sampleSP";

    private static final String LOCAL_EMAIL_CLAIM_URI = "http://wso2.org/claims/email";
    private static final String LOCAL_USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String LOCAL_ROLE_CLAIM_URI = "http://wso2.org/claims/role";
    private static final String LOCAL_UPDATED_AT_CLAIM_URI = "http://wso2.org/claims/update_at";
    private static final String LOCAL_EMAIL_VERIFIED_CLAIM_URI = "http://wso2.org/claims/email_verified";
    private static final String LOCAL_PHONE_VERIFIED_CLAIM_URI = "http://wso2.org/claims/phone_verified";
    private static final String LOCAL_COUNTRY_CLAIM_URI = "http://wso2.org/claims/country";
    private static final String LOCAL_STREET_CLAIM_URI = "http://wso2.org/claims/street";
    private static final String LOCAL_PROVINCE_CLAIM_URI = "http://wso2.org/claims/province";
    private static final String LOCAL_DIVISION_CLAIM_URI = "http://wso2.org/claims/division";
    private static final String LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_URI = "http://wso2.org/claims/division1";
    private static final String LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_IN_URL_FORMAT_URI =
            "http://wso2.org/claims/division2";

    private static final String LOCAL_ADDRESS_CLAIM_URI = "http://wso2.org/claims/addresses";
    private static final String LOCAL_GROUPS_CLAIM_URI = "http://wso2.org/claims/groups";

    // OIDC Claims
    private static final String EMAIL = "email";
    private static final String USERNAME = "username";
    private static final String ROLE = "role";

    private static final String ADDRESS_COUNTRY = "address.country";
    private static final String ADDRESS_STREET = "address.street";
    private static final String ADDRESS_PROVINCE = "address.province";

    private static final String COUNTRY = "country";
    private static final String STREET = "street";
    private static final String PROVINCE = "province";
    private static final String DIVISION = "division";
    private static final String DIVISION_WITH_DOT = "org.division";
    private static final String DIVISION_WITH_DOT_IN_URL = "http://wso2.com.division";
    private static final String ADDRESS = "address";
    private static final String GROUPS = "groups";

    private static final String ROLE1 = "role1";
    private static final String ROLE2 = "role2";
    private static final String ROLE3 = "role3";
    private static final String ROLE_CLAIM_DEFAULT_VALUE =
            ROLE1 + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + ROLE2 + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + ROLE3;
    private static final String ROLE_CLAIM_DEFAULT_VALUE_WITH_DOMAIN =
            "Secondary/role1" + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + "Secondary/role2";

    private static final String SP_ROLE_2 = "SP_ROLE2";

    private static final ClaimMapping[] DEFAULT_REQUESTED_CLAIMS = {
            ClaimMapping.build(LOCAL_EMAIL_CLAIM_URI, EMAIL, "", true),
            ClaimMapping.build(LOCAL_USERNAME_CLAIM_URI, USERNAME, "", true),
            ClaimMapping.build(LOCAL_ROLE_CLAIM_URI, ROLE, "", true)
    };

    private static final Map<String, String> USER_CLAIMS_MAP = new HashMap<String, String>() {{
        put(LOCAL_EMAIL_CLAIM_URI, "peter@example.com");
        put(LOCAL_USERNAME_CLAIM_URI, USER_NAME);
        put(LOCAL_ROLE_CLAIM_URI, ROLE_CLAIM_DEFAULT_VALUE);
    }};

    private static final Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandlerTest.class);
    private static final Map<String, String> USER_CLAIMS_MAP_WITH_SECONDARY_ROLES = new HashMap<String, String>() {{
        put(LOCAL_EMAIL_CLAIM_URI, "john@example.com");
        put(LOCAL_USERNAME_CLAIM_URI, "john");
        put(LOCAL_ROLE_CLAIM_URI, ROLE_CLAIM_DEFAULT_VALUE_WITH_DOMAIN);
    }};

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT_NAME = "dbScripts/identity.sql";
    public static final String H2_SCRIPT2_NAME = "dbScripts/insert_scope_claim.sql";
    Connection connection = null;

    private MockedStatic<FrameworkUtils> frameworkUtils;
    @Mock
    ClaimMetadataHandler mockClaimMetadataHandler;

    @BeforeClass
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

        RequestObjectService requestObjectService = Mockito.mock(RequestObjectService.class);
        List<RequestedClaim> requestedClaims = Collections.emptyList();
        when(requestObjectService.getRequestedClaimsForIDToken(anyString())).
                thenReturn(requestedClaims);
        when(requestObjectService.getRequestedClaimsForUserInfo(anyString())).
                thenReturn(requestedClaims);

        // Skipping filtering with user consent.
        // TODO: Remove mocking claims filtering based on consent when fixing
        // https://github.com/wso2/product-is/issues/2676
        OpenIDConnectClaimFilterImpl openIDConnectClaimFilter = spy(new OpenIDConnectClaimFilterImpl());
        when(openIDConnectClaimFilter
                .getClaimsFilteredByUserConsent(anyMap(), any(AuthenticatedUser.class), anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArguments()[0]);
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters().add(openIDConnectClaimFilter);

        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
        ScopeClaimMappingDAOImpl scopeClaimMappingDAO = new ScopeClaimMappingDAOImpl();
        OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(scopeClaimMappingDAO);
        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class, Mockito.CALLS_REAL_METHODS)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(anyString()))
                    .thenAnswer((Answer<Void>) invocation -> null);
            setPrivateField(OAuthTokenPersistenceFactory.getInstance(), "scopeClaimMappingDAO",
                    new CacheBackedScopeClaimMappingDAOImpl());
        }
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        privilegedCarbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
        privilegedCarbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);
        applicationManagementService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        PrivilegedCarbonContext.endTenantFlow();
        if (connection != null) {
            connection.close();
        }
        frameworkUtils.close();
    }

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

    /**
     * Service provider not available for client_id. Therefore no custom claims will be set.
     */
    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoValidSp() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    /**
     * No requested claims configured for Service Provider.
     */
    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoSpRequestedClaims() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            when(FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()).thenReturn(true);

            JWTClaimsSet jwtClaimsSet =
                    getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                            oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    private ServiceProvider getSpWithDefaultRequestedClaimsMappings() {

        return getSpWithRequestedClaimsMappings(DEFAULT_REQUESTED_CLAIMS);
    }

    private ServiceProvider getSpWithRequestedClaimsMappings(ClaimMapping[] claimMappings) {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
        serviceProvider.setTenantDomain(TENANT_DOMAIN);

        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimMappings(claimMappings);
        serviceProvider.setClaimConfig(claimConfig);

        PermissionsAndRoleConfig permissionsAndRoleConfig = new PermissionsAndRoleConfig();
        serviceProvider.setPermissionAndRoleConfig(permissionsAndRoleConfig);

        return serviceProvider;
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoRealmFound() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
            mockApplicationManagementService(serviceProvider);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoUserClaims() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = mock(UserRealm.class);
            when(userRealm.getUserStoreManager()).thenReturn(mock(UserStoreManager.class));

            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtUserNotFoundInUserStore() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            when(FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()).thenReturn(true);

            UserRealm userRealm = getExceptionThrowingUserRealm(new UserStoreException(USER_NOT_FOUND));
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtUserStoreException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            when(FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()).thenReturn(true);

            UserRealm userRealm = getExceptionThrowingUserRealm(new UserStoreException(""));
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    @Test(description = "This method tests the handle custom claims when there is no user attributes in cache but "
            + "with attributes in authenticated user")
    public void testHandleCustomClaimsWithoutClaimsInUserAttributes() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class);) {
            // Create a token request with User Attributes.
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            Map<ClaimMapping, String> userAttributes = new HashMap<>();
            userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(COUNTRY), TestConstants.CLAIM_VALUE1);
            userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(EMAIL), TestConstants.CLAIM_VALUE2);
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForFederatedUser(userAttributes);
            getUserClaimsMap(claimMetadataHandler);

            // Mock to return all the scopes when the consent is asked for.
            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);
            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet, "JWT Custom claim handling failed.");
            assertFalse(jwtClaimsSet.getClaims().isEmpty(), "JWT custom claim handling failed");
            Assert.assertEquals(jwtClaimsSet.getClaims().size(), 3,
                    "Expected custom claims are not set.");
            Assert.assertEquals(jwtClaimsSet.getClaim(EMAIL), TestConstants.CLAIM_VALUE2,
                    "OIDC claim " + EMAIL + " is not added with the JWT token");
        }
    }

    @Test(description = "This method tests the handle custom claims when there is no user attributes in cache as well"
            + " as in authenticates user object")
    public void testHandleCustomClaimsWithoutClaimsInRefreshFlow() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class);) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForFederatedUser(null);
            // Add the relevant oidc claims to scope resource.
            Properties oidcProperties = new Properties();
            String[] oidcScopeClaims = new String[]{USERNAME, EMAIL};
            oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));

            Map<ClaimMapping, String> userAttributes = new HashMap<>();
            userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(USERNAME), TestConstants.CLAIM_VALUE1);
            userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(EMAIL), TestConstants.CLAIM_VALUE2);
            userAttributes
                    .put(SAML2BearerGrantHandlerTest.buildClaimMapping(PHONE_NUMBER_VERIFIED),
                            TestConstants.CLAIM_VALUE2);

            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    new AuthorizationGrantCacheEntry(userAttributes);
            authorizationGrantCacheEntry.setSubjectClaim(requestMsgCtx.getAuthorizedUser().getUserName());
            mockAuthorizationGrantCache(authorizationGrantCacheEntry, authorizationGrantCache);
            getUserClaimsMap(claimMetadataHandler);

            RefreshTokenValidationDataDO refreshTokenValidationDataDO =
                    Mockito.mock(RefreshTokenValidationDataDO.class);
            Mockito.doReturn(SAMPLE_ACCESS_TOKEN).when(refreshTokenValidationDataDO).getAccessToken();
            requestMsgCtx.addProperty(PREV_ACCESS_TOKEN, refreshTokenValidationDataDO);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);
            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);

            Assert.assertFalse(jwtClaimsSet.getClaims().isEmpty(),
                    "JWT custom claim list is empty. Custom claim handling failed in refresh flow");
            Assert.assertEquals(jwtClaimsSet.getClaim(USERNAME), TestConstants.CLAIM_VALUE1,
                    "Incomplete list of custom claims returned.");

            jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            DefaultOIDCClaimsCallbackHandler mockDefaultOIDCClaimsCallbackHandler =
                    spy(new DefaultOIDCClaimsCallbackHandler());
            jwtClaimsSet = mockDefaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder, requestMsgCtx);

            Assert.assertFalse(jwtClaimsSet.getClaims().isEmpty(),
                    "JWT custom claim list is empty. Custom claim handling failed in refresh flow");
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtEmptyUserClaims() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(Collections.emptyMap());
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoOIDCScopes() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            String[] arr = new String[1];
            arr[0] = "test";
            requestMsgCtx.setScope(arr);
            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getClaims().isEmpty());
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithOIDCScopes() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim("username"));
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithRoleDomainRemoved() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class,
                Mockito.CALLS_REAL_METHODS);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);
            LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                    new LocalAndOutboundAuthenticationConfig();
            // Enable user store domain removal for roles
            localAndOutboundAuthenticationConfig.setUseUserstoreDomainInRoles(false);
            serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP_WITH_SECONDARY_ROLES);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim("username"));
            assertEquals(jwtClaimsSet.getStringArrayClaim("role")[0], "role1");
            assertEquals(jwtClaimsSet.getStringArrayClaim("role")[1], "role2");
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithSpRoleMappings() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            // Add a SP role mapping
            RoleMapping[] roleMappings = new RoleMapping[]{
                    new RoleMapping(new LocalRole(USER_STORE_DOMAIN, ROLE2), SP_ROLE_2),
            };
            serviceProvider.getPermissionAndRoleConfig().setRoleMappings(roleMappings);
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            // Define OIDC Scope property
            Properties oidcProperties = new Properties();
            String[] oidcScopeClaims = new String[]{ROLE, USERNAME};
            oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);

            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim(EMAIL));
            assertNotNull(jwtClaimsSet.getClaim(USERNAME));
            assertEquals(jwtClaimsSet.getClaim(USERNAME), USER_NAME);

            assertNotNull(jwtClaimsSet.getClaim(ROLE));
            JSONArray jsonArray = (JSONArray) jwtClaimsSet.getClaim(ROLE);
            String[] expectedRoles = new String[]{ROLE1, SP_ROLE_2, ROLE3};
            for (String role : expectedRoles) {
                assertTrue(jsonArray.contains(role));
            }
        }
    }

    @DataProvider(name = "customSpecialClaimsProvider")
    public Object[][] provideCustomSpecialClaims() {

        return new Object[][]{
                {new String[]{"12343454", "false", "true"}},
                {new String[]{"2017-12-06T16:52:12", "false", "true"}}
        };
    }

    @Test(dataProvider = "customSpecialClaimsProvider")
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithSpecialFormattedClaims(String[] customClaims)
            throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
            requestMsgCtx.setScope(new String[]{OIDC_SCOPE});

            ClaimMapping claimMappings[] = new ClaimMapping[]{
                    ClaimMapping.build(LOCAL_UPDATED_AT_CLAIM_URI, UPDATED_AT, "", true),
                    ClaimMapping.build(LOCAL_EMAIL_VERIFIED_CLAIM_URI, EMAIL_VERIFIED, "", true),
                    ClaimMapping.build(LOCAL_PHONE_VERIFIED_CLAIM_URI, PHONE_NUMBER_VERIFIED, "", true),
                    ClaimMapping.build(LOCAL_COUNTRY_CLAIM_URI, ADDRESS_COUNTRY, "", true),
                    ClaimMapping.build(LOCAL_STREET_CLAIM_URI, ADDRESS_STREET, "", true),
                    ClaimMapping.build(LOCAL_PROVINCE_CLAIM_URI, ADDRESS_PROVINCE, "", true),
            };

            ServiceProvider serviceProvider = getSpWithRequestedClaimsMappings(claimMappings);
            mockApplicationManagementService(serviceProvider);

            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(LOCAL_UPDATED_AT_CLAIM_URI, customClaims[0]);
            userClaims.put(LOCAL_EMAIL_VERIFIED_CLAIM_URI, customClaims[1]);
            userClaims.put(LOCAL_PHONE_VERIFIED_CLAIM_URI, customClaims[2]);

            UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim(UPDATED_AT));
            assertTrue(jwtClaimsSet.getClaim(UPDATED_AT) instanceof Integer ||
                    jwtClaimsSet.getClaim(UPDATED_AT) instanceof Long);

            assertNotNull(jwtClaimsSet.getClaim(PHONE_NUMBER_VERIFIED));
            assertTrue(jwtClaimsSet.getClaim(PHONE_NUMBER_VERIFIED) instanceof Boolean);

            assertNotNull(jwtClaimsSet.getClaim(EMAIL_VERIFIED));
            assertTrue(jwtClaimsSet.getClaim(EMAIL_VERIFIED) instanceof Boolean);
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtAddressClaim() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ClaimMapping claimMappings[] = new ClaimMapping[]{
                    ClaimMapping.build(LOCAL_COUNTRY_CLAIM_URI, ADDRESS, "", true),
                    ClaimMapping.build(LOCAL_STREET_CLAIM_URI, STREET, "", true),
                    ClaimMapping.build(LOCAL_PROVINCE_CLAIM_URI, PROVINCE, "", true),
                    ClaimMapping.build(LOCAL_ADDRESS_CLAIM_URI, ADDRESS, "", true),
            };

            ServiceProvider serviceProvider = getSpWithRequestedClaimsMappings(claimMappings);
            mockApplicationManagementService(serviceProvider);

            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(LOCAL_COUNTRY_CLAIM_URI, "Sri Lanka");
            userClaims.put(LOCAL_STREET_CLAIM_URI, "Lily Avenue");
            userClaims.put(LOCAL_PROVINCE_CLAIM_URI, "Western");
            userClaims.put(LOCAL_ADDRESS_CLAIM_URI, "matara");

            UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);

            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim(ADDRESS));
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtGroupsClaim() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();
            requestMsgCtx.setScope(new String[]{OIDC_SCOPE, GROUPS});

            ClaimMapping claimMappings[] = new ClaimMapping[]{
                    ClaimMapping.build(LOCAL_GROUPS_CLAIM_URI, GROUPS, "", true),
            };

            ServiceProvider serviceProvider = getSpWithRequestedClaimsMappings(claimMappings);
            mockApplicationManagementService(serviceProvider);

            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(LOCAL_GROUPS_CLAIM_URI, "groups1");

            UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);

            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim(GROUPS));
            assertTrue(jwtClaimsSet.getClaim(GROUPS) instanceof JSONArray);
        }
    }

    private void getUserClaimsMap(MockedStatic<ClaimMetadataHandler> claimMetadataHandler)
            throws Exception {

        Map<String, String> claimMappings = new HashMap<>();
        claimMappings.put(EMAIL, LOCAL_EMAIL_CLAIM_URI);
        claimMappings.put(USERNAME, LOCAL_USERNAME_CLAIM_URI);
        claimMappings.put(ROLE, LOCAL_ROLE_CLAIM_URI);
        claimMappings.put(UPDATED_AT, LOCAL_UPDATED_AT_CLAIM_URI);
        claimMappings.put(EMAIL_VERIFIED, LOCAL_EMAIL_VERIFIED_CLAIM_URI);
        claimMappings.put(PHONE_NUMBER_VERIFIED, LOCAL_PHONE_VERIFIED_CLAIM_URI);
        claimMappings.put(STREET, LOCAL_STREET_CLAIM_URI);
        claimMappings.put(PROVINCE, LOCAL_PROVINCE_CLAIM_URI);
        claimMappings.put(COUNTRY, LOCAL_COUNTRY_CLAIM_URI);
        claimMappings.put(DIVISION, LOCAL_DIVISION_CLAIM_URI);
        claimMappings.put(DIVISION_WITH_DOT, LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_URI);
        claimMappings.put(GROUPS, LOCAL_GROUPS_CLAIM_URI);
        claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
        lenient().when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(anyString(), isNull(),
                anyString(), anyBoolean())).thenReturn(claimMappings);
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

    private void mockUserRealm(String username, UserRealm userRealm,
                               MockedStatic<IdentityTenantUtil> identityTenantUtil) throws IdentityException {

        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(TENANT_DOMAIN, username)).thenReturn(userRealm);
    }

    private UserRealm getExceptionThrowingUserRealm(UserStoreException e) throws UserStoreException {

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        when(userStoreManager.getUserClaimValues(eq(TENANT_AWARE_USERNAME), any(), eq(null)))
                .thenThrow(e);

        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        return userRealm;
    }

    private UserRealm getUserRealmWithUserClaims(Map<String, String> userClaims) throws UserStoreException {

        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        lenient().when(userStoreManager.getUserClaimValues(eq(TENANT_AWARE_USERNAME), any(), eq(null)))
                .thenReturn(userClaims);

        UserRealm userRealm = mock(UserRealm.class);
        lenient().when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        return userRealm;
    }

    private OAuthTokenReqMessageContext getTokenReqMessageContextForLocalUser() {

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setTenantDomain(TENANT_DOMAIN);
        accessTokenReqDTO.setClientId(DUMMY_CLIENT_ID);

        OAuthTokenReqMessageContext requestMsgCtx = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        requestMsgCtx.setScope(APPROVED_SCOPES);
        requestMsgCtx.setAuthorizedUser(getDefaultAuthenticatedLocalUser());
        return requestMsgCtx;
    }

    /**
     * To get token request message context for federates user.
     *
     * @param userAttributes Relevant user attributes need to be added to authenticates user.
     * @return relevant token request context for federated authenticated user.
     */
    private OAuthTokenReqMessageContext getTokenReqMessageContextForFederatedUser(Map<ClaimMapping,
            String> userAttributes) {

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setTenantDomain(TENANT_DOMAIN);
        accessTokenReqDTO.setClientId(DUMMY_CLIENT_ID);
        OAuthTokenReqMessageContext requestMsgCtx = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        requestMsgCtx.setScope(APPROVED_SCOPES);
        requestMsgCtx.addProperty(MultitenantConstants.TENANT_DOMAIN, TENANT_DOMAIN);
        AuthenticatedUser authenticatedUser = getDefaultAuthenticatedUserFederatedUser();

        if (userAttributes != null) {
            authenticatedUser.setUserAttributes(userAttributes);
        }
        requestMsgCtx.setAuthorizedUser(authenticatedUser);
        return requestMsgCtx;
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContext() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);) {
            PrivilegedCarbonContext.startTenantFlow();

            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = mock(OAuthAuthzReqMessageContext.class);
            when(oAuthAuthzReqMessageContext.getApprovedScope()).thenReturn(APPROVED_SCOPES);
            when(oAuthAuthzReqMessageContext.getProperty(OAuthConstants.ACCESS_TOKEN))
                    .thenReturn(SAMPLE_ACCESS_TOKEN);

            mockAuthorizationGrantCache(null, authorizationGrantCache);

            OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
            when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
            oAuth2AuthorizeReqDTO.setConsumerKey(DUMMY_CLIENT_ID);
            oAuth2AuthorizeReqDTO.setTenantDomain(TENANT_DOMAIN);

            AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
            oAuth2AuthorizeReqDTO.setUser(authenticatedUser);
            when(authenticatedUser.isFederatedUser()).thenReturn(true);

            JWTClaimsSet jwtClaimsSet =
                    getJwtClaimSet(jwtClaimsSetBuilder, oAuthAuthzReqMessageContext, jdbcPersistenceManager,
                            oAuthServerConfiguration);
            assertEquals(jwtClaimsSet.getClaims().size(), 0, "Claims are not successfully set.");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void mockAuthorizationGrantCache(AuthorizationGrantCacheEntry authorizationGrantCacheEntry,
                                             MockedStatic<AuthorizationGrantCache> authorizationGrantCache) {

        AuthorizationGrantCache mockAuthorizationGrantCache = mock(AuthorizationGrantCache.class);

        if (authorizationGrantCacheEntry == null) {
            authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);
        }
        authorizationGrantCache.when(AuthorizationGrantCache::getInstance).thenReturn(mockAuthorizationGrantCache);
        lenient().when(mockAuthorizationGrantCache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);
        lenient().when(mockAuthorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContextWithNullAssertion() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                mockStatic(AuthorizationGrantCache.class);) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = mock(OAuthTokenReqMessageContext.class);

            when(requestMsgCtx.getScope()).thenReturn(APPROVED_SCOPES);
            when(requestMsgCtx.getProperty(OAuthConstants.ACCESS_TOKEN)).thenReturn(SAMPLE_ACCESS_TOKEN);
            when(requestMsgCtx.getProperty(AccessTokenIssuer.OAUTH_APP_DO)).thenReturn(null);
            when(requestMsgCtx.getProperty(OAuthConstants.AUTHZ_CODE)).thenReturn(null);
            when(requestMsgCtx.getProperty("device_code")).thenReturn(null);
            when(requestMsgCtx.getProperty("previousAccessToken")).thenReturn(null);
            when(requestMsgCtx.getProperty("tenantDomain")).thenReturn(null);
            when(requestMsgCtx.getProperty("hasNonOIDCClaims")).thenReturn(null);

            mockAuthorizationGrantCache(null, authorizationGrantCache);

            AuthenticatedUser user = mock(AuthenticatedUser.class);
            when(requestMsgCtx.getAuthorizedUser()).thenReturn(user);
            when(user.isFederatedUser()).thenReturn(false);

            OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
            when(requestMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
            when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
            when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(DUMMY_CLIENT_ID);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertEquals(jwtClaimsSet.getClaims().size(), 0, "Claims are not successfully set.");
        }
    }

    private void mockApplicationManagementService(ServiceProvider sp) throws Exception {

        when(applicationManagementService.getApplicationExcludingFileBasedSPs(sp.getApplicationName(), TENANT_DOMAIN))
                .thenReturn(sp);
        when(applicationManagementService.getServiceProviderNameByClientId(anyString(), anyString(), anyString()))
                .thenReturn(SERVICE_PROVIDER_NAME);
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContextNullAccessToken() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();

            AuthenticatedUser authenticatedUser = getDefaultAuthenticatedUserFederatedUser();
            OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
            authorizeReqDTO.setUser(authenticatedUser);
            authorizeReqDTO.setTenantDomain(TENANT_DOMAIN);
            authorizeReqDTO.setConsumerKey(DUMMY_CLIENT_ID);

            OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(authorizeReqDTO);
            authzReqMessageContext.setApprovedScope(APPROVED_SCOPES);

            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
            ClaimMapping claimMap1 =
                    ClaimMapping.build("http://www.wso2.org/claims/email", "email", "sample@abc.com", true);
            ClaimMapping claimMap2 =
                    ClaimMapping.build("http://www.wso2.org/claims/username", "username", "user123", true);

            ClaimMapping[] requestedLocalClaimMap = {claimMap1, claimMap2};

            ClaimConfig claimConfig = new ClaimConfig();
            claimConfig.setClaimMappings(requestedLocalClaimMap);
            serviceProvider.setClaimConfig(claimConfig);
            serviceProvider.setSpProperties(new ServiceProviderProperty[]{});

            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);

            mockApplicationManagementService(serviceProvider);
            DefaultOIDCClaimsCallbackHandler mockDefaultOIDCClaimsCallbackHandler =
                    spy(new DefaultOIDCClaimsCallbackHandler());
            JWTClaimsSet jwtClaimsSet = mockDefaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder,
                    authzReqMessageContext);
            assertEquals(jwtClaimsSet.getClaims().size(), 0, "Claims are not successfully set.");
        }
    }

    @Test()
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithPunctuationMarkInOIDCClaim()
            throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {
            getUserClaimsMap(claimMetadataHandler);
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ClaimMapping[] claimMappings = new ClaimMapping[]{
                    ClaimMapping.build(LOCAL_DIVISION_CLAIM_URI, DIVISION, "", true),
                    ClaimMapping.build(LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_URI, DIVISION_WITH_DOT, "", true),
                    ClaimMapping.build(LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_IN_URL_FORMAT_URI,
                            DIVISION_WITH_DOT_IN_URL, "", true),
                    ClaimMapping.build(LOCAL_COUNTRY_CLAIM_URI, ADDRESS_COUNTRY, "", true)
            };

            ServiceProvider serviceProvider = getSpWithRequestedClaimsMappings(claimMappings);
            mockApplicationManagementService(serviceProvider);

            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(LOCAL_DIVISION_CLAIM_URI, "Division 01");
            userClaims.put(LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_URI, "Division 02");
            userClaims.put(LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_IN_URL_FORMAT_URI, "Division 03");
            userClaims.put(LOCAL_COUNTRY_CLAIM_URI, "LK");

            UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);

            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getClaim(DIVISION_WITH_DOT));
        }

    }

    @Test
    public void testHandleClaimsForOAuthTokenReqMessageContextWithAuthorizationCode() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                mockStatic(AuthorizationGrantCache.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class);) {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            Map<ClaimMapping, String> userAttributes = new HashMap<>();
            userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(COUNTRY), TestConstants.CLAIM_VALUE1);
            userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(EMAIL), TestConstants.CLAIM_VALUE2);
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForFederatedUser(userAttributes);
            requestMsgCtx.addProperty("AuthorizationCode", "dummyAuthorizationCode");

            AuthorizationGrantCacheEntry authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);
            mockAuthorizationGrantCache(authorizationGrantCacheEntry, authorizationGrantCache);
            getUserClaimsMap(claimMetadataHandler);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm, identityTenantUtil);
            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                    oAuthServerConfiguration);
            assertNotNull(jwtClaimsSet, "JWT Custom claim handling failed.");
            assertFalse(jwtClaimsSet.getClaims().isEmpty(), "JWT custom claim handling failed");
            Assert.assertEquals(jwtClaimsSet.getClaims().size(), 3,
                    "Expected custom claims are not set.");
            Assert.assertEquals(jwtClaimsSet.getClaim(EMAIL), TestConstants.CLAIM_VALUE2,
                    "OIDC claim " + EMAIL + " is not added with the JWT token");
        }
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

    private AuthenticatedUser getDefaultAuthenticatedUserFederatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setUserId(StringUtils.EMPTY);
        authenticatedUser.setFederatedUser(true);
        return authenticatedUser;
    }

    private JWTClaimsSet getJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                        OAuthTokenReqMessageContext requestMsgCtx,
                                        MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws IdentityOAuth2Exception {

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        DataSource dataSource = mock(DataSource.class);
        JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.isConvertOriginalClaimsFromAssertionsToOIDCDialect()).thenReturn(true);
        JWTClaimsSet jwtClaimsSet = null;

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

        DefaultOIDCClaimsCallbackHandler defaultOIDCClaimsCallbackHandler =
                new DefaultOIDCClaimsCallbackHandler();
        jwtClaimsSet = defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder, requestMsgCtx);

        return jwtClaimsSet;
    }

    private JWTClaimsSet getJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                        OAuthAuthzReqMessageContext requestMsgCtx,
                                        MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws IdentityOAuth2Exception {

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        DataSource dataSource = mock(DataSource.class);
        JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.isConvertOriginalClaimsFromAssertionsToOIDCDialect())
                .thenReturn(true);
        when(mockOAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);
        JWTClaimsSet jwtClaimsSet = null;
        try {

            lenient().when(dataSource.getConnection()).thenReturn(connection);
            jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
            lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
            DefaultOIDCClaimsCallbackHandler defaultOIDCClaimsCallbackHandler =
                    new DefaultOIDCClaimsCallbackHandler();
            jwtClaimsSet = defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder, requestMsgCtx);

        } catch (SQLException e) {
            log.error("Error while obtaining the datasource. ");
        }
        return jwtClaimsSet;
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }
}
