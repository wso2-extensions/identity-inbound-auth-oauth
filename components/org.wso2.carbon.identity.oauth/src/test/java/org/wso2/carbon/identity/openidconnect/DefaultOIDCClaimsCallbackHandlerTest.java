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
import org.mockito.Mockito;
import org.mockito.Spy;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.w3c.dom.Element;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.LocalRole;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2BearerGrantHandlerTest;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.sql.DataSource;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
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
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getConnection;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.initiateH2Base;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;

/**
 * Class which tests SAMLAssertionClaimsCallback.
 */
@PowerMockIgnore({"javax.xml.*", "org.w3c.*"})
@PrepareForTest({
        AuthorizationGrantCache.class,
        IdentityTenantUtil.class,
        UserCoreUtil.class,
        FrameworkUtils.class,
        JDBCPersistenceManager.class,
        OAuthServerConfiguration.class
})
public class DefaultOIDCClaimsCallbackHandlerTest {

    @Spy
    private DefaultOIDCClaimsCallbackHandler defaultOIDCClaimsCallbackHandler;

    @Spy
    private AuthorizationGrantCache authorizationGrantCache;

    @Mock
    private ApplicationManagementService applicationManagementService;

    private static final String CUSTOM_ATTRIBUTE_NAME = "CustomAttributeName";

    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

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

    private static final String ROLE1 = "role1";
    private static final String ROLE2 = "role2";
    private static final String ROLE3 = "role3";
    private static final String ROLE_CLAIM_DEFAULT_VALUE =
            ROLE1 + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + ROLE2 + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + ROLE3;

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

    private final Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandlerTest.class);
    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT_NAME = "dbScripts/scope_claim.sql";
    Connection connection = null;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, CARBON_HOME);
        BasicDataSource dataSource1 = new BasicDataSource();
        dataSource1.setDriverClassName("org.h2.Driver");
        dataSource1.setUsername("username");
        dataSource1.setPassword("password");
        dataSource1.setUrl("jdbc:h2:mem:test" + DB_NAME);
        connection = dataSource1.getConnection();
        connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT_NAME) + "'");

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);

        RequestObjectService requestObjectService = Mockito.mock(RequestObjectService.class);
        List<RequestedClaim> requestedClaims = Collections.emptyList();
        when(requestObjectService.getRequestedClaimsForIDToken(anyString())).
                thenReturn(requestedClaims);
        when(requestObjectService.getRequestedClaimsForUserInfo(anyString())).
                thenReturn(requestedClaims);

        // Skipping filtering with user consent.
        // TODO: Remove mocking claims filtering based on consent when fixing https://github.com/wso2/product-is/issues/2676
        OpenIDConnectClaimFilterImpl openIDConnectClaimFilter = spy(new OpenIDConnectClaimFilterImpl());
        when(openIDConnectClaimFilter
                .getClaimsFilteredByUserConsent(anyMap(), any(AuthenticatedUser.class), anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArguments()[0]);
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters().add(openIDConnectClaimFilter);

        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
        defaultOIDCClaimsCallbackHandler = new DefaultOIDCClaimsCallbackHandler();

    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return DefaultOIDCClaimsCallbackHandlerTest.class.getClassLoader().getResource(fileName).getPath();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    /**
     * Service provider not available for client_id. Therefore no custom claims will be set.
     */
    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoValidSp() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
        mockApplicationManagementService();

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    /**
     * No requested claims configured for Service Provider.
     */
    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoSpRequestedClaims() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    private ServiceProvider getSpWithDefaultRequestedClaimsMappings() {

        return getSpWithRequestedClaimsMappings(DEFAULT_REQUESTED_CLAIMS);
    }

    private ServiceProvider getSpWithRequestedClaimsMappings(ClaimMapping[] claimMappings) {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);

        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimMappings(claimMappings);
        serviceProvider.setClaimConfig(claimConfig);

        PermissionsAndRoleConfig permissionsAndRoleConfig = new PermissionsAndRoleConfig();
        serviceProvider.setPermissionAndRoleConfig(permissionsAndRoleConfig);

        return serviceProvider;
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoRealmFound() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
        mockApplicationManagementService(serviceProvider);

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoUserClaims() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(mock(UserStoreManager.class));

        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtUserNotFoundInUserStore() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getExceptionThrowingUserRealm(new UserStoreException(USER_NOT_FOUND));
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtUserStoreException() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getExceptionThrowingUserRealm(new UserStoreException(""));
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    @Test(description = "This method tests the handle custom claims when there is no user attributes in cache but "
            + "with attributes in authenticated user")
    public void testHandleCustomClaimsWithoutClaimsInUserAttributes() throws Exception {

        // Create a token request with User Attributes.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(COUNTRY), TestConstants.CLAIM_VALUE1);
        userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(EMAIL), TestConstants.CLAIM_VALUE2);
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForFederatedUser(userAttributes);

        // Mock to return all the scopes when the consent is asked for.
        UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);
        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet, "JWT Custom claim handling failed.");
        assertFalse(jwtClaimsSet.getClaims().isEmpty(), "JWT custom claim handling failed");
        Assert.assertEquals(jwtClaimsSet.getClaims().size(), 3,
                "Expected custom claims are not set.");
        Assert.assertEquals(jwtClaimsSet.getClaim(EMAIL), TestConstants.CLAIM_VALUE2,
                "OIDC claim " + EMAIL + " is not added with the JWT token");
    }

    @Test(description = "This method tests the handle custom claims when there is no user attributes in cache as well"
            + " as in authenticates user object")
    public void testHandleCustomClaimsWithoutClaimsInRefreshFlow() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForFederatedUser(null);
        // Add the relevant oidc claims to scop resource.
        Properties oidcProperties = new Properties();
        String[] oidcScopeClaims = new String[]{USERNAME, EMAIL};
        oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(USERNAME), TestConstants.CLAIM_VALUE1);
        userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping(EMAIL), TestConstants.CLAIM_VALUE2);
        userAttributes
                .put(SAML2BearerGrantHandlerTest.buildClaimMapping(PHONE_NUMBER_VERIFIED), TestConstants.CLAIM_VALUE2);

        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);
        authorizationGrantCacheEntry.setSubjectClaim(requestMsgCtx.getAuthorizedUser().getUserName());
        mockAuthorizationGrantCache(authorizationGrantCacheEntry);

        RefreshTokenValidationDataDO refreshTokenValidationDataDO = Mockito.mock(RefreshTokenValidationDataDO.class);
        Mockito.doReturn(SAMPLE_ACCESS_TOKEN).when(refreshTokenValidationDataDO).getAccessToken();
        requestMsgCtx.addProperty(PREV_ACCESS_TOKEN, refreshTokenValidationDataDO);

        UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);
        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);

        Assert.assertFalse(jwtClaimsSet.getClaims().isEmpty(),
                "JWT custom claim list is empty. Custom claim handling failed in refresh flow");
        Assert.assertEquals(jwtClaimsSet.getClaim(USERNAME), TestConstants.CLAIM_VALUE1,
                "Incomplete list of custom claims returned.");

        jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSet = defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder, requestMsgCtx);

        Assert.assertFalse(jwtClaimsSet.getClaims().isEmpty(),
                "JWT custom claim list is empty. Custom claim handling failed in refresh flow");
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtEmptyUserClaims() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getUserRealmWithUserClaims(Collections.emptyMap());
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoOIDCScopes() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        mockClaimHandler();
        String[] arr = new String[1];
        arr[0] = "test";
        requestMsgCtx.setScope(arr);
        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithOIDCScopes() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        mockClaimHandler();

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertNotNull(jwtClaimsSet.getClaim("username"));

    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithSpRoleMappings() throws Exception {

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
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        mockClaimHandler();

        // Define OIDC Scope property
        Properties oidcProperties = new Properties();
        String[] oidcScopeClaims = new String[]{ROLE, USERNAME};
        oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);

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
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        mockClaimHandler();

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertNotNull(jwtClaimsSet.getClaim(UPDATED_AT));
        assertTrue(jwtClaimsSet.getClaim(UPDATED_AT) instanceof Integer ||
                jwtClaimsSet.getClaim(UPDATED_AT) instanceof Long);

        assertNotNull(jwtClaimsSet.getClaim(PHONE_NUMBER_VERIFIED));
        assertTrue(jwtClaimsSet.getClaim(PHONE_NUMBER_VERIFIED) instanceof Boolean);

        assertNotNull(jwtClaimsSet.getClaim(EMAIL_VERIFIED));
        assertTrue(jwtClaimsSet.getClaim(EMAIL_VERIFIED) instanceof Boolean);
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtAddressClaim() throws Exception {

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
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);
        mockClaimHandler();

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);

        assertNotNull(jwtClaimsSet);
        assertNotNull(jwtClaimsSet.getClaim(ADDRESS));

    }

    private void mockClaimHandler() throws Exception {

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
        // claimMappings.put(DIVISION_WITH_DOT_IN_URL, LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_IN_URL_FORMAT_URI);

        ClaimMetadataHandler claimMetadataHandler = spy(ClaimMetadataHandler.class);
        doReturn(claimMappings).when(claimMetadataHandler).getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null,
                TENANT_DOMAIN, false);
        // Set Claim Handler instance
        setStaticField(ClaimMetadataHandler.class, "INSTANCE", claimMetadataHandler);
    }

    private void setStaticField(Class classname,
                                String fieldName,
                                Object value) throws NoSuchFieldException, IllegalAccessException {

        Field declaredField = classname.getDeclaredField(fieldName);
        declaredField.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(declaredField, declaredField.getModifiers() & ~Modifier.FINAL);

        declaredField.set(null, value);
    }

    private void mockUserRealm(String username, UserRealm userRealm) throws IdentityException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(IdentityTenantUtil.getRealm(TENANT_DOMAIN, username)).thenReturn(userRealm);
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
        when(userStoreManager.getUserClaimValues(eq(TENANT_AWARE_USERNAME), any(), eq(null))).thenReturn(userClaims);

        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
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
        AuthenticatedUser authenticatedUser = getDefaultAuthenticatedUserFederatedUser();

        if (userAttributes != null) {
            authenticatedUser.setUserAttributes(userAttributes);
        }
        requestMsgCtx.setAuthorizedUser(authenticatedUser);
        return requestMsgCtx;
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContext() throws Exception {

        try {
            PrivilegedCarbonContext.startTenantFlow();

            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = mock(OAuthAuthzReqMessageContext.class);
            when(oAuthAuthzReqMessageContext.getApprovedScope()).thenReturn(APPROVED_SCOPES);
            when(oAuthAuthzReqMessageContext.getProperty(OAuthConstants.ACCESS_TOKEN))
                    .thenReturn(SAMPLE_ACCESS_TOKEN);

            mockAuthorizationGrantCache(null);

            OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
            when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);

            AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
            oAuth2AuthorizeReqDTO.setUser(authenticatedUser);
            when(authenticatedUser.isFederatedUser()).thenReturn(true);

            JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, oAuthAuthzReqMessageContext);
            assertEquals(jwtClaimsSet.getClaims().size(), 0, "Claims are not successfully set.");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void mockAuthorizationGrantCache(AuthorizationGrantCacheEntry authorizationGrantCacheEntry) {

        mockStatic(AuthorizationGrantCache.class);
        authorizationGrantCache = mock(AuthorizationGrantCache.class);

        if (authorizationGrantCacheEntry == null) {
            authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);
        }
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);
        when(authorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContextWithNullAssertion() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = mock(OAuthTokenReqMessageContext.class);

        when(requestMsgCtx.getScope()).thenReturn(APPROVED_SCOPES);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(null);
        when(requestMsgCtx.getProperty(OAuthConstants.ACCESS_TOKEN)).thenReturn(SAMPLE_ACCESS_TOKEN);

        mockAuthorizationGrantCache(null);

        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(requestMsgCtx.getAuthorizedUser()).thenReturn(user);
        when(user.isFederatedUser()).thenReturn(false);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(requestMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(DUMMY_CLIENT_ID);

        mockApplicationManagementService();

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);
        assertEquals(jwtClaimsSet.getClaims().size(), 0, "Claims are not successfully set.");
    }

    private void mockApplicationManagementService() throws Exception {

        when(applicationManagementService.getServiceProviderNameByClientId(anyString(), anyString(), anyString()))
                .thenReturn(SERVICE_PROVIDER_NAME);
        setStaticField(OAuth2ServiceComponentHolder.class, "applicationMgtService", applicationManagementService);
    }

    private void mockApplicationManagementService(ServiceProvider sp) throws Exception {

        mockApplicationManagementService();
        when(applicationManagementService.getApplicationExcludingFileBasedSPs(sp.getApplicationName(), TENANT_DOMAIN))
                .thenReturn(sp);
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContextNullAccessToken() throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();

        AuthenticatedUser authenticatedUser = getDefaultAuthenticatedUserFederatedUser();
        OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
        authorizeReqDTO.setUser(authenticatedUser);

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

        mockApplicationManagementService(serviceProvider);

        JWTClaimsSet jwtClaimsSet = defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder,
                authzReqMessageContext);
        assertEquals(jwtClaimsSet.getClaims().size(), 0, "Claims are not successfully set.");
    }

    @Test()
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithPunctuationMarkInOIDCClaim()
            throws Exception {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ClaimMapping claimMappings[] = new ClaimMapping[]{
                ClaimMapping.build(LOCAL_DIVISION_CLAIM_URI, DIVISION, "", true),
                ClaimMapping.build(LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_URI, DIVISION_WITH_DOT, "", true),
                ClaimMapping.build(LOCAL_DIVISION_CLAIM_WITH_PUNCUTATIONMARK_IN_URL_FORMAT_URI, DIVISION_WITH_DOT_IN_URL, "",
                        true),
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
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);
        mockClaimHandler();

        JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx);

        assertNotNull(jwtClaimsSet);
        assertNotNull(jwtClaimsSet.getClaim(DIVISION_WITH_DOT));
        //assertNotNull(jwtClaimsSet.getClaim(DIVISION_WITH_DOT_IN_URL));

    }

    private AuthenticatedUser getDefaultAuthenticatedLocalUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN);
        authenticatedUser.setFederatedUser(false);
        return authenticatedUser;
    }

    private AuthenticatedUser getDefaultAuthenticatedUserFederatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setFederatedUser(true);
        return authenticatedUser;
    }

    private Attribute buildAttribute(String attributeName, String[] attributeValues) throws ConfigurationException {

        Attribute attribute = new AttributeBuilder().buildObject(Attribute.DEFAULT_ELEMENT_NAME);
        attribute.setName(attributeName);

        for (String attributeValue : attributeValues) {
            // Build an attribute value object.
            Element element = mock(Element.class);
            when(element.getTextContent()).thenReturn(attributeValue);

            XMLObject attributeValueObject = mock(XMLObject.class);
            when(attributeValueObject.getDOM()).thenReturn(element);

            attribute.getAttributeValues().add(attributeValueObject);
        }

        return attribute;
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private JWTClaimsSet getJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthTokenReqMessageContext requestMsgCtx) {

        OAuthServerConfiguration mockOAuthServerConfiguration = PowerMockito.mock(OAuthServerConfiguration.class);
        DataSource dataSource = mock(DataSource.class);
        mockStatic(JDBCPersistenceManager.class);
        JDBCPersistenceManager jdbcPersistenceManager = mock(JDBCPersistenceManager.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
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
                Mockito.when(dataSource.getConnection()).thenReturn(connection1);

            } else {
                Mockito.when(dataSource.getConnection()).thenReturn(connection);
            }
        } catch (Exception e) {
            log.error("Error while obtaining the datasource. ");
        }

        Mockito.when(jdbcPersistenceManager.getInstance()).thenReturn(jdbcPersistenceManager);
        Mockito.when(jdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
        jwtClaimsSet = defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder,
                requestMsgCtx);

        //return jwtClaimsSet;

        return jwtClaimsSet;
    }

    private JWTClaimsSet getJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthAuthzReqMessageContext requestMsgCtx) {

        OAuthServerConfiguration mockOAuthServerConfiguration = PowerMockito.mock(OAuthServerConfiguration.class);
        DataSource dataSource = mock(DataSource.class);
        mockStatic(JDBCPersistenceManager.class);
        JDBCPersistenceManager jdbcPersistenceManager = mock(JDBCPersistenceManager.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.isConvertOriginalClaimsFromAssertionsToOIDCDialect()).thenReturn(true);
        JWTClaimsSet jwtClaimsSet = null;
        try {

            Mockito.when(dataSource.getConnection()).thenReturn(connection);
            Mockito.when(jdbcPersistenceManager.getInstance()).thenReturn(jdbcPersistenceManager);
            Mockito.when(jdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
            jwtClaimsSet = defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSetBuilder,
                    requestMsgCtx);

        } catch (SQLException e) {
            log.error("Error while obtaining the datasource. ");
        }
        return jwtClaimsSet;
    }
}