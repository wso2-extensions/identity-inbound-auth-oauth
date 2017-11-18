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
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.Spy;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.ResourceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
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
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.USER_NOT_FOUND;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.EMAIL_VERIFIED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.PHONE_NUMBER_VERIFIED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.UPDATED_AT;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;

/**
 * Class which tests SAMLAssertionClaimsCallback.
 */
@PowerMockIgnore({"javax.xml.*", "org.w3c.*"})
@PrepareForTest({
        AuthorizationGrantCache.class,
        IdentityTenantUtil.class,
        UserCoreUtil.class,
        FrameworkUtils.class
})
public class DefaultOIDCClaimsCallbackHandlerTest {

    @Spy
    private DefaultOIDCClaimsCallbackHandler defaultOIDCClaimsCallbackHandler;

    @Spy
    private AuthorizationGrantCache authorizationGrantCache;

    @Mock
    private Assertion assertion;

    @Mock
    private Subject mockSubject;

    @Mock
    private NameID nameID;

    @Mock
    private RegistryService registryService;

    @Mock
    private Resource resource;

    @Mock
    private UserRegistry userRegistry;

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

    @BeforeClass
    public void setUp() throws Exception {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, CARBON_HOME);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);

        OpenIDConnectServiceComponentHolder.getInstance()
                .getOpenIDConnectClaimFilters()
                .add(new OpenIDConnectClaimFilterImpl());

        defaultOIDCClaimsCallbackHandler = new DefaultOIDCClaimsCallbackHandler();
    }

    @DataProvider(name = "samlAttributeValueProvider")
    public Object[][] provideSamlAttributeValues() {
        return new Object[][]{
                // Empty attribute value
                {new String[]{""}, ""},
                // Single attribute value
                {new String[]{"value1"}, "value1"},
                // Multiple attribute values
                {new String[]{"value1", "value2"}, "value1" + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + "value2"},
                // Multiple attribute values with an empty value
                {new String[]{"value1", "", "value2"}, "value1" + MULTI_ATTRIBUTE_SEPARATOR_DEFAULT + "value2"}
        };
    }

    @Test(dataProvider = "samlAttributeValueProvider")
    public void testCustomClaimForOAuthTokenReqMessageContext(String[] attributeValues,
                                                              String expectedClaimValue) throws Exception {
        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        Assertion assertion = getAssertion(attributeValues);

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setClientId(DUMMY_CLIENT_ID);

        OAuthTokenReqMessageContext requestMsgCtx = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        requestMsgCtx.addProperty(OAuthConstants.OAUTH_SAML2_ASSERTION, assertion);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

        // Assert whether the custom attribute from SAML Assertion was set as a claim.
        assertFalse(jwtClaimsSet.getCustomClaims().isEmpty());
        assertNotNull(jwtClaimsSet.getCustomClaim(CUSTOM_ATTRIBUTE_NAME));
        // Assert whether multi value attribute values were joined correctly.
        assertEquals(jwtClaimsSet.getCustomClaim(CUSTOM_ATTRIBUTE_NAME), expectedClaimValue);
    }

    /**
     * Service provider not available for client_id. Therefore no custom claims will be set.
     */
    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoValidSp() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
        mockApplicationManagementService();

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
    }

    /**
     * No requested claims configured for Service Provider.
     */
    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoSpRequestedClaims() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
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
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER_NAME);
        mockApplicationManagementService(serviceProvider);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoUserClaims() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(mock(UserStoreManager.class));

        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtUserNotFoundInUserStore() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getExceptionThrowingUserRealm(new UserStoreException(USER_NOT_FOUND));
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtUserStoreException() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getExceptionThrowingUserRealm(new UserStoreException(""));
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtEmptyUserClaims() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

        ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
        mockApplicationManagementService(serviceProvider);

        UserRealm userRealm = getUserRealmWithUserClaims(Collections.emptyMap());
        mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertNotNull(jwtClaimsSet);
        assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtRegistryError() throws Exception {
        try {
            PrivilegedCarbonContext.startTenantFlow();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

            mockClaimHandler();

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtNoOIDCScopes() throws Exception {
        try {
            PrivilegedCarbonContext.startTenantFlow();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

            mockClaimHandler();
            mockOIDCScopeResource();

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
            assertNotNull(jwtClaimsSet);
            assertTrue(jwtClaimsSet.getCustomClaims().isEmpty());
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithOIDCScopes() throws Exception {
        try {
            PrivilegedCarbonContext.startTenantFlow();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ServiceProvider serviceProvider = getSpWithDefaultRequestedClaimsMappings();
            mockApplicationManagementService(serviceProvider);

            UserRealm userRealm = getUserRealmWithUserClaims(USER_CLAIMS_MAP);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

            mockClaimHandler();

            Properties oidcProperties = new Properties();
            String[] oidcScopeClaims = new String[]{ROLE, USERNAME};
            oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));
            mockOIDCScopeResource(oidcProperties);

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
            assertNotNull(jwtClaimsSet);
            assertNull(jwtClaimsSet.getCustomClaim(EMAIL));

            assertNotNull(jwtClaimsSet.getCustomClaim(USERNAME));
            assertEquals(jwtClaimsSet.getCustomClaim(USERNAME), USER_NAME);

            assertNotNull(jwtClaimsSet.getCustomClaim(ROLE));
            JSONArray jsonArray = (JSONArray) jwtClaimsSet.getCustomClaim(ROLE);
            String[] expectedRoles = new String[]{ROLE1, ROLE2, ROLE3};
            for (String role : expectedRoles) {
                assertTrue(jsonArray.contains(role));
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithSpRoleMappings() throws Exception {
        try {
            PrivilegedCarbonContext.startTenantFlow();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
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
            mockOIDCScopeResource(oidcProperties);

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

            assertNotNull(jwtClaimsSet);
            assertNull(jwtClaimsSet.getCustomClaim(EMAIL));
            assertNotNull(jwtClaimsSet.getCustomClaim(USERNAME));
            assertEquals(jwtClaimsSet.getCustomClaim(USERNAME), USER_NAME);

            assertNotNull(jwtClaimsSet.getCustomClaim(ROLE));
            JSONArray jsonArray = (JSONArray) jwtClaimsSet.getCustomClaim(ROLE);
            String[] expectedRoles = new String[]{ROLE1, SP_ROLE_2, ROLE3};
            for (String role : expectedRoles) {
                assertTrue(jsonArray.contains(role));
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtWithSpecialFormattedClaims() throws Exception {
        try {
            PrivilegedCarbonContext.startTenantFlow();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
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
            userClaims.put(LOCAL_UPDATED_AT_CLAIM_URI, "12343454");
            userClaims.put(LOCAL_EMAIL_VERIFIED_CLAIM_URI, "false");
            userClaims.put(LOCAL_PHONE_VERIFIED_CLAIM_URI, "true");

            UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);

            mockClaimHandler();

            // Define OIDC Scope properties
            Properties oidcProperties = new Properties();
            String[] oidcScopeClaims = new String[]{UPDATED_AT, PHONE_NUMBER_VERIFIED, EMAIL_VERIFIED};
            oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));
            mockOIDCScopeResource(oidcProperties);

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getCustomClaim(UPDATED_AT));
            assertTrue(jwtClaimsSet.getCustomClaim(UPDATED_AT) instanceof Integer ||
                    jwtClaimsSet.getCustomClaim(UPDATED_AT) instanceof Long);

            assertNotNull(jwtClaimsSet.getCustomClaim(PHONE_NUMBER_VERIFIED));
            assertTrue(jwtClaimsSet.getCustomClaim(PHONE_NUMBER_VERIFIED) instanceof Boolean);

            assertNotNull(jwtClaimsSet.getCustomClaim(EMAIL_VERIFIED));
            assertTrue(jwtClaimsSet.getCustomClaim(EMAIL_VERIFIED) instanceof Boolean);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @DataProvider(name = "addressClaimData")
    public Object[][] provideAddressClaimData() {
        Properties oidcProperties = new Properties();
        String[] oidcScopeClaims = new String[]{
                ADDRESS_COUNTRY, ADDRESS_PROVINCE, ADDRESS_STREET
        };

        oidcProperties.setProperty(OIDC_SCOPE, StringUtils.join(oidcScopeClaims, ","));

        Properties oidcPropertiesWithAddressScope = new Properties();
        String[] addressScopeClaims = new String[]{COUNTRY, PROVINCE, STREET};
        oidcPropertiesWithAddressScope.setProperty(OIDC_SCOPE, StringUtils.join(addressScopeClaims, ","));
        oidcPropertiesWithAddressScope.setProperty(ADDRESS, StringUtils.join(addressScopeClaims, ","));

        return new Object[][]{{oidcProperties}, {oidcPropertiesWithAddressScope}};
    }

    @Test(dataProvider = "addressClaimData")
    public void testHandleCustomClaimsWithOAuthTokenReqMsgCtxtAddressClaim(Properties oidcProperties) throws Exception {
        try {
            PrivilegedCarbonContext.startTenantFlow();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
            OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

            ClaimMapping claimMappings[] = new ClaimMapping[]{
                    ClaimMapping.build(LOCAL_COUNTRY_CLAIM_URI, ADDRESS, "", true),
                    ClaimMapping.build(LOCAL_STREET_CLAIM_URI, STREET, "", true),
                    ClaimMapping.build(LOCAL_PROVINCE_CLAIM_URI, PROVINCE, "", true),
            };

            ServiceProvider serviceProvider = getSpWithRequestedClaimsMappings(claimMappings);
            mockApplicationManagementService(serviceProvider);


            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(LOCAL_COUNTRY_CLAIM_URI, "Sri Lanka");
            userClaims.put(LOCAL_STREET_CLAIM_URI, "Lily Avenue");
            userClaims.put(LOCAL_PROVINCE_CLAIM_URI, "Western");

            UserRealm userRealm = getUserRealmWithUserClaims(userClaims);
            mockUserRealm(requestMsgCtx.getAuthorizedUser().toString(), userRealm);
            mockOIDCScopeResource(oidcProperties);
            mockClaimHandler();

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getCustomClaim(ADDRESS));

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
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

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContext() throws Exception {

        try {
            PrivilegedCarbonContext.startTenantFlow();

            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
            OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = mock(OAuthAuthzReqMessageContext.class);
            when(oAuthAuthzReqMessageContext.getApprovedScope()).thenReturn(APPROVED_SCOPES);
            when(oAuthAuthzReqMessageContext.getProperty(OAuthConstants.ACCESS_TOKEN))
                    .thenReturn(SAMPLE_ACCESS_TOKEN);

            mockAuthorizationGrantCache();

            OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
            when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);

            AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
            oAuth2AuthorizeReqDTO.setUser(authenticatedUser);
            when(authenticatedUser.isFederatedUser()).thenReturn(true);

            mockOIDCScopeResource();

            defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, oAuthAuthzReqMessageContext);
            assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void mockAuthorizationGrantCache() {
        mockStatic(AuthorizationGrantCache.class);
        authorizationGrantCache = mock(AuthorizationGrantCache.class);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);
    }

    private void mockOIDCScopeResource() throws Exception {
        when(registryService.getConfigSystemRegistry(TENANT_ID)).thenReturn(userRegistry);
        Resource resource = spy(new ResourceImpl());
        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);
        setRegistryMockService(registryService);
    }

    private void mockOIDCScopeResource(Properties properties) throws Exception {
        when(registryService.getConfigSystemRegistry(TENANT_ID)).thenReturn(userRegistry);
        Resource resource = spy(new ResourceImpl());
        for (Map.Entry<Object, Object> propertyEntry : properties.entrySet()) {
            resource.setProperty((String) propertyEntry.getKey(), (String) propertyEntry.getValue());
        }

        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);
        setRegistryMockService(registryService);
    }


    private void setRegistryMockService(RegistryService registryMockService) throws Exception {
        setStaticField(OAuth2ServiceComponentHolder.class, "registryService", registryMockService);
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContextWithNullAssertionSubject() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = mock(OAuthTokenReqMessageContext.class);

        mockSubject = mock(Subject.class);
        assertion = mock(Assertion.class);
        nameID = mock(NameID.class);
        when(assertion.getSubject()).thenReturn(mockSubject);
        when(mockSubject.getNameID()).thenReturn(nameID);
        when(nameID.getValue()).thenReturn(" C=US, O=NCSA-TEST, OU=User, CN=trscavo@uiuc.edu");

        AttributeStatement statement = mock(AttributeStatement.class);
        List<AttributeStatement> attributeStatementList = null;
        when(assertion.getAttributeStatements()).thenReturn(attributeStatementList);

        List<Attribute> attributesList = new ArrayList<>();
        Attribute attribute = new AttributeBuilder().buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                "Attribute", "saml2");
        XMLObject obj = mock(XMLObject.class);
        attribute.getAttributeValues().add(obj);

        Element ele = mock(Element.class);
        when(obj.getDOM()).thenReturn(ele);
        attributesList.add(attribute);
        when(statement.getAttributes()).thenReturn(attributesList);

        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(assertion);
        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContextWithNullAssertion() throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        OAuthTokenReqMessageContext requestMsgCtx = mock(OAuthTokenReqMessageContext.class);

        when(requestMsgCtx.getScope()).thenReturn(APPROVED_SCOPES);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(null);
        when(requestMsgCtx.getProperty(OAuthConstants.ACCESS_TOKEN)).thenReturn(SAMPLE_ACCESS_TOKEN);

        mockAuthorizationGrantCache();

        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(requestMsgCtx.getAuthorizedUser()).thenReturn(user);
        when(user.isFederatedUser()).thenReturn(false);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(requestMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(DUMMY_CLIENT_ID);

        mockApplicationManagementService();
        getMockOIDCScopeResource();

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
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
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();

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

        defaultOIDCClaimsCallbackHandler.handleCustomClaims(jwtClaimsSet, authzReqMessageContext);
        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
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

    private void getMockOIDCScopeResource() throws RegistryException {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, CARBON_HOME);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(TENANT_ID);

        when(registryService.getConfigSystemRegistry(anyInt())).thenReturn(userRegistry);
        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);


    }

    private Assertion getAssertion(String[] attributeValues) throws ConfigurationException {
        // Build the SAML Attribute
        List<Attribute> attributesList = new ArrayList<>();
        Attribute attribute = buildAttribute(CUSTOM_ATTRIBUTE_NAME, attributeValues);
        attributesList.add(attribute);

        // Build the SAML Attribute statement
        AttributeStatement statement =
                new AttributeStatementBuilder().buildObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
        statement.getAttributes().addAll(attributesList);

        List<AttributeStatement> attributeStatementList = new ArrayList<>();
        attributeStatementList.add(statement);

        // Build the SAML Assertion
        Assertion assertion = new AssertionBuilder().buildObject(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.getAttributeStatements().addAll(attributeStatementList);
        return assertion;
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
}
