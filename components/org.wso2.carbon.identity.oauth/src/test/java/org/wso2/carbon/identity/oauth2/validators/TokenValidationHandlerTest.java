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

package org.wso2.carbon.identity.oauth2.validators;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.util.TestUtils;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementConfigUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.powermock.api.support.membermodification.MemberModifier.stub;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.SUB_ORG_START_LEVEL;

@WithCarbonHome
@WithAxisConfiguration
@PowerMockIgnore({"javax.xml.*", "org.xml.sax.*", "org.w3c.dom.*"})
@PrepareForTest({OAuthServerConfiguration.class, JDBCPersistenceManager.class, IdentityDatabaseUtil.class,
        IdentityApplicationManagementUtil.class, IdentityProviderManager.class, RealmService.class, LoggerUtils.class,
        FederatedAuthenticatorConfig.class, OAuth2ServiceComponentHolder.class, OAuth2JWTTokenValidator.class,
        OrganizationManagementConfigUtil.class, IdentityUtil.class, OAuthTokenPersistenceFactory.class,
        OAuth2Util.class, JWTUtils.class})
public class TokenValidationHandlerTest extends PowerMockTestCase {

    private String[] scopeArraySorted = new String[]{"scope1", "scope2", "scope3"};
    private String clientId = "dummyClientId";
    private String authorizationCode = "testAuthorizationCode";
    private String tokenType = "testTokenType";
    private AuthenticatedUser authzUser;
    private Timestamp issuedTime;
    private Timestamp refreshTokenIssuedTime;
    private long validityPeriodInMillis;
    private long refreshTokenValidityPeriodInMillis;
    private static final String DEFAULT_TOKEN_TYPE = "Default";
    private static final String JWT_TOKEN_TYPE = "JWT";
    private static final String DB_NAME = "jdbc/WSO2IdentityDB";
    private static final String H2_SCRIPT_NAME = "token.sql";
    private Connection conn = null;
    private TokenValidationHandler tokenValidationHandler;
    private OAuth2JWTTokenValidator oAuth2JWTTokenValidator;

    @Mock
    private OAuth2TokenValidator tokenValidator;
    @Mock
    private OAuthIssuer oAuthIssuer;
    @Mock
    protected OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private OrganizationManager organizationManager;
    @Mock
    private RealmConfiguration realmConfiguration;
    @Mock
    private IdentityProviderManager identityProviderManager;
    @Mock
    private IdentityProvider identityProvider;
    @Mock
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();

    @BeforeMethod
    public void setUp() {

        authzUser = new AuthenticatedUser();
        authzUser.setAccessingOrganization("test_org");
        issuedTime = new Timestamp(System.currentTimeMillis());
        refreshTokenIssuedTime = new Timestamp(System.currentTimeMillis());
        validityPeriodInMillis = 3600000L;
        refreshTokenValidityPeriodInMillis = 3600000L;
        tokenValidationHandler = TokenValidationHandler.getInstance();
        tokenValidationHandler.addTokenValidator("test", tokenValidator);
        oAuth2JWTTokenValidator = new OAuth2JWTTokenValidator();
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    @Test
    public void testGetInstance() throws Exception {
        assertNotNull(tokenValidationHandler);
    }

    @Test
    public void testValidate() throws Exception {
        OAuth2TokenValidationResponseDTO responseDTO = tokenValidationHandler
                .validate(new OAuth2TokenValidationRequestDTO());
        assertNotNull(responseDTO);
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "IdpIDColumnAvailabilityDataProvider")
    public Object[][] idpIDColumnAvailabilityDataProvider() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "IdpIDColumnAvailabilityDataProvider")
    public void testFindOAuthConsumerIfTokenIsValid(boolean isIDPIdColumnEnabled) throws Exception {

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
        mockRequiredObjects();
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken =
                oAuth2TokenValidationRequestDTO.new OAuth2AccessToken();
        oAuth2AccessToken.setIdentifier("testIdentifier");
        oAuth2AccessToken.setTokenType("bearer");
        oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

        when(OAuth2Util.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        OAuth2ClientApplicationDTO response = tokenValidationHandler
                .findOAuthConsumerIfTokenIsValid(oAuth2TokenValidationRequestDTO);
        assertNotNull(response);
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "CommonDataProvider")
    public Object[][] commonDataProvider() {
        return new Object[][]{
                {true, "1234"},
                {false, "12345"}
        };
    }

    @Test(dataProvider = "CommonDataProvider")
    public void testBuildIntrospectionResponse(boolean isIDPIdColumnEnabled, String accessTokenId) throws Exception {

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
        mockRequiredObjects();
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        doReturn(MultitenantConstants.SUPER_TENANT_ID).when(tenantManager).getTenantId(Mockito.anyString());
        OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
        IdentityTenantUtil.setRealmService(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        accessToken.setIdentifier("testAccessToken");
        accessToken.setTokenType("bearer");

        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        accessTokenDO.setTokenId(accessTokenId);

        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        tokenBinding.setBindingReference("test_binding_reference");
        tokenBinding.setBindingValue("R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
        accessTokenDO.setTokenBinding(tokenBinding);

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        mockStatic(OAuth2ServiceComponentHolder.class);
        OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                Mockito.mock(OAuth2ServiceComponentHolder.class);
        TokenProvider tokenProvider = Mockito.mock(TokenProvider.class);
        when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(oAuth2ServiceComponentHolderInstance);
        when(oAuth2ServiceComponentHolderInstance.getTokenProvider()).thenReturn(tokenProvider);
        when(tokenProvider.getVerifiedAccessToken(Mockito.anyString(), Mockito.anyBoolean())).thenReturn(accessTokenDO);

        mockStatic(OAuthTokenPersistenceFactory.class);
        OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory = Mockito.mock(OAuthTokenPersistenceFactory.class);
        TokenManagementDAO tokenManagementDAO =
                Mockito.mock(TokenManagementDAO.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(oAuthTokenPersistenceFactory);
        when(oAuthTokenPersistenceFactory.getTokenManagementDAO()).thenReturn(tokenManagementDAO);
        when(tokenManagementDAO.getRefreshToken(Mockito.anyString())).thenReturn(accessTokenDO);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setTokenType("Default");
        oAuthAppDO.setApplicationName("testApp");
        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        appInfoCache.addToCache("testConsumerKey", oAuthAppDO);
        oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        when(OAuth2Util.getAppInformationByAccessTokenDO(Mockito.any())).thenReturn(oAuthAppDO);
        when(OAuth2Util.getAccessTokenExpireMillis(Mockito.any(), Mockito.anyBoolean())).thenReturn(1000L);

        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = tokenValidationHandler
                .buildIntrospectionResponse(oAuth2TokenValidationRequestDTO);
        assertNotNull(oAuth2IntrospectionResponseDTO);
        assertEquals(oAuth2IntrospectionResponseDTO.getBindingType(),
                OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        assertEquals(oAuth2IntrospectionResponseDTO.getBindingReference(), "test_binding_reference");
        assertEquals(oAuth2IntrospectionResponseDTO.getCnfBindingValue(),
                "R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
    }

    private Property getProperty(String name, String value) {

        Property property = new Property();
        property.setName(name);
        property.setValue(value);
        return property;
    }

    @DataProvider(name = "dataProviderForValidateOrgSwitchedJWTToken")
    public Object[][] dataProviderForValidateOrgSwitchedJWTToken() {

        String jwtToken = "eyJ4NXQiOiJNVEJrWXpJNVpERXhOMkV5WldJM056UXdPREk0WlRZNFlqaGtaakUzWXpaa05tSXdNelkwWWpFME1XW" +
                "m1NRE5rT0RKbU5UUTFOamN6Wm1Ga1pEa3pOdyIsImtpZCI6Ik1UQmtZekk1WkRFeE4yRXlaV0kzTnpRd09ESTRaVFk0WWpoa1pq" +
                "RTNZelprTm1Jd016WTBZakUwTVdabU1ETmtPREptTlRRMU5qY3pabUZrWkRrek53X1JTMjU2IiwidHlwIjoiYXQrand0IiwiYWx" +
                "nIjoiUlMyNTYifQ.eyJzdWIiOiJkNzUxNjk3Mi01Yjg0LTQ2OGMtOGQzNy1hYWVlZjQ4NjU5MjkiLCJhdXQiOiJBUFBMSUNBVEl" +
                "PTl9VU0VSIiwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My90L3Jvb3Rvcmcvb2F1dGgyL3Rva2VuIiwiY2xpZW50X2lkIj" +
                "oiTVpvbFEwb19COUo4V3B1WmZ4Q3p3blZiUmFrYSIsImF1ZCI6Ik1ab2xRMG9fQjlKOFdwdVpmeEN6d25WYlJha2EiLCJuYmYiO" +
                "jE2ODcyNTUzMDksImF6cCI6Ik1ab2xRMG9fQjlKOFdwdVpmeEN6d25WYlJha2EiLCJvcmdfaWQiOiIzNTViNjExZi04MmJmLTQy" +
                "MWUtOTNmMy00Zjk4OTI0M2FiNTciLCJzY29wZSI6ImludGVybmFsX3VzZXJfbWd0X2xpc3QiLCJleHAiOjE2ODcyNTg5MDksIm9" +
                "yZ19uYW1lIjoic3ViLW9yZzEiLCJpYXQiOjE2ODcyNTUzMDksImp0aSI6ImNhODZlZjhiLWVlZWQtNDcyZC1hZDNlLWQwMWVmMD" +
                "BiNTRiNSJ9.MwZiTjdZa-o2n7yIHoEDNuK0k48-3AaOBXEwdhM6Brj04vlW5JfPMrgLrGKbpBkiFQ4s8oI4x2YdIqgxfbqLrsP8" +
                "uTMtzbk6wU-zdQP4N6-ZqQxgZy0mObLhvEkd5TPcbrrqo_kZTXQ0J6eev5TqrDRFrHByJZTaFIdDrNMNvinUmxCkKbGyVRCDbTS" +
                "qaVUwWSl24LjvjdhG_Zk5MSSjn2v89JV7XueEPCoq1WJ2S24c8PZhcbovL10V55GXp3a7c9_ZbABR7d0D34pGj6LzUvtIqB-w29" +
                "ievHKesdZqFVII89-0DKtHQhHoehj0jA8zuz5nAwfVr75cjjLahdlRIA";

        return new Object[][]{
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        "355b611f-82bf-421e-93f3-4f989243ab57", jwtToken,
                        new ArrayList() {{
                            add("10084a8d-113f-4211-a0d5-efe36b082211");
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "2", true},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        "355b611f-82bf-421e-93f3-4f989243ab57", jwtToken,
                        new ArrayList() {{
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "1", true},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        "355b611f-82bf-421e-93f3-4f989243ab57", jwtToken,
                        new ArrayList() {{
                            add("10084a8d-113f-4211-a0d5-efe36b082211");
                            add("8a027d53-8a4d-4a6d-8ade-6428b5e76feb");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "2", false},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        "355b611f-82bf-421e-93f3-4f989243ab57", jwtToken,
                        new ArrayList() {{
                            add("10084a8d-113f-4211-a0d5-efe36b082211");
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "1", false},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        "4b084b1f-860f-4536-a0d5-h1924f5c4951", jwtToken,
                        new ArrayList() {{
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                            add("4b084b1f-860f-4536-a0d5-h1924f5c4951");
                        }}, "1", false}
        };
    }

    @Test(dataProvider = "dataProviderForValidateOrgSwitchedJWTToken")
    public void testValidateOrgSwitchedJWTToken(String clientAppTenantDomain,
                                                String clientAppOrganizationId,
                                                String switchedOrganizationId,
                                                String resourceResidentOrganizationId,
                                                String jwtToken,
                                                List<String> parentHierarchyFromSwitchedOrg,
                                                String subOrgStartLevel,
                                                boolean expectedValidatorResponse)
            throws Exception {

        mockRequiredObjects();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(clientAppTenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setOrganizationId(resourceResidentOrganizationId);
        OAuth2TokenValidationMessageContext validationReqDTO = getOAuth2TokenValidationMessageContext(
                jwtToken, "bearer", "dummyKey", "dummyValue");

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(Mockito.anyString())).thenReturn(identityProvider);
        mockStatic(JWTUtils.class);
        when(JWTUtils.isJWT(Mockito.anyString())).thenCallRealMethod();
        when(JWTUtils.parseJWT(Mockito.anyString())).thenCallRealMethod();
        when(JWTUtils.getJWTClaimSet(Mockito.any())).thenCallRealMethod();
        when(JWTUtils.validateRequiredFields(Mockito.any())).thenCallRealMethod();
        when(JWTUtils.getResidentIDPForIssuer(Mockito.any(), Mockito.any())).thenCallRealMethod();
        when(JWTUtils.getIDPForIssuer(Mockito.anyString(), Mockito.anyString(), Mockito.anyString()))
                .thenCallRealMethod();
        when(JWTUtils.getSubOrgStartLevel()).thenCallRealMethod();
        when(JWTUtils.resolveSubject(Mockito.any())).thenCallRealMethod();
        when(JWTUtils.getSigningTenantDomain(Mockito.any(), Mockito.any())).thenReturn(clientAppTenantDomain);
        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[0];
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);
        mockStatic(IdentityApplicationManagementUtil.class);
        mockStatic(FederatedAuthenticatorConfig.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs,
                "openidconnect")).thenReturn(federatedAuthenticatorConfig);

        Property[] properties = new Property[0];
        Property property = new Property();
        property.setName("IdPEntityId");
        property.setValue("https://localhost:9443/o/" + switchedOrganizationId + "/oauth2/token");
        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(IdentityApplicationManagementUtil.getProperty(properties, "IdPEntityId")).thenReturn(property);

        // Mock OAuth2ServiceComponentHolder instances.
        mockStatic(OAuth2ServiceComponentHolder.class);
        OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                Mockito.mock(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(oAuth2ServiceComponentHolderInstance);
        when(oAuth2ServiceComponentHolderInstance.isOrganizationManagementEnabled()).thenReturn(true);
        when(oAuth2ServiceComponentHolderInstance.getOrganizationManager()).thenReturn(organizationManager);
        when(organizationManager.resolveOrganizationId(clientAppTenantDomain)).thenReturn(clientAppOrganizationId);
        when(organizationManager.getAncestorOrganizationIds(switchedOrganizationId)).thenReturn(
                parentHierarchyFromSwitchedOrg);

        mockStatic(OrganizationManagementConfigUtil.class);
        when(OrganizationManagementConfigUtil.getProperty(SUB_ORG_START_LEVEL)).thenReturn(subOrgStartLevel);
        when(JWTUtils.checkExpirationTime(Mockito.any())).thenReturn(true);
        stub(method(OAuth2JWTTokenValidator.class, "validateSignature", SignedJWT.class, IdentityProvider.class))
                .toReturn(true);

        // Assert response of the validateAccessToken() in OAuth2JWTTokenValidator class.
        if (expectedValidatorResponse) {
            assertTrue(oAuth2JWTTokenValidator.validateAccessToken(validationReqDTO));
        } else {
            assertThrows(IdentityOAuth2Exception.class, () ->
                    oAuth2JWTTokenValidator.validateAccessToken(validationReqDTO));
        }
    }

    protected void mockRequiredObjects() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(OAuthServerConfiguration.getInstance().getOAuthTokenGenerator()).thenReturn(oAuthIssuer);
        when(OAuthServerConfiguration.getInstance().getSignatureAlgorithm()).thenReturn("SHA256withRSA");
        when(OAuthServerConfiguration.getInstance().getHashAlgorithm()).thenReturn("SHA-256");

        Map<String, OauthTokenIssuer> oauthTokenIssuerMap = new HashMap<>();
        oauthTokenIssuerMap.put(DEFAULT_TOKEN_TYPE, new OauthTokenIssuerImpl());
        oauthTokenIssuerMap.put(JWT_TOKEN_TYPE, new JWTTokenIssuer());
        when(OAuthServerConfiguration.getInstance().getOauthTokenIssuerMap()).thenReturn(oauthTokenIssuerMap);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getDBConnection());
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(getDBConnection());
    }

    private Connection getDBConnection() throws Exception {

        if (conn == null) {
            BasicDataSource dataSource = new BasicDataSource();
            dataSource.setDriverClassName("org.h2.Driver");
            dataSource.setUsername("username");
            dataSource.setPassword("password");
            dataSource.setUrl("jdbc:h2:mem:test" + DB_NAME);
            try (Connection connection = dataSource.getConnection()) {
                connection.createStatement()
                        .executeUpdate("RUNSCRIPT FROM '" + TestUtils.getFilePath(H2_SCRIPT_NAME) + "'");
            }
            conn = dataSource.getConnection();
        }
        return conn;
    }

    private OAuth2TokenValidationMessageContext getOAuth2TokenValidationMessageContext(
            String tokenIdentifier, String tokenType, String contextParamKey, String contextParamValue) {

        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        oAuth2AccessToken.setIdentifier(tokenIdentifier);
        oAuth2AccessToken.setTokenType(tokenType);
        oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam tokenValidationContextParam =
                mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        tokenValidationContextParam.setKey(contextParamKey);
        tokenValidationContextParam.setValue(contextParamValue);
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] tokenValidationContextParams =
                {tokenValidationContextParam};
        oAuth2TokenValidationRequestDTO.setContext(tokenValidationContextParams);

        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationMessageContext validationReqDTO = new OAuth2TokenValidationMessageContext(
                oAuth2TokenValidationRequestDTO, oAuth2TokenValidationResponseDTO);

        return validationReqDTO;
    }
}
