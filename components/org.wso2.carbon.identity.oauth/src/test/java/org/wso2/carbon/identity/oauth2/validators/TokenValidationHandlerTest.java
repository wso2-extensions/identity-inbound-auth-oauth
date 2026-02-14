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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultOAuth2RevocationProcessor;
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
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.SUB_ORG_START_LEVEL;

@WithCarbonHome
@WithAxisConfiguration
@Listeners(MockitoTestNGListener.class)
public class TokenValidationHandlerTest {

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
    private static final String H2_SCRIPT_NAME = "identity.sql";
    private Connection conn = null;
    private TokenValidationHandler tokenValidationHandler;
    private OAuth2JWTTokenValidator oAuth2JWTTokenValidator;
    private static final String SSO_SESSION_BINDING_REFERENCE = "sso_session_binding_ref";

    @Mock
    private OAuth2TokenValidator tokenValidator;
    @Mock
    private OAuthIssuer oAuthIssuer;
    @Mock
    protected OAuthServerConfiguration mockOAuthServerConfiguration;
    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private OrganizationManager organizationManager;
    @Mock
    private RealmConfiguration realmConfiguration;
    @Mock
    private IdentityProviderManager mockIdentityProviderManager;
    @Mock
    private IdentityProvider identityProvider;
    @Mock
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();

    private MockedStatic<LoggerUtils> loggerUtils;

    @BeforeMethod
    public void setUp() {

        authzUser = new AuthenticatedUser();
        authzUser.setAccessingOrganization("test_org");
        authzUser.setTenantDomain("carbon.super");
        issuedTime = new Timestamp(System.currentTimeMillis());
        refreshTokenIssuedTime = new Timestamp(System.currentTimeMillis());
        validityPeriodInMillis = 3600000L;
        refreshTokenValidityPeriodInMillis = 3600000L;
        tokenValidationHandler = TokenValidationHandler.getInstance();
        tokenValidationHandler.addTokenValidator("test", tokenValidator);
        oAuth2JWTTokenValidator = new OAuth2JWTTokenValidator();
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
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

    @Test
    public void testFindOAuthConsumerIfTokenIsValid() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);) {
            mockRequiredObjects(oAuthServerConfiguration, identityDatabaseUtil);

            AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                    refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                    authorizationCode);
            accessTokenDO.setTokenId("testIdentifier");

            TokenBinding tokenBinding = new TokenBinding();
            tokenBinding.setBindingType(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
            tokenBinding.setBindingReference("test_binding_reference");
            tokenBinding.setBindingValue("R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
            accessTokenDO.setTokenBinding(tokenBinding);

            OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                    Mockito.mock(OAuth2ServiceComponentHolder.class);
            oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(oAuth2ServiceComponentHolderInstance);
            TokenProvider tokenProvider = Mockito.mock(TokenProvider.class);
            when(oAuth2ServiceComponentHolderInstance.getTokenProvider()).thenReturn(tokenProvider);
            when(tokenProvider.getVerifiedAccessToken(anyString(), anyBoolean())).thenReturn(
                    accessTokenDO);
            OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
            OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken =
                    oAuth2TokenValidationRequestDTO.new OAuth2AccessToken();
            oAuth2AccessToken.setIdentifier("testIdentifier");
            oAuth2AccessToken.setTokenType("bearer");
            oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

            oAuth2Util.when(OAuth2Util::getPersistenceProcessor).thenReturn(new PlainTextPersistenceProcessor());
            OAuth2ClientApplicationDTO response = tokenValidationHandler
                    .findOAuthConsumerIfTokenIsValid(oAuth2TokenValidationRequestDTO);
            assertNotNull(response);
        }
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "CommonDataProvider")
    public Object[][] commonDataProvider() {
        return new Object[][]{
                {"1234"},
                {"12345"}
        };
    }

    @Test(dataProvider = "CommonDataProvider")
    public void testBuildIntrospectionResponse(String accessTokenId) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<OrganizationManagementUtil> organizationManagementUtil =
                     mockStatic(OrganizationManagementUtil.class)) {

            organizationManagementUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString())).
                    thenReturn(false);
            mockRequiredObjects(oAuthServerConfiguration, identityDatabaseUtil);
            OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                    Mockito.mock(OAuth2ServiceComponentHolder.class);
            oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(oAuth2ServiceComponentHolderInstance);

            try (MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactory =
                         mockStatic(OAuthTokenPersistenceFactory.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                when(realmService.getTenantManager()).thenReturn(tenantManager);
                doReturn(MultitenantConstants.SUPER_TENANT_ID).when(tenantManager).getTenantId(anyString());
                lenient().doReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME).when(tenantManager)
                        .getDomain(Mockito.anyInt());
                OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
                OAuthComponentServiceHolder.getInstance().setOrganizationManager(organizationManager);
                IdentityTenantUtil.setRealmService(realmService);
                lenient().when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
                identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");

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

                String testUUID = "testUUID";
                Tenant tenant = new Tenant();
                tenant.setId(MultitenantConstants.SUPER_TENANT_ID);
                tenant.setAssociatedOrganizationUUID(testUUID);
                tenantManager.addTenant(tenant);

                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(MultitenantConstants.SUPER_TENANT_ID);
                TokenProvider tokenProvider = Mockito.mock(TokenProvider.class);
                when(oAuth2ServiceComponentHolderInstance.getTokenProvider()).thenReturn(tokenProvider);
                when(tokenProvider.getVerifiedAccessToken(anyString(), anyBoolean())).thenReturn(
                        accessTokenDO);

                OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory =
                        Mockito.mock(OAuthTokenPersistenceFactory.class);
                TokenManagementDAO tokenManagementDAO =
                        Mockito.mock(TokenManagementDAO.class);
                oAuthTokenPersistenceFactory.when(
                        OAuthTokenPersistenceFactory::getInstance).thenReturn(mockOAuthTokenPersistenceFactory);
                lenient().when(mockOAuthTokenPersistenceFactory.getTokenManagementDAO()).thenReturn(tokenManagementDAO);
                lenient().when(tokenManagementDAO.getRefreshToken(anyString())).thenReturn(accessTokenDO);

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setTokenType("Default");
                oAuthAppDO.setApplicationName("testApp");
                AppInfoCache appInfoCache = AppInfoCache.getInstance();
                appInfoCache.addToCache("testConsumerKey", oAuthAppDO);
                oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);

                oAuth2Util.when(OAuth2Util::getPersistenceProcessor).thenReturn(new PlainTextPersistenceProcessor());
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByAccessTokenDO(any())).thenReturn(oAuthAppDO);
                oAuth2Util.when(() -> OAuth2Util.getAccessTokenExpireMillis(any(), anyBoolean()))
                        .thenReturn(1000L);

                ServiceProvider serviceProvider = new ServiceProvider();
                serviceProvider.setApplicationVersion("v1.0.0");
                oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), any()))
                        .thenReturn(serviceProvider);
                // As the token is dummy, no point in getting actual tenant details.
                oAuth2Util.when(() -> OAuth2Util.getTenantDomain(anyInt()))
                        .thenReturn(StringUtils.EMPTY);

                OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = tokenValidationHandler
                        .buildIntrospectionResponse(oAuth2TokenValidationRequestDTO);
                assertNotNull(oAuth2IntrospectionResponseDTO);
                assertEquals(oAuth2IntrospectionResponseDTO.getBindingType(),
                        OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
                assertEquals(oAuth2IntrospectionResponseDTO.getBindingReference(), "test_binding_reference");
                assertEquals(oAuth2IntrospectionResponseDTO.getCnfBindingValue(),
                        "R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
            }
        }
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

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<IdentityProviderManager> identityProviderManager =
                     mockStatic(IdentityProviderManager.class);
             MockedStatic<JWTUtils> jwtUtils = mockStatic(JWTUtils.class);
             MockedStatic<IdentityApplicationManagementUtil> identityApplicationManagementUtil =
                     mockStatic(IdentityApplicationManagementUtil.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<OrganizationManagementConfigUtil> organizationManagementConfigUtil =
                     mockStatic(OrganizationManagementConfigUtil.class);
             MockedStatic<OrganizationManagementUtil> organizationManagementUtil =
                     mockStatic(OrganizationManagementUtil.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            mockRequiredObjects(oAuthServerConfiguration, identityDatabaseUtil);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(clientAppTenantDomain);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setOrganizationId(resourceResidentOrganizationId);
            OAuth2TokenValidationMessageContext validationReqDTO = getOAuth2TokenValidationMessageContext(
                    jwtToken, "bearer", "dummyKey", "dummyValue");

            identityProviderManager.when(IdentityProviderManager::getInstance).thenReturn(mockIdentityProviderManager);
            lenient().when(mockIdentityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
            jwtUtils.when(() -> JWTUtils.isJWT(anyString())).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.parseJWT(anyString())).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.getJWTClaimSet(any())).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.validateRequiredFields(any())).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.getResidentIDPForIssuer(any(), any())).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.getResidentIDPIssuer(anyString(), anyString(), anyString(), anyString()))
                    .thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.getIDPForIssuer(anyString(), anyString(), anyString()))
                    .thenCallRealMethod();
            jwtUtils.when(JWTUtils::getSubOrgStartLevel).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.resolveSubject(any())).thenCallRealMethod();
            jwtUtils.when(() -> JWTUtils.getSigningTenantDomain(any(), any()))
                    .thenReturn(clientAppTenantDomain);
            FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[0];
            lenient().when(identityProvider.getFederatedAuthenticatorConfigs())
                    .thenReturn(federatedAuthenticatorConfigs);

            identityApplicationManagementUtil.when(
                    () -> IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs,
                            "openidconnect")).thenReturn(federatedAuthenticatorConfig);

            Property[] properties = new Property[0];
            Property property = new Property();
            property.setName("IdPEntityId");
            property.setValue("https://localhost:9443/o/" + switchedOrganizationId + "/oauth2/token");
            lenient().when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);
            identityApplicationManagementUtil.when(
                            () -> IdentityApplicationManagementUtil.getProperty(properties, "IdPEntityId"))
                    .thenReturn(property);

            // Mock OAuth2ServiceComponentHolder instances.
            OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                    Mockito.mock(OAuth2ServiceComponentHolder.class);
            oAuth2ServiceComponentHolder.when(
                    OAuth2ServiceComponentHolder::getInstance).thenReturn(oAuth2ServiceComponentHolderInstance);
            lenient().when(oAuth2ServiceComponentHolderInstance.isOrganizationManagementEnabled())
                    .thenReturn(true);
            lenient().when(oAuth2ServiceComponentHolderInstance.getOrganizationManager())
                    .thenReturn(organizationManager);
            lenient().when(organizationManager.resolveOrganizationId(clientAppTenantDomain))
                    .thenReturn(clientAppOrganizationId);
            lenient().when(organizationManager.getAncestorOrganizationIds(switchedOrganizationId))
                    .thenReturn(parentHierarchyFromSwitchedOrg);

            // Mock OrganizationManagementUtil and OAuth2Util for client-based issuer validation
            organizationManagementUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString()))
                    .thenReturn(true);
            OAuthAppDO oAuthAppDO = Mockito.mock(OAuthAppDO.class);
            lenient().when(oAuthAppDO.getIssuerDetails()).thenReturn(null);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                    .thenReturn(oAuthAppDO);

            organizationManagementConfigUtil.when(
                            () -> OrganizationManagementConfigUtil.getProperty(SUB_ORG_START_LEVEL))
                    .thenReturn(subOrgStartLevel);
            jwtUtils.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
            X509Certificate x509Certificate = Mockito.mock(X509Certificate.class);
            jwtUtils.when(() -> JWTUtils.getCertificateFromClaims(any(JWTClaimsSet.class))).thenReturn(Optional.of(
                    x509Certificate));
            jwtUtils.when(() -> JWTUtils.verifyAlgorithm(any(SignedJWT.class))).thenReturn("SHA256withRSA");
            jwtUtils.when(() -> JWTUtils.verifySignature(any(SignedJWT.class), any(X509Certificate.class), anyString()))
                    .thenReturn(true);

            // Assert response of the validateAccessToken() in OAuth2JWTTokenValidator class.
            if (expectedValidatorResponse) {
                assertTrue(oAuth2JWTTokenValidator.validateAccessToken(validationReqDTO));
            } else {
                assertThrows(IdentityOAuth2Exception.class, () ->
                        oAuth2JWTTokenValidator.validateAccessToken(validationReqDTO));
            }
        }
    }

    protected void mockRequiredObjects(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration,
                                       MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil) throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getOAuthTokenGenerator())
                .thenReturn(oAuthIssuer);
        oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getSignatureAlgorithm())
                .thenReturn("SHA256withRSA");

        Map<String, OauthTokenIssuer> oauthTokenIssuerMap = new HashMap<>();
        oauthTokenIssuerMap.put(DEFAULT_TOKEN_TYPE, new OauthTokenIssuerImpl());
        oauthTokenIssuerMap.put(JWT_TOKEN_TYPE, new JWTTokenIssuer());

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getDBConnection());
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(getDBConnection());
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
            } catch (Exception e) {
                // ignore
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

    @Test
    public void testBuildClientAppDTOWithValidInputs() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setConsumerKey("testConsumerKey");
            accessTokenDO.setScope(new String[]{"scope1", "scope2"});
            accessTokenDO.setAuthzUser(new AuthenticatedUser());
            accessTokenDO.setValidityPeriodInMillis(3600000L);
            accessTokenDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));

            oAuth2Util.when(() -> OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);
            oAuth2Util.when(() -> OAuth2Util.getAccessTokenExpireMillis(any(), anyBoolean())).thenReturn(3600000L);

            TokenValidationHandler tokenValidationHandler = TokenValidationHandler.getInstance();
            OAuth2IntrospectionResponseDTO introspectionResponseDTO = new OAuth2IntrospectionResponseDTO();
            introspectionResponseDTO.setActive(true);
            introspectionResponseDTO.setClientId("testConsumerKey");

            OAuth2ClientApplicationDTO result = tokenValidationHandler.buildClientAppDTO(
                    "testAccessToken", introspectionResponseDTO);

            assertNotNull(result, "Expected a non-null OAuth2ClientApplicationDTO");
            assertEquals(result.getConsumerKey(), "testConsumerKey", "Consumer key mismatch");
            assertNotNull(result.getAccessTokenValidationResponse(),
                    "Expected a non-null AccessTokenValidationResponse");
            assertTrue(result.getAccessTokenValidationResponse().isValid(), "Expected the token to be valid");
        }
    }

    @Test
    public void testBuildClientAppDTOWithInvalidAccessToken() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            oAuth2Util.when(() -> OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenReturn(null);

            TokenValidationHandler tokenValidationHandler = TokenValidationHandler.getInstance();
            OAuth2IntrospectionResponseDTO introspectionResponseDTO = new OAuth2IntrospectionResponseDTO();
            introspectionResponseDTO.setActive(false);

            OAuth2ClientApplicationDTO result = tokenValidationHandler.buildClientAppDTO(
                    "invalidAccessToken", introspectionResponseDTO);

            assertNotNull(result, "Expected a non-null OAuth2ClientApplicationDTO");
            assertFalse(result.getAccessTokenValidationResponse().isValid(), "Expected the token to be invalid");
        }
    }

    @DataProvider(name = "ssoSessionBoundTokenDataProvider")
    public Object[][] ssoSessionBoundTokenDataProvider() {

        return new Object[][]{
                {false, false, false, false, false},
                {false, false, false, true,  false},
                {false, false, true,  false, false},
                {false, false, true,  true,  false},
                {false, true,  false, false, true},
                {false, true,  false, true,  false},
                {false, true,  true,  false, true},
                {false, true,  true,  true,  true},
                {true,  false, false, false, true},
                {true,  false, false, true,  true},
                {true,  false, true,  false, true},
                {true,  false, true,  true,  true},
                {true,  true,  false, false, true},
                {true,  true,  false, true,  true},
                {true,  true,  true,  false, true},
                {true,  true,  true,  true,  true}
        };
    }

    @Test(dataProvider = "ssoSessionBoundTokenDataProvider")
    public void testBuildIntrospectionResponseForSSOSessionBoundToken(
            boolean isSessionActive,
            boolean isLegacySessionBoundTokenBehaviourEnabled,
            boolean isSessionBoundTokensAllowedAfterSessionExpiry,
            boolean isAppLevelTokenRevocationEnabled,
            boolean expectedActiveState) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OrganizationManagementUtil> organizationManagementUtil =
                     mockStatic(OrganizationManagementUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<OAuthUtil> oAuthUtil = mockStatic(OAuthUtil.class)) {

            SessionContext sessionContext = isSessionActive ? new SessionContext() : null;
            frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(anyString(), anyString()))
                    .thenReturn(sessionContext);

            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setTokenRevocationWithIDPSessionTerminationEnabled(isAppLevelTokenRevocationEnabled);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString())).thenReturn(appDO);

            organizationManagementUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString()))
                    .thenReturn(false);
            mockRequiredObjects(oAuthServerConfiguration, identityDatabaseUtil);

            oAuthServerConfiguration.when(
                            () -> OAuthServerConfiguration.getInstance().isCrossTenantTokenIntrospectionAllowed())
                    .thenReturn(true);
            oAuthServerConfiguration.when(
                            () -> OAuthServerConfiguration.getInstance().allowCrossTenantIntrospectionForSubOrgTokens())
                    .thenReturn(true);
            oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getAllowedScopes())
                    .thenReturn(Collections.emptyList());

            OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                    Mockito.mock(OAuth2ServiceComponentHolder.class);
            oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(oAuth2ServiceComponentHolderInstance);

            OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
            IdentityTenantUtil.setRealmService(realmService);
            lenient().when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");

            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(MultitenantConstants.SUPER_TENANT_ID);

            OAuth2TokenValidationRequestDTO validationRequest = new OAuth2TokenValidationRequestDTO();
            OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = validationRequest.new OAuth2AccessToken();
            accessToken.setIdentifier("sso-session-access-token");
            accessToken.setTokenType("bearer");
            validationRequest.setAccessToken(accessToken);

            AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                    refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                    authorizationCode);
            accessTokenDO.setTokenId("sso-session-token-id");

            TokenBinding tokenBinding = new TokenBinding();
            tokenBinding.setBindingType(OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER);
            tokenBinding.setBindingReference(SSO_SESSION_BINDING_REFERENCE);
            tokenBinding.setBindingValue("sso_session_binding_value");
            accessTokenDO.setTokenBinding(tokenBinding);

            TokenProvider tokenProvider = Mockito.mock(TokenProvider.class);
            when(oAuth2ServiceComponentHolderInstance.getTokenProvider()).thenReturn(tokenProvider);
            when(tokenProvider.getVerifiedAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByAccessTokenDO(any())).thenReturn(new OAuthAppDO());

            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationVersion("v1.0.0");
            oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), any()))
                    .thenReturn(serviceProvider);
            oAuth2Util.when(() -> OAuth2Util.getAccessTokenExpireMillis(any(), anyBoolean())).thenReturn(1000L);
            // As the token is dummy, no point in getting actual tenant details.
            oAuth2Util.when(() -> OAuth2Util.getTenantDomain(anyInt())).thenReturn(StringUtils.EMPTY);
            oAuth2Util.when(OAuth2Util::isSessionBoundTokensAllowedAfterSessionExpiry)
                    .thenReturn(isSessionBoundTokensAllowedAfterSessionExpiry);
            oAuth2Util.when(OAuth2Util::isLegacySessionBoundTokenBehaviourEnabled)
                    .thenReturn(isLegacySessionBoundTokenBehaviourEnabled);

            DefaultOAuth2RevocationProcessor revocationProcessor = null;
            if ((!isLegacySessionBoundTokenBehaviourEnabled || !isSessionBoundTokensAllowedAfterSessionExpiry &&
                    isAppLevelTokenRevocationEnabled) && !isSessionActive) {
                revocationProcessor = mock(DefaultOAuth2RevocationProcessor.class);
                when(oAuth2ServiceComponentHolderInstance.getRevocationProcessor()).thenReturn(revocationProcessor);
            }
            OAuth2IntrospectionResponseDTO introspectionResponse = tokenValidationHandler
                    .buildIntrospectionResponse(validationRequest);

            assertNotNull(introspectionResponse, "Introspection response should not be null");
            assertEquals(introspectionResponse.isActive(), expectedActiveState);

            if ((!isLegacySessionBoundTokenBehaviourEnabled || !isSessionBoundTokensAllowedAfterSessionExpiry &&
                    isAppLevelTokenRevocationEnabled) && !isSessionActive) {
                oAuthUtil.verify(() -> OAuthUtil.clearOAuthCache(accessTokenDO));
                verify(revocationProcessor, times(1)).revokeAccessToken(
                        any(), eq(accessTokenDO));
            }
        }
    }
}
