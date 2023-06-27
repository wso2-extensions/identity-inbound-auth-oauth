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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.powermock.api.support.membermodification.MemberModifier.stub;
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
        OrganizationManagementConfigUtil.class})
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

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setTokenType("Default");
        oAuthAppDO.setApplicationName("testApp");
        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        appInfoCache.addToCache("testConsumerKey", oAuthAppDO);
        oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);
        when(OAuth2Util.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());

        assertNotNull(tokenValidationHandler.buildIntrospectionResponse(oAuth2TokenValidationRequestDTO));
    }

    private Property getProperty(String name, String value) {

        Property property = new Property();
        property.setName(name);
        property.setValue(value);
        return property;
    }

    @DataProvider(name = "dataProviderForValidateOrgSwitchedJWTToken")
    public Object[][] dataProviderForValidateOrgSwitchedJWTToken() {

        String jwtToken = "eyJ4NXQiOiJNVEJrWXpJNVpERXhOMkV5WldJM056UXdPREk0WlRZNFlqaGtaakUzWXpaa05tSXdNelkwWWpFME1X" +
                "Wm1NRE5rT0RKbU5UUTFOamN6Wm1Ga1pEa3pOdyIsImtpZCI6Ik1UQmtZekk1WkRFeE4yRXlaV0kzTnpRd09ESTRaVFk0WWpoa1p" +
                "qRTNZelprTm1Jd016WTBZakUwTVdabU1ETmtPREptTlRRMU5qY3pabUZrWkRrek53X1JTMjU2IiwidHlwIjoiYXQrand0IiwiYW" +
                "xnIjoiUlMyNTYifQ.eyJzdWIiOiJkNzUxNjk3Mi01Yjg0LTQ2OGMtOGQzNy1hYWVlZjQ4NjU5MjkiLCJhdXQiOiJBUFBMSUNBVE" +
                "lPTl9VU0VSIiwiaXNzIjoiaHR0cHM6XC9cL2FwaS5hc2cuaW9cL3RcL3Jvb3RvcmdcL29hdXRoMlwvdG9rZW4iLCJjbGllbnRfa" +
                "WQiOiJNWm9sUTBvX0I5SjhXcHVaZnhDenduVmJSYWthIiwiYXVkIjoiTVpvbFEwb19COUo4V3B1WmZ4Q3p3blZiUmFrYSIsIm5i" +
                "ZiI6MTY4NzI1NTMwOSwiYXpwIjoiTVpvbFEwb19COUo4V3B1WmZ4Q3p3blZiUmFrYSIsIm9yZ19pZCI6IjM1NWI2MTFmLTgyYmY" +
                "tNDIxZS05M2YzLTRmOTg5MjQzYWI1NyIsInNjb3BlIjoiaW50ZXJuYWxfdXNlcl9tZ3RfbGlzdCIsImV4cCI6MTY4NzI1ODkwOS" +
                "wib3JnX25hbWUiOiJzdWItb3JnMSIsImlhdCI6MTY4NzI1NTMwOSwianRpIjoiY2E4NmVmOGItZWVlZC00NzJkLWFkM2UtZDAxZ" +
                "WYwMGI1NGI1In0.Sof0rXhR61E2mRreIItsL_kxHVc7dvZL1oRgyd0ShFKm5ubp2RlHEJV1E-6oQo4u6pQ5k5jPHP9elqCPvmPN" +
                "6wyoNXudgRS8a8yLvP3-AuVI9L3qNfZHim0XETL5DLPwvSa_isWG0eA6WGk6ezV8Xp8MICl3r5uS4xHvzbyiU9cRFA-6_-fuA6a" +
                "FuBBgqmxmG2XyXNZlBf7JSNInGUbwXJhRINmSBDz5PHnoQDQcDAADvJJSiWJKo_DAcMT0qkRd1m8mfyugS571-oEpjQxq6wN-xD" +
                "9Vp0BoLN8jjNs0mfz6EP_wgxiBpXDxfX8kXFDhI1G4iMzIf88Wm_Ec94Tirg";

        return new Object[][]{
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        jwtToken,
                        new ArrayList() {{
                            add("10084a8d-113f-4211-a0d5-efe36b082211");
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "2", true},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        jwtToken,
                        new ArrayList() {{
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "1", true},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        jwtToken,
                        new ArrayList() {{
                            add("10084a8d-113f-4211-a0d5-efe36b082211");
                            add("8a027d53-8a4d-4a6d-8ade-6428b5e76feb");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "2", false},
                {"rootorg", "3b47f496-660b-4536-b780-b1924f5c4951", "355b611f-82bf-421e-93f3-4f989243ab57",
                        jwtToken,
                        new ArrayList() {{
                            add("10084a8d-113f-4211-a0d5-efe36b082211");
                            add("3b47f496-660b-4536-b780-b1924f5c4951");
                            add("355b611f-82bf-421e-93f3-4f989243ab57");
                        }}, "1", false}
        };
    }

    @Test(dataProvider = "dataProviderForValidateOrgSwitchedJWTToken")
    public void testValidateOrgSwitchedJWTToken(String clientAppTenantDomain,
                                                String clientAppOrganizationId,
                                                String switchedOrganizationId,
                                                String jwtToken,
                                                List<String> parentHierarchyFromSwitchedOrg,
                                                String subOrgStartLevel,
                                                boolean expectedValidatorResponse)
            throws Exception {

        mockRequiredObjects();

        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        oAuth2AccessToken.setIdentifier(jwtToken);
        oAuth2AccessToken.setTokenType("bearer");
        oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam tokenValidationContextParam =
                mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        tokenValidationContextParam.setKey("dummy");
        tokenValidationContextParam.setValue("dummy");
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] tokenValidationContextParams =
                {tokenValidationContextParam};
        oAuth2TokenValidationRequestDTO.setContext(tokenValidationContextParams);

        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();

        OAuth2TokenValidationMessageContext validationReqDTO = new OAuth2TokenValidationMessageContext(
                oAuth2TokenValidationRequestDTO, oAuth2TokenValidationResponseDTO);

        authzUser.setTenantDomain(clientAppTenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(clientAppTenantDomain);

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(Mockito.anyString())).thenReturn(identityProvider);
        stub(method(OAuth2JWTTokenValidator.class, "getSigningTenantDomain", JWTClaimsSet.class, AccessTokenDO.class))
                .toReturn(clientAppTenantDomain);

        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[0];
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);
        mockStatic(IdentityApplicationManagementUtil.class);
        mockStatic(FederatedAuthenticatorConfig.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs,
                "openidconnect")).thenReturn(federatedAuthenticatorConfig);

        Property[] properties = new Property[0];
        Property property = new Property();
        property.setName("IdPEntityId");
        property.setValue("https://api.asg.io/o/" + switchedOrganizationId + "/oauth2/token");
        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(IdentityApplicationManagementUtil.getProperty(properties, "IdPEntityId")).thenReturn(property);

        // Mock OAuth2ServiceComponentHolder instances.
        mockStatic(OAuth2ServiceComponentHolder.class);
        OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                Mockito.mock(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(oAuth2ServiceComponentHolderInstance);
        when(oAuth2ServiceComponentHolderInstance.getOrganizationManager()).thenReturn(organizationManager);
        when(organizationManager.resolveOrganizationId(clientAppTenantDomain)).thenReturn(clientAppOrganizationId);
        when(organizationManager.getAncestorOrganizationIds(switchedOrganizationId)).thenReturn(
                parentHierarchyFromSwitchedOrg);

        mockStatic(OrganizationManagementConfigUtil.class);
        when(OrganizationManagementConfigUtil.getProperty(SUB_ORG_START_LEVEL)).thenReturn(subOrgStartLevel);

        stub(method(OAuth2JWTTokenValidator.class, "validateSignature", SignedJWT.class, IdentityProvider.class))
                .toReturn(true);
        stub(method(OAuth2JWTTokenValidator.class, "checkExpirationTime", Date.class))
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
}
