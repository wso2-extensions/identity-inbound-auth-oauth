/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth2.authcontext;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.dbcp.BasicDataSource;
import org.mockito.internal.util.reflection.FieldSetter;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.openidconnect.util.TestUtils;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;
import java.security.Key;
import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@WithCarbonHome
@WithRealmService(tenantId = MultitenantConstants.SUPER_TENANT_ID,
        tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
        initUserStoreManager = true)
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
@WithKeyStore
@PrepareForTest({IdentityUtil.class, IdentityTenantUtil.class, OAuthUtil.class, IdentityDatabaseUtil.class})
@PowerMockIgnore({"javax.crypto.*"})
public class JWTTokenGeneratorTest extends PowerMockIdentityBaseTest {

    private DefaultOAuth2TokenValidator defaultOAuth2TokenValidator;
    private OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO;
    private OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO;
    private OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext;
    private OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken;

    private JWTTokenGenerator jwtTokenGenerator;
    private boolean includeClaims = true;
    private boolean enableSigning = true;

    private static final String DB_NAME = "jdbc/WSO2IdentityDB";

    private static final String H2_SCRIPT1_NAME = "h2_with_application_and_token.sql";
    private static final String H2_SCRIPT2_NAME = "identity.sql";

    private Connection conn1 = null;
    private Connection conn2 = null;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityConfigDirPath())
                .thenReturn(System.getProperty("user.dir")
                        + File.separator + "src"
                        + File.separator + "test"
                        + File.separator + "resources"
                        + File.separator + "conf");
        mockStatic(IdentityTenantUtil.class);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain("carbon.super");
        user.setFederatedUser(false);

        defaultOAuth2TokenValidator = new DefaultOAuth2TokenValidator();
        oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam tokenValidationContextParam =
                mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        tokenValidationContextParam.setKey("sampleKey");
        tokenValidationContextParam.setValue("sampleValue");

        accessToken = oAuth2TokenValidationRequestDTO.new OAuth2AccessToken();

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[]
                tokenValidationContextParams = {tokenValidationContextParam};
        oAuth2TokenValidationRequestDTO.setContext(tokenValidationContextParams);

        oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        oAuth2TokenValidationResponseDTO.setAuthorizedUser("testUser");
        oAuth2TokenValidationMessageContext =
                new OAuth2TokenValidationMessageContext
                        (oAuth2TokenValidationRequestDTO, oAuth2TokenValidationResponseDTO);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setScope(new String[]{"scope1", "scope2"});
        accessTokenDO.setConsumerKey("sampleConsumerKey");
        accessTokenDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));

        accessTokenDO.setAuthzUser(user);
        accessTokenDO.setTenantID(MultitenantConstants.SUPER_TENANT_ID);

        oAuth2TokenValidationMessageContext.addProperty("AccessTokenDO", accessTokenDO);
        jwtTokenGenerator = new JWTTokenGenerator();
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
    }

    @AfterTest
    public void tearDown() throws Exception {
    }

    @Test
    public void testInit() throws Exception {
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) Whitebox.getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNotNull(claimsRetriever);
        OAuth2ServiceComponentHolder.setKeyIDProvider(new DefaultKeyIDProviderImpl());
    }

    @Test(dependsOnMethods = "testInit")
    public void testGenerateToken() throws Exception {
        FieldSetter.setField(jwtTokenGenerator, jwtTokenGenerator.getClass().getDeclaredField("ttl"), 15L);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(getConnection1());
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getConnection2());

        addSampleOauth2Application();
        ClaimCache claimsLocalCache = ClaimCache.getInstance();
        Whitebox.setInternalState(jwtTokenGenerator, "claimsLocalCache", claimsLocalCache);
        Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
        publicCerts.put(-1234, ReadCertStoreSampleUtil.createKeyStore(getClass())
                                                      .getCertificate("wso2carbon"));
        setFinalStatic(OAuth2Util.class.getDeclaredField("publicCerts"), publicCerts);
        Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
        privateKeys.put(-1234, ReadCertStoreSampleUtil.createKeyStore(getClass())
                                                      .getKey("wso2carbon", "wso2carbon".toCharArray()));
        setFinalStatic(OAuth2Util.class.getDeclaredField("privateKeys"), privateKeys);

        accessToken.setTokenType("Bearer");
        oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);

        jwtTokenGenerator.generateToken(oAuth2TokenValidationMessageContext);

        Assert.assertNotNull(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                                .getTokenString(), "JWT Token not set");
        Assert.assertEquals(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                               .getTokenType(), "JWT");

    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testNbfClaimInJWT() throws Exception {
        String tokenString = oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                                .getTokenString();
        JWT jwt = JWTParser.parse(tokenString);
        Date notBeforeTime = jwt.getJWTClaimsSet().getNotBeforeTime();
        Assert.assertTrue(notBeforeTime.compareTo(new Date()) <= 0);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEmptyClaimsRetriever() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
        Whitebox.setInternalState(OAuthServerConfiguration.getInstance(), "claimsRetrieverImplClass", (Object) null);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) Whitebox.getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitIncludeClaimsFalse() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(false, enableSigning);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) Whitebox.getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEnableSigningFalse() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, false);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) Whitebox.getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEmptySignatureAlg() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
        Whitebox.setInternalState(OAuthServerConfiguration.getInstance(), "signatureAlgorithm", ( Object) null);
        jwtTokenGenerator.init();
        JWSAlgorithm signatureAlgorithm =
                (JWSAlgorithm) Whitebox.getInternalState(jwtTokenGenerator, "signatureAlgorithm");
        Assert.assertNotNull(signatureAlgorithm);
        Assert.assertNotNull(signatureAlgorithm.getName());
        Assert.assertEquals(signatureAlgorithm.getName(), "none");
    }

    private void addSampleOauth2Application() throws IdentityOAuthAdminException {

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey("sampleConsumerKey");
        oAuthAppDO.setState("active");
        oAuthAppDO.setCallbackUrl("https://localhost:8080/playground2/oauth2client");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain("PRIMARY");
        user.setUserName("testUser");
        oAuthAppDO.setUser(user);
        oAuthAppDO.setApplicationName("testApp" + new Random(4));
        oAuthAppDO.setOauthVersion("2.0");

        OAuthAppDAO authAppDAO = new OAuthAppDAO();
        authAppDAO.addOAuthConsumer("testUser", -1234, "PRIMARY");
        authAppDAO.addOAuthApplication(oAuthAppDO);
        authAppDAO.getConsumerAppState("sampleConsumerKey");
    }

    private void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }

    private Connection getConnection1() throws Exception {

        if (conn1 == null) {
            System.out.println("creating database connection..........");
            BasicDataSource dataSource = new BasicDataSource();
            dataSource.setDriverClassName("org.h2.Driver");
            dataSource.setUsername("username");
            dataSource.setPassword("password");
            dataSource.setUrl("jdbc:h2:mem:test" + DB_NAME);
            try (Connection connection = dataSource.getConnection()) {
                Statement statement = connection.createStatement();
                statement.addBatch("RUNSCRIPT FROM '" + TestUtils.getFilePath(H2_SCRIPT1_NAME) + "'");
                statement.addBatch("RUNSCRIPT FROM '" + TestUtils.getFilePath(H2_SCRIPT2_NAME) + "'");
                statement.executeBatch();
            }
            conn1 = dataSource.getConnection();
        }
        return conn1;
    }
    private Connection getConnection2() throws Exception {

        if (conn2 == null) {
            System.out.println("creating database connection..........");
            BasicDataSource dataSource = new BasicDataSource();
            dataSource.setDriverClassName("org.h2.Driver");
            dataSource.setUsername("username");
            dataSource.setPassword("password");
            dataSource.setUrl("jdbc:h2:mem:test" + DB_NAME);
            conn2 = dataSource.getConnection();
        }
        return conn2;
    }
}



