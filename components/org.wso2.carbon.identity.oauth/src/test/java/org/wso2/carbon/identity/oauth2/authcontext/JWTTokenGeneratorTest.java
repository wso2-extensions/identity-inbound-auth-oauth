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
import org.mockito.internal.util.reflection.Whitebox;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Key;
import java.security.cert.Certificate;
import java.sql.Timestamp;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.Mockito.mock;

@WithCarbonHome
@WithRealmService(tenantId = MultitenantConstants.SUPER_TENANT_ID,
        tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
        initUserStoreManager = true)
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
@WithKeyStore
public class JWTTokenGeneratorTest extends PowerMockIdentityBaseTest {

    private DefaultOAuth2TokenValidator defaultOAuth2TokenValidator;
    private OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO;
    private OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO;
    private OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext;

    private JWTTokenGenerator jwtTokenGenerator;
    private boolean includeClaims = true;
    private boolean enableSigning = true;

    @BeforeTest
    public void setUp() throws Exception {

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
    }

    @Test(dependsOnMethods = "testInit")
    public void testGenerateToken() throws Exception {
        Whitebox.setInternalState(jwtTokenGenerator, "ttl", 15L);
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
        jwtTokenGenerator.generateToken(oAuth2TokenValidationMessageContext);

        Assert.assertNotNull(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                                .getTokenString(), "JWT Token not set");
        Assert.assertEquals(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                               .getTokenType(), "JWT");

    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEmptyClaimsRetriever() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
        Whitebox.setInternalState(OAuthServerConfiguration.getInstance(), "claimsRetrieverImplClass", null);
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
        Whitebox.setInternalState(OAuthServerConfiguration.getInstance(), "signatureAlgorithm", null);
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
}
