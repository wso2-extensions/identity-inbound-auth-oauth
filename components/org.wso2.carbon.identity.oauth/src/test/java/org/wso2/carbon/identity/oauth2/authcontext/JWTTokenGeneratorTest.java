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
import org.powermock.api.support.membermodification.MemberModifier;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.internal.CarbonCoreDataHolder;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.test.common.testng.utils.ReadCertStoreSampleUtil;
import org.wso2.carbon.registry.core.service.RegistryService;

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
        initUserStoreManager = true, injectToSingletons = {OAuthComponentServiceHolder.class})
@WithH2Database(files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
public class JWTTokenGeneratorTest {

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
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam tokenValidationContextParam = mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
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
        Assert.assertNotNull((ClaimsRetriever)
                (MemberModifier.field(JWTTokenGenerator.class,
                        "claimsRetriever").get(jwtTokenGenerator)), "Init method invoked");
    }

    @Test(dependsOnMethods = "testInit")
    public void testGenerateToken() throws Exception {
        Whitebox.setInternalState(JWTTokenGenerator.class, "ttl", 15L);
        addSampleOauth2Application();
        KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
        ServerConfigurationService serverConfigurationService = mock(ServerConfigurationService.class);
        RegistryService registryService = mock(RegistryService.class);
        keyStoreManager.updateKeyStore("-1234", ReadCertStoreSampleUtil.createKeyStore(getClass()));

        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        Whitebox.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        MemberModifier
                .field(KeyStoreManager.class, "primaryKeyStore")
                .set(keyStoreManager, ReadCertStoreSampleUtil.createKeyStore(getClass()));
        MemberModifier
                .field(KeyStoreManager.class, "registryKeyStore")
                .set(keyStoreManager, ReadCertStoreSampleUtil.createKeyStore(getClass()));
        Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();
        publicCerts.put(-1234, ReadCertStoreSampleUtil.createKeyStore(getClass())
                .getCertificate("wso2carbon"));
        Whitebox.setInternalState(OAuth2Util.class, "publicCerts", publicCerts);
        Map<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();
        privateKeys.put(-1234, ReadCertStoreSampleUtil.createKeyStore(getClass())
                .getKey("wso2carbon", "wso2carbon".toCharArray()));
        Whitebox.setInternalState(OAuth2Util.class, "privateKeys", privateKeys);
        ClaimCache claimsLocalCache = ClaimCache.getInstance();
        MemberModifier
                .field(JWTTokenGenerator.class, "claimsLocalCache")
                .set(jwtTokenGenerator, claimsLocalCache);

        CarbonCoreDataHolder carbonCoreDataHolder = mock(CarbonCoreDataHolder.class);

        CarbonCoreDataHolder.getInstance().setRegistryService(registryService);
        CarbonCoreDataHolder.getInstance().setServerConfigurationService(serverConfigurationService);

        carbonCoreDataHolder.setServerConfigurationService(serverConfigurationService);
        carbonCoreDataHolder.setRegistryService(registryService);
        jwtTokenGenerator.generateToken(oAuth2TokenValidationMessageContext);

        MemberModifier.method(JWTTokenGenerator.class, "generateToken",
                OAuth2TokenValidationMessageContext.class);
        Assert.assertNotNull(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                                .getTokenString(), "JWT Token not set");
        Assert.assertEquals(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                                                               .getTokenType(), "JWT");

    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEmptyClaimsRetriever() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
        org.mockito.internal.util.reflection.Whitebox
                .setInternalState(OAuthServerConfiguration.getInstance(), "claimsRetrieverImplClass", null);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) org.mockito.internal.util.reflection.Whitebox
                        .getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitIncludeClaimsFalse() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(false, enableSigning);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) org.mockito.internal.util.reflection.Whitebox
                        .getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEnableSigningFalse() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, false);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever =
                (ClaimsRetriever) org.mockito.internal.util.reflection.Whitebox
                        .getInternalState(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEmptySignatureAlg() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
        org.mockito.internal.util.reflection.Whitebox
                .setInternalState(OAuthServerConfiguration.getInstance(), "signatureAlgorithm", null);
        jwtTokenGenerator.init();
        JWSAlgorithm signatureAlgorithm =
                (JWSAlgorithm) org.mockito.internal.util.reflection.Whitebox
                        .getInternalState(jwtTokenGenerator, "signatureAlgorithm");
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
}
