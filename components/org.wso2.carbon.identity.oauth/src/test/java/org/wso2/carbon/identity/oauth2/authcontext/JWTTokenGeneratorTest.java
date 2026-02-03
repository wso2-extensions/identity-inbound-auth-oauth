/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.authcontext;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Random;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.DEFAULT_BACKCHANNEL_LOGOUT_URL;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.JWT_X5T_HEXIFY_REQUIRED;

@WithCarbonHome
@WithRealmService(tenantId = MultitenantConstants.SUPER_TENANT_ID,
        tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
        initUserStoreManager = true)
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/identity.sql", "dbScripts/insert_application_and_token.sql",
                "dbScripts/insert_consumer_app.sql",
                "dbScripts/insert_local_idp.sql"})
@WithKeyStore
@Listeners(MockitoTestNGListener.class)
public class JWTTokenGeneratorTest {

    private OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO;
    private OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO;
    private OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext;
    private OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken;

    private JWTTokenGenerator jwtTokenGenerator;
    private boolean includeClaims = true;
    private boolean enableSigning = true;
    @Mock
    RealmService realmService;
    @Mock
    private TenantManager tenantManager;

    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;

    @BeforeClass
    public void setUp() throws Exception {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain("carbon.super");
        user.setFederatedUser(false);

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
        mockKeystores();
    }

    @AfterClass
    public void tearDown() throws Exception {

        identityKeyStoreResolverMockedStatic.close();
    }

    @Test
    public void testInit() throws Exception {
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever = (ClaimsRetriever) getPrivateField(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNotNull(claimsRetriever);
        OAuth2ServiceComponentHolder.setKeyIDProvider(new DefaultKeyIDProviderImpl());
    }

    @Test(dependsOnMethods = "testInit")
    public void testGenerateToken() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId)
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            identityUtil.when(IdentityUtil::getPrimaryDomainName)
                    .thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            addSampleOauth2Application();
            ClaimCache claimsLocalCache = ClaimCache.getInstance();
            setPrivateField(jwtTokenGenerator, "claimsLocalCache", claimsLocalCache);
            OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
            when(realmService.getTenantManager()).thenReturn(tenantManager);
            when(tenantManager.getDomain(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(
                    MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            accessToken.setTokenType("Bearer");
            oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);

            // Hexify disabled.
            jwtTokenGenerator.generateToken(oAuth2TokenValidationMessageContext);

            Assert.assertNotNull(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                    .getTokenString(), "JWT Token not set");
            Assert.assertEquals(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                    .getTokenType(), "JWT");

            // Hexify enabled.
            identityUtil.when(() -> IdentityUtil.getProperty(JWT_X5T_HEXIFY_REQUIRED))
                    .thenReturn(String.valueOf(true));
            jwtTokenGenerator.generateToken(oAuth2TokenValidationMessageContext);

            Assert.assertNotNull(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                    .getTokenString(), "JWT Token not set");
            Assert.assertEquals(oAuth2TokenValidationMessageContext.getResponseDTO().getAuthorizationContextToken()
                    .getTokenType(), "JWT");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

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
        setPrivateField(OAuthServerConfiguration.getInstance(), "claimsRetrieverImplClass", (Object) null);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever = (ClaimsRetriever) getPrivateField(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitIncludeClaimsFalse() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(false, enableSigning);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever = (ClaimsRetriever) getPrivateField(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEnableSigningFalse() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, false);
        jwtTokenGenerator.init();
        ClaimsRetriever claimsRetriever = (ClaimsRetriever) getPrivateField(jwtTokenGenerator, "claimsRetriever");
        Assert.assertNull(claimsRetriever);
    }

    @Test(dependsOnMethods = "testGenerateToken")
    public void testInitEmptySignatureAlg() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
        setPrivateField(OAuthServerConfiguration.getInstance(), "signatureAlgorithm", ( Object) null);
        jwtTokenGenerator.init();
        JWSAlgorithm signatureAlgorithm = (JWSAlgorithm) getPrivateField(jwtTokenGenerator, "signatureAlgorithm");
        Assert.assertNotNull(signatureAlgorithm);
        Assert.assertNotNull(signatureAlgorithm.getName());
        Assert.assertEquals(signatureAlgorithm.getName(), "none");
    }

    @Test(description = "This will test the `signJWTWithRSA` method.")
    public void testSignJWTWithRSA() throws Exception {

        jwtTokenGenerator = new JWTTokenGenerator();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("testUser")
                .issuer("https://example.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                claimsSet
        );
        signedJWT = jwtTokenGenerator.signJWTWithRSA(signedJWT, null, SUPER_TENANT_DOMAIN_NAME, SUPER_TENANT_ID);
        assertNotNull(signedJWT.getSignature());

        // Verify the signature generation when the tenant domain is null.
        signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                claimsSet
        );
        signedJWT = jwtTokenGenerator.signJWTWithRSA(signedJWT, null, null, 0);
        assertNotNull(signedJWT.getSignature());
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
        oAuthAppDO.setBackChannelLogoutUrl(DEFAULT_BACKCHANNEL_LOGOUT_URL);

        OAuthAppDAO authAppDAO = new OAuthAppDAO();
        authAppDAO.addOAuthConsumer("testUser", -1234, "PRIMARY");
        authAppDAO.addOAuthApplication(oAuthAppDO);
        authAppDAO.getConsumerAppState("sampleConsumerKey");
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

    private Object getPrivateField(Object object, String fieldName) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(object);
    }

    private void mockKeystores() throws Exception {

        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        when(identityKeyStoreResolver.getPrivateKey(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                ReadCertStoreSampleUtil.createKeyStore(getClass()).getKey("wso2carbon", "wso2carbon".toCharArray()));
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                ReadCertStoreSampleUtil.createKeyStore(getClass()).getCertificate("wso2carbon"));

        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }

}
