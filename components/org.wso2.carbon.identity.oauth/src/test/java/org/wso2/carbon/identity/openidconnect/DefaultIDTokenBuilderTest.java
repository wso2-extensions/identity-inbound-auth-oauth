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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONObject;
import org.mockito.Mockito;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.internal.impl.AuthenticationMethodNameTranslatorImpl;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponent;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.TestUtil;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2BearerGrantHandlerTest;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.identity.secret.mgt.core.IdPSecretsProcessor;
import org.wso2.carbon.identity.secret.mgt.core.SecretsProcessor;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.ArgumentMatchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.PHONE_NUMBER_VERIFIED;
import static org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils.setFinalStatic;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(files = { "dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql" })
@WithRealmService
@WithKeyStore
public class DefaultIDTokenBuilderTest extends PowerMockTestCase {

    public static final String TEST_APPLICATION_NAME = "DefaultIDTokenBuilderTest";
    private static final String AUTHORIZATION_CODE = "AuthorizationCode";
    private static final String AUTHORIZATION_CODE_VALUE = "55fe926f-3b43-3681-aecc-dc3ed7938325";
    private static final String CLIENT_ID = TestConstants.CLIENT_ID;
    private static final String ACCESS_TOKEN = TestConstants.ACCESS_TOKEN;
    private DefaultIDTokenBuilder defaultIDTokenBuilder;
    private OAuthTokenReqMessageContext messageContext;
    private OAuth2AccessTokenRespDTO tokenRespDTO;
    private AuthenticatedUser user;

    public DefaultIDTokenBuilderTest() {

        OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(new ScopeClaimMappingDAOImpl());
    }

    @BeforeClass
    public void setUp() throws Exception {

        user = getDefaultAuthenticatedLocalUser();
        messageContext = getTokenReqMessageContextForUser(user, CLIENT_ID);
        messageContext.addProperty(AUTHORIZATION_CODE, AUTHORIZATION_CODE_VALUE);
        tokenRespDTO = new OAuth2AccessTokenRespDTO();
        tokenRespDTO.setAccessToken(ACCESS_TOKEN);

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName("LOCAL");
        idp.setEnable(true);

        Map<String, Object> configuration = new HashMap<>();
        configuration.put("SSOService.EntityId", "LOCAL");
        configuration.put("SSOService.SAMLECPEndpoint", "https://localhost:9443/samlecp");
        configuration.put("SSOService.ArtifactResolutionEndpoint", "https://localhost:9443/samlartresolve");
        configuration.put("OAuth.OpenIDConnect.IDTokenIssuerID", "https://localhost:9443/oauth2/token");
        WhiteboxImpl.setInternalState(IdentityUtil.class, "configuration", configuration);
        SecretsProcessor<IdentityProvider> identityProviderSecretsProcessor = mock(
                IdPSecretsProcessor.class);
        IdpMgtServiceComponentHolder.getInstance().setIdPSecretsProcessorService(identityProviderSecretsProcessor);
        when(identityProviderSecretsProcessor.encryptAssociatedSecrets(anyObject())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
        when(identityProviderSecretsProcessor.decryptAssociatedSecrets(anyObject())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
        IdentityProviderManager.getInstance().addResidentIdP(idp, SUPER_TENANT_DOMAIN_NAME);
        defaultIDTokenBuilder =  new DefaultIDTokenBuilder();

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping("username"), "username");
        userAttributes.put(SAML2BearerGrantHandlerTest.buildClaimMapping("email"), "email");
        userAttributes
                .put(SAML2BearerGrantHandlerTest.buildClaimMapping(PHONE_NUMBER_VERIFIED), "phone");
        LinkedHashSet acrValuesHashSet = new LinkedHashSet<>();
        acrValuesHashSet.add(new Object());
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);
        authorizationGrantCacheEntry.setSubjectClaim(messageContext.getAuthorizedUser().getUserName());
        authorizationGrantCacheEntry.setNonceValue("nonce");
        authorizationGrantCacheEntry.addAmr("amr");
        authorizationGrantCacheEntry.setSessionContextIdentifier("idp");
        authorizationGrantCacheEntry.setAuthTime(1000);
        authorizationGrantCacheEntry.setSelectedAcrValue("acr");
        authorizationGrantCacheEntry.setSubjectClaim("user@carbon.super");
        authorizationGrantCacheEntry.setEssentialClaims(getEssentialClaims());
        AuthorizationGrantCacheKey authorizationGrantCacheKey =
                new AuthorizationGrantCacheKey(AUTHORIZATION_CODE_VALUE);
        AuthorizationGrantCacheKey authorizationGrantCacheKeyForAccessToken =
                new AuthorizationGrantCacheKey("2sa9a678f890877856y66e75f605d456");
        AuthorizationGrantCache.getInstance()
                .addToCacheByToken(authorizationGrantCacheKey, authorizationGrantCacheEntry);
        AuthorizationGrantCache.getInstance()
                .addToCacheByToken(authorizationGrantCacheKeyForAccessToken, authorizationGrantCacheEntry);

        ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
        ServiceProviderProperty[] serviceProviders = new ServiceProviderProperty[]{serviceProviderProperty};
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setSpProperties(serviceProviders);
        serviceProvider.setCertificateContent("MIIDWTCCAkGgAwIBAgIEcZgeVDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJG\n" +
                "UjEMMAoGA1UECBMDTVBMMQwwCgYDVQQHEwNNUEwxDTALBgNVBAoTBHRlc3QxDTAL\n" +
                "BgNVBAsTBHRlc3QxEzARBgNVBAMMCioudGVzdC5jb20wIBcNMjEwNTEwMTcwODU4\n" +
                "WhgPMjA1MTA1MDMxNzA4NThaMFwxCzAJBgNVBAYTAkZSMQwwCgYDVQQIEwNNUEwx\n" +
                "DDAKBgNVBAcTA01QTDENMAsGA1UEChMEdGVzdDENMAsGA1UECxMEdGVzdDETMBEG\n" +
                "A1UEAwwKKi50ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                "AIkuoEuR/or5oL4h6TZ7r90Qyb1xAK6qrAHGCGWz5k1dnmCdvM39zBZF5EDGVKKe\n" +
                "p+BQWNgG+FST19Z2l71YJllKxVsI0syw3r9PXcAfVLahs3fn8HEa5uJqIdHRsVzz\n" +
                "uO+rEWYn7kx4jmwwqtb8HBnhlVgn32OWQ6X4mLll/1n87cWGMsNouVP5TCySFNyD\n" +
                "BFPzC3+gYiVVy7Aj1NBw6Ft4i4r0UIOZ8BPGfHrd7zB4Zmnc9KwyRNj+S3bvJECm\n" +
                "D1/9hMiHcIj46qnvLJw69f/HmL3LTmp1oQJUnFlA0hykrUcwjVjUEptcBMu627j4\n" +
                "kfY2xsI613k5NLi6eHlwx7cCAwEAAaMhMB8wHQYDVR0OBBYEFIg+fWViskGrce5K\n" +
                "48Oy9x1Mh0GTMA0GCSqGSIb3DQEBCwUAA4IBAQB76yS+Wkt2RBh4XEihiMsrgn9L\n" +
                "2RkxAvDldfVEZTtQHm0uOkjT53AG8RSK5tedWdETJnEa0cq9SGLBjuTB5ojjP18g\n" +
                "R3fT2HXiP2QDfqnEhj7SYOEPp+QjcgW7rPBpMVOe9qKU6BWw0/ufEFq/SgSb9/xV\n" +
                "dZa4puEYDVEJ4pu6uJuh/oXgvwcIcL6xURDav1gqTDuMrLnJrKui+FsabnWeC+XB\n" +
                "1mRWtpZPay9xB5kVWAEVdMtGePP0/wz2zxQU9uCmjwvIsIfx307CpBI54sjomXPU\n" +
                "DldsCG6l8QRJ3NvijWa/0olA/7BpaOtbNS6S5dBSfPScpUvVQiBYFFvMXbmd\n");
        ApplicationManagementService applicationMgtService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);
        Map<String, ServiceProvider> fileBasedSPs = CommonTestUtils.getFileBasedSPs();
        setFinalStatic(ApplicationManagementServiceComponent.class.getDeclaredField("fileBasedSPs"),
                                       fileBasedSPs);
        when(applicationMgtService
                     .getApplicationExcludingFileBasedSPs(TEST_APPLICATION_NAME, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(fileBasedSPs.get(TEST_APPLICATION_NAME));
        when(applicationMgtService
                .getServiceProviderNameByClientId(anyString(), anyString(),
                        anyString()))
                .thenReturn(TEST_APPLICATION_NAME);
        when(applicationMgtService
                .getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);
        AuthenticationMethodNameTranslator authenticationMethodNameTranslator =
                new AuthenticationMethodNameTranslatorImpl();
        OAuth2ServiceComponentHolder.setAuthenticationMethodNameTranslator(authenticationMethodNameTranslator);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        HashMap<String, String> claims = new HashMap<>();
        claims.put("http://wso2.org/claims/username", TestConstants.USER_NAME);
        realmService.getTenantUserRealm(SUPER_TENANT_ID).getUserStoreManager()
                    .addUser(TestConstants.USER_NAME, TestConstants.PASSWORD, new String[0], claims,
                             TestConstants.DEFAULT_PROFILE);

        Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
        publicCerts.put(SUPER_TENANT_ID, ReadCertStoreSampleUtil.createKeyStore(getClass())
                                                                .getCertificate("wso2carbon"));
        setFinalStatic(OAuth2Util.class.getDeclaredField("publicCerts"), publicCerts);
        Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
        privateKeys.put(SUPER_TENANT_ID, ReadCertStoreSampleUtil.createKeyStore(getClass())
                                                                .getKey("wso2carbon", "wso2carbon".toCharArray()));
        setFinalStatic(OAuth2Util.class.getDeclaredField("privateKeys"), privateKeys);

        OpenIDConnectServiceComponentHolder.getInstance()
                .getOpenIDConnectClaimFilters().add(new OpenIDConnectClaimFilterImpl());

        RequestObjectService requestObjectService = Mockito.mock(RequestObjectService.class);
        List<RequestedClaim> requestedClaims =  Collections.EMPTY_LIST;
        when(requestObjectService.getRequestedClaimsForIDToken(anyString())).
                thenReturn(requestedClaims);
        when(requestObjectService.getRequestedClaimsForUserInfo(anyString())).
                thenReturn(requestedClaims);
        OpenIDConnectServiceComponentHolder.getInstance()
                .getOpenIDConnectClaimFilters()
                .add(new OpenIDConnectClaimFilterImpl());
        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
        OAuth2ServiceComponentHolder.setKeyIDProvider(new DefaultKeyIDProviderImpl());
        ClaimProvider claimProvider = new OpenIDConnectSystemClaimImpl();
        List claimProviders = new ArrayList();
        claimProviders.add(claimProvider);
        WhiteboxImpl.setInternalState(OpenIDConnectServiceComponentHolder.getInstance(),
                "claimProviders", claimProviders);
    }

    @Test
    public void testBuildIDToken() throws Exception {

        String clientId = "dabfba9390aa423f8b04332794d83614";
        OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
        tokenRespDTO.setAccessToken("2sa9a678f890877856y66e75f605d456");
        AuthenticatedUser user = getDefaultAuthenticatedUserFederatedUser();
        OAuthTokenReqMessageContext messageContext = getTokenReqMessageContextForUser(user, clientId);

        mockRealmService();
        String idToken = defaultIDTokenBuilder.buildIDToken(messageContext, tokenRespDTO);
        JWTClaimsSet claims = SignedJWT.parse(idToken).getJWTClaimsSet();
        Assert.assertEquals(claims.getAudience().get(0),
                clientId);
        Assert.assertEquals(claims.getIssuer(),
                "https://localhost:9443/oauth2/token");
        Assert.assertNotNull(claims.getJWTID());
        Assert.assertEquals(claims.getSubject(), "user1");
        Assert.assertEquals(claims.getClaim("isk"), "idp");
        Assert.assertEquals(claims.getClaim("email"), "email");
        Assert.assertEquals(claims.getClaim("username"), "username");
        Assert.assertNotNull(claims.getClaim("nbf"));
        Long expirationTime = ((Date) claims.getClaim("exp")).getTime();
        Assert.assertTrue(expirationTime > (new Date()).getTime());
        Long issueTime = ((Date) claims.getClaim("iat")).getTime();
        Assert.assertTrue(issueTime <= (new Date()).getTime());
    }

    @Test
    public void testBuildIDTokenForAuthorization() throws Exception {

        String clientId = "dabfba9390aa423f8b04332794d83614";
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = new OAuth2AuthorizeRespDTO();
        AuthenticatedUser user = getDefaultAuthenticatedUserFederatedUser();
        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = getOAuthAuthzReqMessageContextForUser(user, clientId);
        oAuth2AuthorizeRespDTO.setAccessToken("2sa9a678f890877856y66e75f605d456");

        mockRealmService();
        String idToken = defaultIDTokenBuilder.buildIDToken(oAuthAuthzReqMessageContext, oAuth2AuthorizeRespDTO);
        JWTClaimsSet claims = SignedJWT.parse(idToken).getJWTClaimsSet();
        Assert.assertNotNull(claims.getJWTID());
        Assert.assertEquals(claims.getAudience().get(0), clientId);
        Assert.assertEquals(claims.getIssuer(), "https://localhost:9443/oauth2/token");
        Assert.assertEquals(claims.getSubject(), "user1");
        Assert.assertEquals(claims.getClaim("isk"), "wso2.is.com");
        Long expirationTime = ((Date) claims.getClaim("exp")).getTime();
        Assert.assertTrue(expirationTime > (new Date()).getTime());
        Long issueTime = ((Date) claims.getClaim("iat")).getTime();
        Assert.assertTrue(issueTime <= (new Date()).getTime());
    }

    @DataProvider(name = "testBuildEncryptedIDTokenForSupportedAlgorithm")
    public Object[][] testBuildEncryptedIDTokenForSupportedAlgorithm() {

        return new Object[][] {
                {"RSA-OAEP-256"}, {"RSA-OAEP"}, {"RSA1_5"}
        };
    }

    @Test(dataProvider = "testBuildEncryptedIDTokenForSupportedAlgorithm")
    public void testBuildEncryptedIDTokenForSupportedAlgorithm(String algorithm) throws Exception {

        mockRealmService();
        OAuthAppDO entry = getOAuthAppDO(algorithm);
        AppInfoCache.getInstance().addToCache(CLIENT_ID, entry);

        String idToken = defaultIDTokenBuilder.buildIDToken(messageContext, tokenRespDTO);
        EncryptedJWT encryptedJWT = decryptToken(idToken);
        JWTClaimsSet claims = encryptedJWT.getPayload().toSignedJWT().getJWTClaimsSet();
        Assert.assertNotNull(claims.getJWTID());
        Assert.assertEquals(claims.getAudience().get(0), CLIENT_ID);
        Assert.assertEquals(claims.getIssuer(), "https://localhost:9443/oauth2/token");
        Assert.assertEquals(claims.getSubject(), "user1");
        Assert.assertEquals(claims.getClaim("acr"),  "acr");
        Assert.assertEquals(claims.getClaim("isk"), "idp");
        Assert.assertEquals(claims.getClaim("nonce"), "nonce");
        Assert.assertNotNull(claims.getClaim("nbf"));
        long expirationTime = ((Date) claims.getClaim("exp")).getTime();
        Assert.assertTrue(expirationTime < (new Date()).getTime());
        long issueTime = ((Date) claims.getClaim("iat")).getTime();
        Assert.assertTrue(issueTime <= (new Date()).getTime());
    }

    @Test(dataProvider = "testBuildEncryptedIDTokenForSupportedAlgorithm")
    public void testBuildEncryptedIDTokenForAuthorization(String algorithm) throws Exception {

        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = getOAuthAuthzReqMessageContextForUser
                (getDefaultAuthenticatedLocalUser(), CLIENT_ID);
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = new OAuth2AuthorizeRespDTO();
        oAuth2AuthorizeRespDTO.setAccessToken(ACCESS_TOKEN);

        OAuthAppDO entry = getOAuthAppDO(algorithm);
        AppInfoCache.getInstance().addToCache(CLIENT_ID, entry);

        mockRealmService();
        String idToken = defaultIDTokenBuilder.buildIDToken(oAuthAuthzReqMessageContext, oAuth2AuthorizeRespDTO);
        EncryptedJWT encryptedJWT = decryptToken(idToken);
        JWTClaimsSet claims = encryptedJWT.getPayload().toSignedJWT().getJWTClaimsSet();
        Assert.assertNotNull(claims.getJWTID());
        Assert.assertEquals(claims.getAudience().get(0), CLIENT_ID);
        Assert.assertEquals(claims.getIssuer(), "https://localhost:9443/oauth2/token");
        Assert.assertEquals(claims.getSubject(),  "user1");
        Assert.assertEquals(claims.getClaim("isk"), "wso2.is.com");
        long expirationTime = ((Date) claims.getClaim("exp")).getTime();
        Assert.assertTrue(expirationTime < (new Date()).getTime());
        long issueTime = ((Date) claims.getClaim("iat")).getTime();
        Assert.assertTrue(issueTime <= (new Date()).getTime());
    }

    @DataProvider(name = "testBuildEncryptedIDTokenForUnSupportedAlgorithm")
    public Object[][] testBuildEncryptedIDTokenForUnSupportedAlgorithm() {

        return new Object[][] {
                {"A128KW"}, {"A192KW"}, {"A256KW"}, {"ECDH-ES"}, {"A256GCMKW"}
        };
    }

    @Test(dataProvider = "testBuildEncryptedIDTokenForUnSupportedAlgorithm")
    public void testBuildEncryptedIDTokenForUnSupportedAlgorithm(String algorithm) throws Exception {

        mockRealmService();
        OAuthAppDO entry = getOAuthAppDO(algorithm);
        AppInfoCache.getInstance().addToCache(CLIENT_ID, entry);

        try {
            defaultIDTokenBuilder.buildIDToken(messageContext, tokenRespDTO);
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(),
                    "Provided encryption algorithm: " + algorithm + " is not supported");
        }
    }

    @Test
    public void testClientIDNotFoundException() throws Exception {

        mockRealmService();
        String invalidClientId = "3f8b04332794d8dabfba9390aa423614";
        OAuthTokenReqMessageContext messageContext =
                getTokenReqMessageContextForUser(getDefaultAuthenticatedLocalUser(), invalidClientId);
        try {
            defaultIDTokenBuilder.buildIDToken(messageContext, tokenRespDTO);
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals(e.getMessage(),
                    "Error occurred while getting app information for client_id: " +
                            invalidClientId);
        }
    }

    @Test
    public void testClientIDNotFoundExceptionForAuthorization() throws Exception {

        String invalidClientId = "3f8b04332794d8dabfba9390aa423614";
        mockRealmService();
        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = getOAuthAuthzReqMessageContextForUser
                (getDefaultAuthenticatedLocalUser(), invalidClientId);
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = new OAuth2AuthorizeRespDTO();
        oAuth2AuthorizeRespDTO.setAccessToken("2sa9a678f890877856y66e75f605d456");
        try {
            defaultIDTokenBuilder.buildIDToken(oAuthAuthzReqMessageContext, oAuth2AuthorizeRespDTO);
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals(e.getMessage(),
                    "Error while getting the registered callback URI for client_id: " + invalidClientId);
        }
    }

    private OAuthAppDO getOAuthAppDO(String algorithm) throws Exception {

        OAuthAppDO entry = new OAuthAppDO();
        entry.setOauthConsumerKey(CLIENT_ID);
        entry.setOauthConsumerSecret("87n9a540f544777860e75f605d435");
        entry.setApplicationName("myApp");
        entry.setCallbackUrl(TestConstants.CALLBACK);
        entry.setOauthVersion("OAuth-2.0");
        entry.setState("ACTIVE");
        entry.setUserAccessTokenExpiryTime(3600000);
        entry.setApplicationAccessTokenExpiryTime(3600000);
        entry.setRefreshTokenExpiryTime(84600000);
        entry.setAppOwner(user);
        entry.setIdTokenEncryptionEnabled(true);
        entry.setIdTokenEncryptionAlgorithm(algorithm);
        entry.setIdTokenEncryptionMethod("A128GCM");
        return entry;
    }

    private EncryptedJWT decryptToken (String  token) throws Exception {

        InputStream file = Files.newInputStream(Paths.get("src/test/resources/keyStore/encryption/appKeystore.jks"));
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, "wso2carbon".toCharArray());
        String alias = "wso2carbon";
        // Get the private key. Password for the key store is 'wso2carbon'.
        RSAPrivateKey privateKey = (RSAPrivateKey) keystore.getKey(alias, "wso2carbon".toCharArray());
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        encryptedJWT.decrypt(decrypter);
        return encryptedJWT;
    }

    private AuthenticatedUser getDefaultAuthenticatedLocalUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(TestConstants.USER_NAME);
        authenticatedUser.setUserName(TestConstants.USER_NAME);
        authenticatedUser.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        authenticatedUser.setUserStoreDomain(TestConstants.USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        authenticatedUser.setFederatedUser(false);
        return authenticatedUser;
    }

    private AuthenticatedUser getDefaultAuthenticatedUserFederatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(TestConstants.USER_NAME);
        authenticatedUser.setUserName(TestConstants.USER_NAME);
        authenticatedUser.setUserStoreDomain(TestConstants.USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        authenticatedUser.setFederatedUser(true);
        return authenticatedUser;
    }

    private OAuthTokenReqMessageContext getTokenReqMessageContextForUser(AuthenticatedUser user,
                                                                              String clientId) {
        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        accessTokenReqDTO.setClientId(clientId);
        accessTokenReqDTO.setCallbackURI(TestConstants.CALLBACK);

        OAuthTokenReqMessageContext requestMsgCtx = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        requestMsgCtx.setAuthorizedUser(user);
        requestMsgCtx.setScope(TestConstants.OPENID_SCOPE_STRING.split(" "));
        return requestMsgCtx;
    }

    private OAuthAuthzReqMessageContext getOAuthAuthzReqMessageContextForUser(AuthenticatedUser user,
                                                                              String clientId) {
        OAuth2AuthorizeReqDTO authzTokenReqDTO = new OAuth2AuthorizeReqDTO();
        authzTokenReqDTO.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        authzTokenReqDTO.setConsumerKey(clientId);
        authzTokenReqDTO.setIdpSessionIdentifier(TestConstants.IDP_ENTITY_ID_ALIAS);
        authzTokenReqDTO.setUser(user);
        authzTokenReqDTO.addProperty("amr", new String[]{"amr"});
        authzTokenReqDTO.setAuthTime(1000);
        authzTokenReqDTO.setEssentialClaims(getEssentialClaims());
        authzTokenReqDTO.setNonce("nonce");
        authzTokenReqDTO.setSelectedAcr("acr");
        authzTokenReqDTO.setResponseType("token");
        return new OAuthAuthzReqMessageContext(authzTokenReqDTO);
    }

    private void mockRealmService() throws Exception {

        RealmService realmService = IdentityTenantUtil.getRealmService();
        PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .setUserRealm(realmService.getTenantUserRealm(SUPER_TENANT_ID));
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);
        OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
        TestUtil.mockRealmInIdentityTenantUtil(TestConstants.TENANT_ID, TestConstants.TENANT_DOMAIN);
    }

    private String getEssentialClaims() {

        JSONObject essentialClaims = new JSONObject();
        JSONObject claimIdToken = new JSONObject();
        JSONObject claimValue = new JSONObject();
        claimValue.put("essential", true);
        claimIdToken.put("auth_time", claimValue);
        essentialClaims.put("id_token", claimIdToken);
        return essentialClaims.toString();
    }

}
