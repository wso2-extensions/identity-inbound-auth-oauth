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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.OpaqueRSAKeyTestProvider;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.identity.openidconnect.util.TestUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.expectThrows;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getRequestObjects;

@Listeners(MockitoTestNGListener.class)
public class RequestParamRequestObjectBuilderTest {

    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";
    public static final String SOME_SERVER_URL = "some-server-url";

    @Mock
    private CentralLogMgtServiceComponentHolder centralLogMgtServiceComponentHolderMock;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }

    @DataProvider(name = "TestBuildRequestObjectTest")
    public Object[][] buildRequestObjectData() throws Exception {

        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        Key privateKey2 = wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        return getRequestObjects(privateKey, privateKey2, publicKey, TEST_CLIENT_ID_1, SOME_SERVER_URL);
    }

    @Test(dataProvider = "TestBuildRequestObjectTest")
    public void buildRequestObjectTest(String requestObjectString, Map<String, Object> claims, boolean isSigned,
                                       boolean isEncrypted,
                                       boolean exceptionNotExpected,
                                       String errorMsg, boolean isFAPITest, String encryptionAlgo,
                                       String encryptionMethod) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);

            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class, CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);
                centralLogMgtServiceComponentHolder.when(CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                lenient().when(centralLogMgtServiceComponentHolderMock.getIdentityEventService())
                        .thenReturn(eventServiceMock);
                lenient().doNothing().when(eventServiceMock).handleEvent(any());
                identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                        .thenReturn("some-server-url");

                OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
                oAuth2Parameters.setTenantDomain("carbon.super");
                oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

//        MockedStatic<RequestObjectValidatorImpl> requestObjectValidator =
//                mockStatic(RequestObjectValidatorImpl.class);
//        spy(RequestObjectValidatorImpl.class);

                rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
                oAuth2Util.when(() -> OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
                oAuth2Util.when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(rsaPrivateKey);
                oAuth2Util.when(() -> OAuth2Util.asPrivateKey(any(), anyString())).thenCallRealMethod();
                oAuth2Util.when(() -> OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1,
                                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                        .thenReturn(clientKeyStore.getCertificate("wso2carbon"));

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setRequestObjectEncryptionMethod(encryptionMethod);
                oAuthAppDO.setRequestObjectEncryptionAlgorithm(encryptionAlgo);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(oAuthAppDO);

                RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
                lenient().when((oauthServerConfigurationMock.getRequestObjectValidator()))
                        .thenReturn(requestObjectValidator);

                RequestObject requestObject;
                RequestParamRequestObjectBuilder requestParamRequestObjectBuilder =
                        new RequestParamRequestObjectBuilder();

                try {
                    requestObject =
                            requestParamRequestObjectBuilder.buildRequestObject(requestObjectString, oAuth2Parameters);
                    Assert.assertEquals(requestObject.isSigned(), isSigned, errorMsg);
                    if (claims != null && !claims.isEmpty()) {
                        for (Map.Entry<String, Object> entry : claims.entrySet()) {
                            if ("nbf".equals(entry.getKey()) || "exp".equals(entry.getKey())) {
                                Assert.assertEquals(((Date) requestObject.getClaim(entry.getKey())).getTime() / 1000,
                                        entry.getValue(), "Request object claim:" + entry.getKey() +
                                                " is not properly set.");
                            } else {
                                Assert.assertEquals(requestObject.getClaim(entry.getKey()), entry.getValue(),
                                        "Request object claim:" + entry.getKey() + " is not properly set.");
                            }
                        }
                    }
                } catch (RequestObjectException e) {
                    Assert.assertFalse(exceptionNotExpected, errorMsg + " Building failed due to " + e.getMessage());
                }
            }
        }
    }

    @DataProvider(name = "jweAlgorithms")
    public Object[][] jweAlgorithms() {

        return new Object[][]{{JWEAlgorithm.RSA1_5}, {JWEAlgorithm.RSA_OAEP}, {JWEAlgorithm.RSA_OAEP_256},
                {JWEAlgorithm.RSA_OAEP_512}};
    }

    @Test(dataProvider = "jweAlgorithms")
    public void testDecryptWithOpaqueKey(JWEAlgorithm algorithm) throws Exception {

        // A key held in an HSM: like SunPKCS11 together with the server's PKCS11 OAEP provider, registered after the
        // JDK providers. JCA selects that provider because the decrypter names none.
        OpaqueRSAKeyTestProvider token = new OpaqueRSAKeyTestProvider(2048, true);
        Security.addProvider(token);
        try {
            String requestObject = signedRequestObject();
            String jwe = encrypt(requestObject, algorithm, (RSAPublicKey) token.getPublicKey());

            assertEquals(decrypt(jwe, algorithm, token.getPrivateKey()), requestObject);
        } finally {
            Security.removeProvider(token.getName());
        }
    }

    @Test
    public void testOpaqueKeyRSAOAEPNeedsProviderSupport() throws Exception {

        // SunPKCS11 alone offers PKCS#1 v1.5 only: RSA1_5 decrypts, RSA-OAEP needs the server's PKCS11 OAEP provider.
        OpaqueRSAKeyTestProvider token = new OpaqueRSAKeyTestProvider(2048, false);
        Security.addProvider(token);
        try {
            String requestObject = signedRequestObject();
            RSAPublicKey publicKey = (RSAPublicKey) token.getPublicKey();
            String oaep = encrypt(requestObject, JWEAlgorithm.RSA_OAEP_256, publicKey);

            expectThrows(RequestObjectException.class,
                    () -> decrypt(oaep, JWEAlgorithm.RSA_OAEP_256, token.getPrivateKey()));
            assertEquals(decrypt(encrypt(requestObject, JWEAlgorithm.RSA1_5, publicKey), JWEAlgorithm.RSA1_5,
                    token.getPrivateKey()), requestObject);
        } finally {
            Security.removeProvider(token.getName());
        }
    }

    private String decrypt(String jwe, JWEAlgorithm algorithm, PrivateKey decryptionKey) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mock(OAuthServerConfiguration.class));
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setRequestObjectEncryptionAlgorithm(algorithm.getName());
                oAuthAppDO.setRequestObjectEncryptionMethod(EncryptionMethod.A256GCM.getName());
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(oAuthAppDO);
                oAuth2Util.when(() -> OAuth2Util.getTenantId(anyString())).thenReturn(-1234);
                oAuth2Util.when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(decryptionKey);
                oAuth2Util.when(() -> OAuth2Util.asPrivateKey(any(), anyString())).thenCallRealMethod();

                OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
                oAuth2Parameters.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);
                return new RequestParamRequestObjectBuilder().decrypt(jwe, oAuth2Parameters);
            }
        }
    }

    private String signedRequestObject() throws Exception {

        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(TEST_CLIENT_ID_1).audience(SOME_SERVER_URL)
                .claim("client_id", TEST_CLIENT_ID_1).claim("scope", "openid").build();
        return TestUtils.signJWTWithRSA(claims, clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray()));
    }

    private static String encrypt(String requestObject, JWEAlgorithm algorithm, RSAPublicKey publicKey)
            throws Exception {

        JWEObject jwe = new JWEObject(new JWEHeader.Builder(algorithm, EncryptionMethod.A256GCM).contentType("JWT")
                .build(), new Payload(requestObject));
        jwe.encrypt(new RSAEncrypter(publicKey));
        return jwe.serialize();
    }
}
