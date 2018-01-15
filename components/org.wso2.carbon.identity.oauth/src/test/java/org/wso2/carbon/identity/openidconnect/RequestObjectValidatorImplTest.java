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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponent;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWE;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWT;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {OAuth2ServiceComponent.class})
@WithCarbonHome
@WithKeyStore
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity_req_obj.sql"}, dbName = "testdb2")
@PrepareForTest({RequestObjectValidatorImpl.class, IdentityUtil.class, IdentityTenantUtil.class,
        OAuthServerConfiguration.class, OAuth2Util.class})
@PowerMockIgnore({"javax.crypto.*"})
public class RequestObjectValidatorImplTest extends PowerMockTestCase {
    public static final String SOME_SERVER_URL = "some-server-url";
    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }

    @DataProvider(name = "provideJWT")
    public Object[][] createJWT() throws Exception {
        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        String audience = SOME_SERVER_URL;
//            String audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        HashMap claims1 = new HashMap<>();
        claims1.put(Constants.STATE, "af0ifjsldkj");
        String jsonWebToken1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", privateKey, 0,
                claims1);
        String jsonWebToken2 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1001", audience, "none", privateKey, 0,
                claims1);
        String jsonWebEncryption1 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims1);
        String jsonWebEncryption2 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims1);
        return new Object[][]{
                {jsonWebToken1, true, false, true, "Valid Request Object, signed not encrypted."},
                {jsonWebToken2, false, false, true, "Valid Request Object, signed not encrypted."},
//                    {"some-request-object", false, false, false, "Invalid Request Object, signed not encrypted."},
                {jsonWebEncryption1, false, true, true, "Valid Request Object, signed and encrypted."},
                {jsonWebEncryption2, true, true, true, "Valid Request Object, signed and encrypted."}};
    }

    @Test(dataProvider = "provideJWT")
    public void testValidateRequestObj(String jwt, boolean isSigned, boolean isEncrypted, boolean expected,
                                       String errorMsg) throws Exception {
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn("some-server-url");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(RequestObjectValidatorImpl.class);
        PowerMockito.spy(RequestObjectValidatorImpl.class);

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(SUPER_TENANT_DOMAIN_NAME)).thenReturn(SUPER_TENANT_ID);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
        when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidator);

        Path clientStorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "resources",
                "security", "client-truststore1.jks");
        Path configPath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "conf",
                "identity", "EndpointConfig.properties");

        PowerMockito.doReturn(configPath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
                "./repository/conf/identity/EndpointConfig.properties");
        PowerMockito.doReturn(clientStorePath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
                "./repository/resources/security/client-truststore.jks");

        PowerMockito.doReturn(SOME_SERVER_URL.toString()).when(RequestObjectValidatorImpl.class, "getTokenEpURL",
                anyString());


        String requestObjectString = jwt;
        RequestObject requestObject = new RequestObject();
        requestParamRequestObjectBuilder.buildRequestObject(requestObjectString,
                oAuth2Parameters, requestObject);

        Assert.assertEquals(requestObjectValidator.isEncrypted(requestObjectString), isEncrypted,
                "Payload is encrypted:" + isEncrypted);
        Assert.assertEquals(requestObjectValidator.isSigned(requestObject), isSigned,
                "Request object isSigned: " + isSigned);
        requestObject.setSigned(isSigned);
        if (isSigned) {
            requestObjectValidator.validateSignature(requestObject, TEST_CLIENT_ID_1);
        }
        Assert.assertEquals(requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters), expected,
                errorMsg);
    }

//    @Test()
//    public void validateRequestObjectTest() throws Exception {
//        RequestObjectTest requestObjectInstance = new RequestObjectTest();
//        String requestObject = requestObjectInstance.getEncodeRequestObject();
//        RequestObject requestObject1 = new RequestObject();
//        requestObject1.setSignedJWT(SignedJWT.parse(requestObject));
//        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
//        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
//        oAuth2Parameters.setTenantDomain("carbon.super");
////        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
////        mockStatic(OAuthServerConfiguration.class);
////        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
////
////        mockStatic(OAuth2Util.class);
////        when(OAuth2Util.isValidJson(requestObject)).thenReturn(false);
//
//        mockStatic(RequestObjectValidatorImpl.class);
//        PowerMockito.spy(RequestObjectValidatorImpl.class);
//        Path clientStorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "resources",
//                "security", "client-truststore.jks");
//        Path configPath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "conf",
//                "identity", "EndpointConfig.properties");
//
//        PowerMockito.doReturn(configPath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
//                "./repository/conf/identity/EndpointConfig.properties");
//        PowerMockito.doReturn(clientStorePath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
//                "./repository/resources/security/client-truststore.jks");
//        Assert.assertFalse(requestObjectValidator.isEncrypted(requestObject), "Payload is encrypted.");
//        requestObject1.setSigned(requestObjectValidator.isSigned(requestObject1));
//        requestObjectValidator.validateRequestObject(requestObject1, oAuth2Parameters);
//    }

//    @Test()
//    public void DecryptTest() throws Exception {
//        RequestObjectTest requestObjectInstance = new RequestObjectTest();
//        String requestObject = requestObjectInstance.getEncryptedRequestObject();
//        RequestObject requestObject1 = new RequestObject();
//        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
//        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
//        oAuth2Parameters.setTenantDomain("carbon.super");
//
//        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
//        rsaPrivateKey = Mockito.mock(RSAPrivateKey.class);
////        rsaPrivateKey = wso2KeyStore.g
//        PrivateKey privateKey = mock(PrivateKey.class);
//
//        KeyStoreManager keyStoreManagerMock = mock(KeyStoreManager.class);
//        when(keyStoreManagerMock.getDefaultPrivateKey()).thenReturn(privateKey);
//
//        mockStatic(KeyStoreManager.class);
//        when(KeyStoreManager.getInstance(-1234)).thenReturn(keyStoreManagerMock);
//
//        mockStatic(OAuthServerConfiguration.class);
//        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
//
//        mockStatic(OAuth2Util.class);
//        when(OAuth2Util.isValidJson(requestObject)).thenReturn(false);
//        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
//        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);
//        Assert.assertTrue(requestObjectValidator.isEncrypted(requestObject), "Payload is not encrypted.");
//        requestObject1.setSignedJWT(SignedJWT.parse(requestObjectValidator.decrypt(requestObject, oAuth2Parameters)));
//        requestObjectValidator.validateRequestObject(requestObject1, oAuth2Parameters);
//    }


}
