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
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponent;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWE;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWT;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWTWithExpiry;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {OAuth2ServiceComponent.class})
@WithCarbonHome
@WithKeyStore
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbScripts/identity_req_obj.sql"}, dbName = "testdb2")
@PrepareForTest({RequestObjectValidatorImpl.class, IdentityUtil.class, IdentityTenantUtil.class,
        OAuthServerConfiguration.class, OAuth2Util.class})
@PowerMockIgnore({"javax.crypto.*"})
public class RequestObjectValidatorImplTest extends PowerMockTestCase {
    public static final String SOME_SERVER_URL = "some-server-url";
    public static final String CLIENT_PUBLIC_CERT_ALIAS = "wso2carbon";
    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore =
                getKeyStoreFromFile("testkeystore.jks", CLIENT_PUBLIC_CERT_ALIAS, System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }

    @DataProvider(name = "provideJWT")
    public Object[][] createJWT() throws Exception {
        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        String audience = SOME_SERVER_URL;

        HashMap<String, Object> claims1 = new HashMap<>();
        claims1.put(Constants.STATE, "af0ifjsldkj");
        String jsonWebToken1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", privateKey, 0,
                claims1);
        String jsonWebToken2 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1001", audience, "none", privateKey, 0,
                claims1);
        String jsonWebToken3 = buildJWTWithExpiry(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1003", audience, "none",
                privateKey, 0, claims1, (- 3600 * 1000));
        String jsonWebToken4 = buildJWTWithExpiry(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1004", audience, "RSA265",
                privateKey, 0,claims1, (- 3600 * 1000));
        String jsonWebEncryption1 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims1);
        String jsonWebEncryption2 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims1);
        return new Object[][]{
                {jsonWebToken1, true, false, true, true, "Valid Request Object, signed not encrypted."},
                {jsonWebToken2, false, false, true, true, "Valid Request Object, not xsigned not encrypted."},
                {jsonWebToken3, false, false, true, false, "InValid Request Object, expired, not signed not " +
                        "encrypted."},
                {jsonWebToken4, true, false, true, false, "InValid Request Object, expired, signed not encrypted."},
                {jsonWebEncryption1, false, true, true, true, "Valid Request Object, signed and encrypted."},
                {jsonWebEncryption2, true, true, true, true, "Valid Request Object, signed and encrypted."}
        };
    }

    @Test(dataProvider = "provideJWT")
    public void testValidateRequestObj(String jwt,
                                       boolean isSigned,
                                       boolean isEncrypted,
                                       boolean validSignature,
                                       boolean validRequestObj,
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

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(SUPER_TENANT_DOMAIN_NAME)).thenReturn(SUPER_TENANT_ID);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        // Mock OAuth2Util returning public cert of the service provider
        when(OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(clientKeyStore.getCertificate(CLIENT_PUBLIC_CERT_ALIAS));

        RequestObjectValidatorImpl requestObjectValidator = PowerMockito.spy(new RequestObjectValidatorImpl());

        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
        when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidator);

        PowerMockito.doReturn(SOME_SERVER_URL).when(requestObjectValidator, "getTokenEpURL", anyString());

        RequestObject requestObject = requestParamRequestObjectBuilder.buildRequestObject(jwt, oAuth2Parameters);

        Assert.assertEquals(requestParamRequestObjectBuilder.isEncrypted(jwt), isEncrypted,
                "Payload is encrypted:" + isEncrypted);
        Assert.assertEquals(requestObjectValidator.isSigned(requestObject), isSigned,
                "Request object isSigned: " + isSigned);

        if (isSigned) {
            Assert.assertEquals(requestObjectValidator.validateSignature(requestObject, oAuth2Parameters),
                    validSignature, errorMsg + "Request Object Signature Validation failed.");
        }

        boolean validObject;
        try {
            validObject = requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        } catch (Exception e) {
            validObject = false;
        }
        Assert.assertEquals(validObject, validRequestObj, errorMsg);
    }
}
