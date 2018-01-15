/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWSAlgorithm;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWE;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWT;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;

@PrepareForTest({OAuth2Util.class, IdentityUtil.class, OAuthServerConfiguration.class, OAuthAuthzRequest.class,
        RequestObjectValidatorImpl.class})
@PowerMockIgnore({"javax.crypto.*"})
public class OIDCRequestObjectFactoryTest extends PowerMockTestCase {

    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";
    public static final String SOME_SERVER_URL = "some-server-url";
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";
    private static final String REQUEST_URI_PARAM_VALUE_BUILDER = "request_uri_param_value_builder";

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }

    @DataProvider(name = "TestBuildRequestObjectTest")
    public Object[][] buildRequestObjectData() throws Exception {
        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        Key privateKey2 = wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        String audience = SOME_SERVER_URL;

        Map<String,Object> claims1 = new HashMap<>();
        Map<String,Object> claims2 = new HashMap<>();
        Map<String,Object> claims3 = new HashMap<>();
        Map<String,Object> claims4 = new HashMap<>();

        claims1.put(Constants.STATE, "af0ifjsldkj");
        claims1.put(Constants.CLIENT_ID, TEST_CLIENT_ID_1);

        JSONObject userInfoClaims = new JSONObject();
        userInfoClaims.put("essential", true);
        userInfoClaims.put("value", "some-value");
        JSONArray valuesArray = new JSONArray();
        valuesArray.add("value1");
        valuesArray.add("value2");
        userInfoClaims.put("values", valuesArray);
        JSONObject userInfoClaim = new JSONObject();
        userInfoClaim.put("user_info", userInfoClaims);
        JSONObject acr = new JSONObject();
        acr.put("acr", userInfoClaim);
        claims2.put("claims", acr);

        claims3.put(Constants.CLIENT_ID, "some-string");

        JSONObject givenName = new JSONObject();
        givenName.put("given_name", null);

        JSONObject idTokenClaim = new JSONObject();
        idTokenClaim.put("id_token", givenName);
        claims4.put("claims", idTokenClaim);

        String jsonWebToken1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", privateKey, 0,
                claims1);
        String jsonWebToken2 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1001", audience, "none", privateKey, 0,
                claims1);
        String jsonWebToken3 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1002", audience, "RSA265", privateKey, 0,
                claims2);
        String jsonWebToken4 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1003", audience, "none", privateKey, 0,
                claims2);
        String jsonWebToken5 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1004", audience, "none", privateKey, 0,
                claims3);
        String jsonWebToken6 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1005", audience, "RSA265", privateKey2, 0,
                claims2);
        String jsonWebToken7 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", privateKey, 0,
                claims4);
        String jsonWebEncryption1 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims1);
        String jsonWebEncryption2 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims1);
        return new Object[][]{
                {jsonWebToken1, claims1, true, false, true, "Valid Request Object, signed, not encrypted."},
                {jsonWebToken2, claims1, false, false, true, "Valid Request Object, not signed, not encrypted."},
                {jsonWebToken3, claims2, true, false, true, "Valid Request Object, signed, not encrypted."},
                {jsonWebToken4, claims2, false, false, true, "Valid Request Object, not signed, not encrypted."},
                {jsonWebToken5, claims3, false, false, false, "Invalid Request Object, not signed, not encrypted, " +
                        "mismatching client_id."},
                {jsonWebToken6, claims2, true, false, false, "Invalid Request Object, signed but with different key, " +
                        "not encrypted."},
                {jsonWebToken7, claims4, true, false, true, "Valid Request Object, signed, not encrypted."},
                {"some-request-object", null, false, false, false, "Non JWT Request Object string, " +
                        "signed not encrypted."},
                {"", null, false, false, false, "Invalid Request Object, signed not encrypted."},
                {jsonWebEncryption1, claims1, false, true, true, "Valid Request Object, signed and encrypted."},
                {jsonWebEncryption2, claims1, true, true, true, "Valid Request Object, signed and encrypted."}
        };
    }

    @Test(dataProvider = "TestBuildRequestObjectTest")
    public void testBuildRequestObjectTest(String requestObjectString, Map<String, Object> claims, boolean isSigned,
                                           boolean isEncrypted,
                                           boolean exceptionNotExpected,
                                           String errorMsg) throws Exception {
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");
        oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

        OAuthAuthzRequest oAuthAuthzRequest = mock(OAuthAuthzRequest.class);
        when(oAuthAuthzRequest.getParam(Constants.REQUEST)).thenReturn(requestObjectString);

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(RequestObjectValidatorImpl.class);
        PowerMockito.spy(RequestObjectValidatorImpl.class);

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
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

        RequestObject requestObject = new RequestObject();
        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
        Map<String, RequestObjectBuilder> requestObjectBuilderMap = new HashMap<>();
        requestObjectBuilderMap.put(REQUEST_PARAM_VALUE_BUILDER, requestParamRequestObjectBuilder);
        requestObjectBuilderMap.put(REQUEST_URI_PARAM_VALUE_BUILDER, null);
        when((oauthServerConfigurationMock.getRequestObjectBuilders())).thenReturn(requestObjectBuilderMap);

        OIDCRequestObjectFactory oidcRequestObjectFactory = new OIDCRequestObjectFactory();
        try {
            oidcRequestObjectFactory.buildRequestObject(oAuthAuthzRequest, oAuth2Parameters, requestObject);
        } catch (RequestObjectException e) {
            Assert.assertFalse(exceptionNotExpected, errorMsg + "Request Object Building failed.");
        }


    }

    @Test(expectedExceptions = {RequestObjectException.class})
    public void testBuildRequestObjectURITest() throws Exception {
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");
        oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

        OAuthAuthzRequest oAuthAuthzRequest = mock(OAuthAuthzRequest.class);
        when(oAuthAuthzRequest.getParam(Constants.REQUEST_URI)).thenReturn("some-uri");

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(RequestObjectValidatorImpl.class);
        PowerMockito.spy(RequestObjectValidatorImpl.class);

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
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

        RequestObject requestObject = new RequestObject();
        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
        Map<String, RequestObjectBuilder> requestObjectBuilderMap = new HashMap<>();
        requestObjectBuilderMap.put(REQUEST_PARAM_VALUE_BUILDER, requestParamRequestObjectBuilder);
        requestObjectBuilderMap.put(REQUEST_URI_PARAM_VALUE_BUILDER, null);
        when((oauthServerConfigurationMock.getRequestObjectBuilders())).thenReturn(requestObjectBuilderMap);

        OIDCRequestObjectFactory oidcRequestObjectFactory = new OIDCRequestObjectFactory();
        oidcRequestObjectFactory.buildRequestObject(oAuthAuthzRequest, oAuth2Parameters, requestObject);
    }
}
