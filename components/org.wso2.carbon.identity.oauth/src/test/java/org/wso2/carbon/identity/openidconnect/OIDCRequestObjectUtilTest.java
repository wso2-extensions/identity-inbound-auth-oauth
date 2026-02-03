/*
 * Copyright (c) 2018-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWSAlgorithm;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getRequestObjects;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@Listeners(MockitoTestNGListener.class)
public class OIDCRequestObjectUtilTest {

    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    private static final String TEST_CLIENT_ID_1 = "test-client-id";
    private static final String SOME_SERVER_URL = "some-server-url";
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";
    private static final String REQUEST_URI_PARAM_VALUE_BUILDER = "request_uri_param_value_builder";

    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;

    @Mock
    private CentralLogMgtServiceComponentHolder centralLogMgtServiceComponentHolderMock;

    @BeforeClass
    public void setUpMocks() throws Exception {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
        mockKeystores();
    }

    @AfterClass
    public void tearDown() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
        identityKeyStoreResolverMockedStatic.close();
    }

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());

    }

    @DataProvider(name = "TestBuildRequestObjectTest")
    public Object[][] buildRequestObjectData() throws Exception {
        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        Key privateKey2 = wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        return getRequestObjects(privateKey, privateKey2, publicKey, TEST_CLIENT_ID_1, SOME_SERVER_URL);
    }

    @Test(dataProvider = "TestBuildRequestObjectTest")
    public void testBuildRequestObjectTest(String requestObjectString, Map<String, Object> claims, boolean isSigned,
                                           boolean isEncrypted,
                                           boolean exceptionNotExpected,
                                           String errorMsg, boolean isFAPITest, String encryptionAlgo,
                                           String encryptionMethod) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);

            try (MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<IdentityUtil> identityUtilMockedStatic = mockStatic(IdentityUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

                OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
                oAuth2Parameters.setTenantDomain("carbon.super");
                oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);
                oAuth2Parameters.setRedirectURI(TestConstants.CALLBACK);

                OAuthAuthzRequest oAuthAuthzRequest = mock(OAuthAuthzRequest.class);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);
                when(oAuthAuthzRequest.getParam(Constants.REQUEST)).thenReturn(requestObjectString);
                centralLogMgtServiceComponentHolder.when(
                                CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                lenient().when(centralLogMgtServiceComponentHolderMock.getIdentityEventService())
                        .thenReturn(eventServiceMock);
                lenient().doNothing().when(eventServiceMock).handleEvent(any());

                identityUtilMockedStatic.when(
                                () -> IdentityUtil.getPropertyAsList(TestConstants.FAPI_SIGNATURE_ALG_CONFIGURATION))
                        .thenReturn(Arrays.asList(JWSAlgorithm.PS256.getName(), JWSAlgorithm.ES256.getName(),
                                JWSAlgorithm.RS256.getName()));

                oAuth2Util.when(() -> OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
                oAuth2Util.when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(rsaPrivateKey);
                oAuth2Util.when(() -> OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1,
                                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                        .thenReturn(clientKeyStore.getCertificate("wso2carbon"));
                oAuth2Util.when(() -> OAuth2Util.isFapiConformantApp(anyString())).thenReturn(isFAPITest);
                oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString())).thenReturn(new ServiceProvider());

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setRequestObjectSignatureValidationEnabled(isFAPITest);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CLIENT_ID_1)).thenReturn(oAuthAppDO);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(oAuthAppDO);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

                RequestObjectValidatorImpl requestObjectValidator = spy(new RequestObjectValidatorImpl());
                lenient().when((oauthServerConfigurationMock.getRequestObjectValidator()))
                        .thenReturn(requestObjectValidator);

                lenient().doReturn(SOME_SERVER_URL).when(requestObjectValidator).getTokenEpURL(anyString());

                RequestParamRequestObjectBuilder requestParamRequestObjectBuilder =
                        new RequestParamRequestObjectBuilder();
                Map<String, RequestObjectBuilder> requestObjectBuilderMap = new HashMap<>();
                requestObjectBuilderMap.put(REQUEST_PARAM_VALUE_BUILDER, requestParamRequestObjectBuilder);
                requestObjectBuilderMap.put(REQUEST_URI_PARAM_VALUE_BUILDER, null);
                lenient().when((oauthServerConfigurationMock.getRequestObjectBuilders()))
                        .thenReturn(requestObjectBuilderMap);
                try {
                    OIDCRequestObjectUtil.buildRequestObject(oAuthAuthzRequest, oAuth2Parameters);
                } catch (RequestObjectException e) {
                    Assert.assertFalse(exceptionNotExpected,
                            errorMsg + " Request Object Building failed due to " + e.getErrorMessage());
                }
            }
        }
    }

    @Test(expectedExceptions = {RequestObjectException.class})
    public void testBuildRequestObjectURITest() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
            oAuth2Parameters.setTenantDomain("carbon.super");
            oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

            OAuthAuthzRequest oAuthAuthzRequest = mock(OAuthAuthzRequest.class);
            when(oAuthAuthzRequest.getParam(Constants.REQUEST)).thenReturn(null);
            when(oAuthAuthzRequest.getParam(Constants.REQUEST_URI)).thenReturn("some-uri");

            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);

            oAuth2Util.when(() -> OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
            oAuth2Util.when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(rsaPrivateKey);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

            RequestObjectValidatorImpl requestObjectValidator = spy(new RequestObjectValidatorImpl());
            when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidator);

            doReturn(SOME_SERVER_URL.toString()).when(requestObjectValidator).getTokenEpURL(anyString());

            RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
            Map<String, RequestObjectBuilder> requestObjectBuilderMap = new HashMap<>();
            requestObjectBuilderMap.put(REQUEST_PARAM_VALUE_BUILDER, requestParamRequestObjectBuilder);
            requestObjectBuilderMap.put(REQUEST_URI_PARAM_VALUE_BUILDER, null);
            when((oauthServerConfigurationMock.getRequestObjectBuilders())).thenReturn(requestObjectBuilderMap);
            OIDCRequestObjectUtil.buildRequestObject(oAuthAuthzRequest, oAuth2Parameters);
        }
    }

    private void mockKeystores() throws IdentityKeyStoreResolverException {

        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(wso2KeyStore);
        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }

    @Test
    public void testConvertToJSONObject() {
        // Test simple map with primitives
        Map<String, Object> simpleMap = new HashMap<>();
        simpleMap.put("string", "test");
        simpleMap.put("number", 42);
        simpleMap.put("boolean", true);

        JSONObject result1 = OIDCRequestObjectUtil.convertToJSONObject(simpleMap);
        Assert.assertNotNull(result1);
        Assert.assertEquals(result1.get("string"), "test");
        Assert.assertEquals(result1.get("number"), 42);
        Assert.assertEquals(result1.get("boolean"), true);

        // Test deep nested structure (depth 4) - Array of objects with nested arrays
        Map<String, Object> deepNestedMap = new HashMap<>();
        deepNestedMap.put("level1", "value1");

        // Level 2: Array of objects
        List<Object> arrayOfObjects = new ArrayList<>();

        // First object in array (Level 3)
        Map<String, Object> obj1 = new HashMap<>();
        obj1.put("id", 1);
        obj1.put("name", "object1");

        // Level 4: Array within object
        List<Object> nestedArray = new ArrayList<>();
        nestedArray.add("item1");
        nestedArray.add(100);

        // Level 4: Object within array within object
        Map<String, Object> deepObj = new HashMap<>();
        deepObj.put("deepKey", "deepValue");
        deepObj.put("deepNumber", 999);
        nestedArray.add(deepObj);

        obj1.put("items", nestedArray);
        arrayOfObjects.add(obj1);

        // Second object in array (Level 3)
        Map<String, Object> obj2 = new HashMap<>();
        obj2.put("id", 2);
        obj2.put("type", "complex");

        // Level 4: Nested array of arrays
        List<Object> arrayOfArrays = new ArrayList<>();
        arrayOfArrays.add(Arrays.asList("a", "b", "c"));
        arrayOfArrays.add(Arrays.asList(1, 2, 3));
        obj2.put("matrix", arrayOfArrays);

        arrayOfObjects.add(obj2);

        deepNestedMap.put("objects", arrayOfObjects);

        // Level 2: Object with nested structure
        Map<String, Object> nestedObj = new HashMap<>();
        nestedObj.put("config", "enabled");

        // Level 3: Array of mixed types
        List<Object> mixedArray = new ArrayList<>();
        mixedArray.add("text");
        mixedArray.add(true);

        // Level 4: Object in mixed array
        Map<String, Object> objInMixed = new HashMap<>();
        objInMixed.put("nested", "value");
        objInMixed.put("array", Arrays.asList("x", "y", "z"));
        mixedArray.add(objInMixed);

        nestedObj.put("mixed", mixedArray);
        deepNestedMap.put("configuration", nestedObj);

        deepNestedMap.put("nullValue", null);

        JSONObject result2 = OIDCRequestObjectUtil.convertToJSONObject(deepNestedMap);
        Assert.assertNotNull(result2);

        // Verify array of objects conversion
        Assert.assertTrue(result2.get("objects") instanceof JSONArray);
        JSONArray objectsArray = (JSONArray) result2.get("objects");
        Assert.assertEquals(objectsArray.size(), 2);

        // Verify first object in array
        Assert.assertTrue(objectsArray.get(0) instanceof JSONObject);
        JSONObject firstObj = (JSONObject) objectsArray.get(0);
        Assert.assertEquals(firstObj.get("id"), 1);
        Assert.assertTrue(firstObj.get("items") instanceof JSONArray);

        JSONArray itemsArray = (JSONArray) firstObj.get("items");
        Assert.assertEquals(itemsArray.size(), 3);
        Assert.assertTrue(itemsArray.get(2) instanceof JSONObject); // Deep object

        // Verify second object with array of arrays
        Assert.assertTrue(objectsArray.get(1) instanceof JSONObject);
        JSONObject secondObj = (JSONObject) objectsArray.get(1);
        Assert.assertTrue(secondObj.get("matrix") instanceof JSONArray);

        JSONArray matrix = (JSONArray) secondObj.get("matrix");
        Assert.assertEquals(matrix.size(), 2);
        Assert.assertTrue(matrix.get(0) instanceof JSONArray);
        Assert.assertTrue(matrix.get(1) instanceof JSONArray);

        // Verify nested object with mixed array
        Assert.assertTrue(result2.get("configuration") instanceof JSONObject);
        JSONObject config = (JSONObject) result2.get("configuration");
        Assert.assertTrue(config.get("mixed") instanceof JSONArray);

        JSONArray mixedArr = (JSONArray) config.get("mixed");
        Assert.assertEquals(mixedArr.size(), 3);
        Assert.assertTrue(mixedArr.get(2) instanceof JSONObject);

        JSONObject objInMixedArr = (JSONObject) mixedArr.get(2);
        Assert.assertTrue(objInMixedArr.get("array") instanceof JSONArray);

        Assert.assertNull(result2.get("nullValue"));
    }
}
