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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

@PrepareForTest({CarbonUtils.class, IdentityTenantUtil.class, IdentityUtil.class, OAuthServerConfiguration.class,
        KeyStoreManager.class, OAuth2Util.class})
public class JwksEndpointTest extends PowerMockIdentityBaseTest {

    @Mock
    ServerConfiguration serverConfiguration;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    KeyStoreManager keyStoreManager;

    private static final String CERT_THUMB_PRINT = "generatedCertThrumbPrint";
    private static final String ALG = "RS256";
    private static final String USE = "sig";
    private JwksEndpoint jwksEndpoint;
    private Object identityUtilObj;

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        jwksEndpoint = new JwksEndpoint();

        Class<?> clazz = IdentityUtil.class;
        identityUtilObj = clazz.newInstance();
    }

    @DataProvider (name = "provideTenantDomain")
    public Object[][] provideTenantDomain() {
        return new Object[][] {
                {null, MultitenantConstants.SUPER_TENANT_ID},
                {"", MultitenantConstants.SUPER_TENANT_ID},
                {"foo.com", 1},
                {"invalid.com", -1},
        };
    }

    @Test(dataProvider = "provideTenantDomain")
    public void testJwks(String tenantDomain, int tenantId) throws Exception {
        Path keystorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "resources",
                "security", "wso2carbon.jks");
        mockOAuthServerConfiguration();
        mockStatic(CarbonUtils.class);
        when(CarbonUtils.getServerConfiguration()).thenReturn(serverConfiguration);
        when(serverConfiguration.getFirstProperty("Security.KeyStore.Location")).thenReturn(keystorePath.toString());
        when(serverConfiguration.getFirstProperty("Security.KeyStore.Password")).thenReturn("wso2carbon");
        when(serverConfiguration.getFirstProperty("Security.KeyStore.KeyAlias")).thenReturn("wso2carbon");


        ThreadLocal<Map<String, Object>> threadLocalProperties = new ThreadLocal() {
            protected Map<String, Object> initialValue() {
                return new HashMap();
            }
        };

        threadLocalProperties.get().put(OAuthConstants.TENANT_NAME_FROM_CONTEXT, tenantDomain);

        Field threadLocalPropertiesField = identityUtilObj.getClass().getDeclaredField("threadLocalProperties");
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(threadLocalPropertiesField, threadLocalPropertiesField.getModifiers() & ~Modifier.FINAL);
        threadLocalPropertiesField.setAccessible(true);
        threadLocalPropertiesField.set(identityUtilObj, threadLocalProperties);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(tenantId);

        mockStatic(OAuth2Util.class);

        if (tenantDomain == null) {
            when(OAuth2Util.getThumbPrint(any(), anyString())).thenThrow(new IdentityOAuth2Exception("error"));
        } else {
            when(OAuth2Util.getThumbPrint(any(), anyString())).thenReturn(CERT_THUMB_PRINT);
        }
        when(OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString())).thenReturn(JWSAlgorithm.RS256);
        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(anyInt())).thenReturn(keyStoreManager);
        when(keyStoreManager.getKeyStore("foo-com.jks")).thenReturn(getKeyStoreFromFile("foo-com.jks", "foo.com"));

        String result = jwksEndpoint.jwks();

        try {
            JSONObject jwksJson = new JSONObject(result);
            JSONArray objectArray = jwksJson.getJSONArray("keys");
            JSONObject keyObject = objectArray.getJSONObject(0);
            assertEquals(keyObject.get("kid"), CERT_THUMB_PRINT, "Incorrect kid value");
            assertEquals(keyObject.get("alg"), ALG, "Incorrect alg value");
            assertEquals(keyObject.get("use"), USE, "Incorrect use value");
            assertEquals(keyObject.get("kty"), "RSA", "Incorrect kty value");
        } catch (JSONException e) {
            if ("invalid.com".equals(tenantDomain)) {
                assertTrue(result.contains("Invalid Tenant"),
                        "Error message for non existing tenant is not found");
            } else if (tenantDomain == null) {
                assertTrue(result.contains("Error while generating the keyset for"),
                        "Error message for thrown exception is not found");
            } else {
                fail("Unexpected exception: " + e.getMessage());
            }
        }

        threadLocalProperties.get().remove(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
    }

    private void mockOAuthServerConfiguration() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(oAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn("SHA256withRSA");
    }

    private KeyStore getKeyStoreFromFile(String keystoreName, String password) throws Exception {
        Path tenantKeystorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository",
                "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }
}
