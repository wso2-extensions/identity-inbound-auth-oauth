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
package org.wso2.carbon.identity.oauth.endpoint.introspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * This class does unit test coverage for RecoveryConfigImpl class
 */
@PrepareForTest({OAuthServerConfiguration.class})
public class IntrospectionResponseBuilderTest extends PowerMockIdentityBaseTest {

    private IntrospectionResponseBuilder introspectionResponseBuilder1;

    private IntrospectionResponseBuilder introspectionResponseBuilder2;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;
    List<String> filteredIntrospectionClaims = new ArrayList<>();

    @BeforeClass
    public void setUp() {

        introspectionResponseBuilder1 = new IntrospectionResponseBuilder();
        introspectionResponseBuilder2 = new IntrospectionResponseBuilder();

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
    }

    @DataProvider(name = "provideBuilderData")
    public Object[][] provideBuilderData() {

        return new Object[][]{
                // Token is active and none zero expiration and notBefore values will be added by builder
                {true, 7343678, 1452173776, true},
                // Expiration and notBefore values will not be saved since the token is not active
                {false, 7343678, 1452173776, false},
                // Expiration and notBefore values will not be saved since the values are zero
                {true, 0, 0, false},
        };
    }

    /**
     * This method does unit test for build response with values
     */
    @Test(dataProvider = "provideBuilderData")
    public void testResposeBuilderWithVal(boolean isActive, int notBefore, int expiration, boolean timesSetInJson)
            throws Exception {

        String idToken = "eyJhbGciOiJSUzI1NiJ9.eyJhdXRoX3RpbWUiOjE0NTIxNzAxNzYsImV4cCI6MTQ1MjE3Mzc3Niwic3ViI" +
                "joidXNlQGNhcmJvbi5zdXBlciIsImF6cCI6IjF5TDFfZnpuekdZdXRYNWdCMDNMNnRYR3lqZ2EiLCJhdF9oYXNoI" +
                "joiWWljbDFlNTI5WlhZOE9zVDlvM3ktdyIsImF1ZCI6WyIxeUwxX2Z6bnpHWXV0WDVnQjAzTDZ0WEd5amdhIl0s" +
                "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImlhdCI6MTQ1MjE3MDE3Nn0.RqAgm0ybe7tQ" +
                "YvQYi7uqEtzWf6wgDv5sJq2UIQRC4OJGjn_fTqftIWerZc7rIMRYXi7jzuHxX_GabUhuj7m1iRzi1wgxbI9yQn825lDVF4Lt9" +
                "DMUTBfKLk81KIy6uB_ECtyxumoX3372yRgC7R56_L_hAElflgBsclEUwEH9psE";

        mockOAuthServerConfiguration(filteredIntrospectionClaims);

        introspectionResponseBuilder1.setActive(isActive);
        introspectionResponseBuilder1.setIssuedAt(1452170176);
        introspectionResponseBuilder1.setJwtId(idToken);
        introspectionResponseBuilder1.setSubject("admin@carbon.super");
        introspectionResponseBuilder1.setExpiration(expiration);
        introspectionResponseBuilder1.setUsername("admin@carbon.super");
        introspectionResponseBuilder1.setTokenType("Bearer");
        introspectionResponseBuilder1.setNotBefore(notBefore);
        introspectionResponseBuilder1.setAudience("1yL1_fznzGYutX5gB03L6tXGyjga");
        introspectionResponseBuilder1.setIssuer("https:\\/\\/localhost:9443\\/oauth2\\/token");
        introspectionResponseBuilder1.setScope("test");
        introspectionResponseBuilder1.setClientId("rgfKVdnMQnJSSr_pKFTxj3apiwYa");
        introspectionResponseBuilder1.setErrorCode("Invalid input");
        introspectionResponseBuilder1.setErrorDescription("error_discription");
        introspectionResponseBuilder1.setAuthorizedUserType(OAuthConstants.UserType.APPLICATION_USER);
        introspectionResponseBuilder1.setCnfBindingValue("R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");

        JSONObject jsonObject = new JSONObject(introspectionResponseBuilder1.build());

        assertEquals(jsonObject.has(IntrospectionResponse.EXP), timesSetInJson, "Unexpected exp value");
        assertEquals(jsonObject.has(IntrospectionResponse.NBF), timesSetInJson, "Unexpected nbf value");
        assertEquals(jsonObject.get(IntrospectionResponse.IAT), 1452170176, "IAT values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.JTI), idToken, "JTI values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.SUB), "admin@carbon.super",
                "SUBJECT values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.USERNAME), "admin@carbon.super",
                "USERNAME values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.TOKEN_TYPE), "Bearer",
                "TOKEN_TYPE values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.AUD), "1yL1_fznzGYutX5gB03L6tXGyjga",
                "AUD values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.ISS), "https:\\/\\/localhost:9443\\/oauth2\\/token",
                "ISS values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.SCOPE), "test",
                "SCOPE values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.CLIENT_ID), "rgfKVdnMQnJSSr_pKFTxj3apiwYa",
                "CLIENT_ID values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.Error.ERROR), "Invalid input",
                "ERROR messages are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.Error.ERROR_DESCRIPTION), "error_discription",
                "ERROR_DESCRIPTION messages are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.AUT), "APPLICATION_USER",
                "AUT values are not equal");
        Map<String, Object> cnf = new ObjectMapper()
                .readValue(jsonObject.get(IntrospectionResponse.CNF).toString(), HashMap.class);
        assertEquals(cnf.get(OAuthConstants.X5T_S256), "R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9",
                "CNF value is not equal");
    }

    /**
     * This method does unit test for build response without values
     */
    @Test
    public void testResposeBuilderWithoutVal() {

        mockOAuthServerConfiguration(filteredIntrospectionClaims);

        introspectionResponseBuilder2.setActive(false);
        introspectionResponseBuilder2.setIssuedAt(0);
        introspectionResponseBuilder2.setJwtId("");
        introspectionResponseBuilder2.setSubject("");
        introspectionResponseBuilder2.setExpiration(0);
        introspectionResponseBuilder2.setUsername("");
        introspectionResponseBuilder2.setTokenType("");
        introspectionResponseBuilder2.setNotBefore(0);
        introspectionResponseBuilder2.setAudience("");
        introspectionResponseBuilder2.setIssuer("");
        introspectionResponseBuilder2.setScope("");
        introspectionResponseBuilder2.setClientId("");
        introspectionResponseBuilder2.setErrorCode("");
        introspectionResponseBuilder2.setErrorDescription("");
        introspectionResponseBuilder2.setAuthorizedUserType("");
        introspectionResponseBuilder2.setCnfBindingValue("");

        JSONObject jsonObject2 = new JSONObject(introspectionResponseBuilder2.build());
        assertFalse(jsonObject2.has(IntrospectionResponse.EXP), "EXP already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.NBF), "NBF already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.IAT), "IAT already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.JTI), "JTI already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.SUB), "sub already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.USERNAME), "USERNAME already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.TOKEN_TYPE),
                "TOKEN_TYPE already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.AUD), "AUD already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.ISS), "ISS already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.SCOPE), "SCOPE already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.CLIENT_ID),
                "CLIENT_ID already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.Error.ERROR), "ERROR already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.Error.ERROR_DESCRIPTION),
                "ERROR_DESCRIPTION already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.AUT), "AUT already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.CNF), "CNF value exists in the response builder");
    }

    @Test(dependsOnMethods = "testResposeBuilderWithVal")
    public void testResponseBuilderWithAdditionalProperties() throws Exception {

        Map<String, Object> additionalData = new HashMap<>();
        List<Map<String, Object>> permissions = new ArrayList<>();

        mockOAuthServerConfiguration(filteredIntrospectionClaims);

        Map<String, Object> resource1 = new HashMap<>();
        String resourceIdKey = "resource_id";
        String resourceScopesKey = "resource_scopes";
        String permissionKey = "permission";

        resource1.put(resourceIdKey, "resource-id-1");
        List<String> scopesList1 = new ArrayList<>();
        scopesList1.add("view");
        scopesList1.add("edit");
        resource1.put(resourceScopesKey, scopesList1);

        Map<String, Object> resource2 = new HashMap<>();
        resource2.put(resourceIdKey, "resource-id-2");
        List<String> scopesList2 = new ArrayList<>();
        scopesList2.add("view");
        scopesList2.add("edit");
        resource2.put(resourceScopesKey, scopesList2);

        permissions.add(resource1);
        permissions.add(resource2);

        additionalData.put(permissionKey, permissions);
        introspectionResponseBuilder1.setAdditionalData(additionalData);

        JSONObject permissionEntry = new JSONObject(introspectionResponseBuilder1.build());
        assertTrue(permissionEntry.has(permissionKey), permissionKey + " key not found in introspection response.");

        JSONArray resourcesArray = permissionEntry.getJSONArray(permissionKey);
        assertEquals(resourcesArray.length(), 2, "Resources array should contain 2 elements.");

        JSONObject resourceEntry = resourcesArray.getJSONObject(1);
        assertTrue(resourceEntry.has(resourceIdKey), resourceIdKey + " key not found in introspection response.");
        assertTrue(resourceEntry.has(resourceScopesKey), resourceScopesKey + " key not found in introspection " +
                "response.");
    }

    /**
     * This method does unit test for build response with username as a filtered values
     */
    @Test (priority = 1)
    public void testResponseBuilderWithFilteredUsernameClaims() {

        String idToken = "eyJhbGciOiJSUzI1NiJ9.eyJhdXRoX3RpbWUiOjE0NTIxNzAxNzYsImV4cCI6MTQ1MjE3Mzc3Niwic3ViI" +
                "joidXNlQGNhcmJvbi5zdXBlciIsImF6cCI6IjF5TDFfZnpuekdZdXRYNWdCMDNMNnRYR3lqZ2EiLCJhdF9oYXNoI" +
                "joiWWljbDFlNTI5WlhZOE9zVDlvM3ktdyIsImF1ZCI6WyIxeUwxX2Z6bnpHWXV0WDVnQjAzTDZ0WEd5amdhIl0s" +
                "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImlhdCI6MTQ1MjE3MDE3Nn0.RqAgm0ybe7tQ" +
                "YvQYi7uqEtzWf6wgDv5sJq2UIQRC4OJGjn_fTqftIWerZc7rIMRYXi7jzuHxX_GabUhuj7m1iRzi1wgxbI9yQn825lDVF4Lt9" +
                "DMUTBfKLk81KIy6uB_ECtyxumoX3372yRgC7R56_L_hAElflgBsclEUwEH9psE";

        introspectionResponseBuilder1.setActive(true);
        introspectionResponseBuilder1.setIssuedAt(1452170176);
        introspectionResponseBuilder1.setJwtId(idToken);
        introspectionResponseBuilder1.setSubject("admin@carbon.super");
        introspectionResponseBuilder1.setExpiration(7343678);
        introspectionResponseBuilder1.setUsername("admin@carbon.super");
        introspectionResponseBuilder1.setTokenType("Bearer");
        introspectionResponseBuilder1.setNotBefore(1452173776);
        introspectionResponseBuilder1.setAudience("1yL1_fznzGYutX5gB03L6tXGyjga");
        introspectionResponseBuilder1.setIssuer("https:\\/\\/localhost:9443\\/oauth2\\/token");
        introspectionResponseBuilder1.setScope("test");
        introspectionResponseBuilder1.setClientId("rgfKVdnMQnJSSr_pKFTxj3apiwYa");
        introspectionResponseBuilder1.setErrorCode("Invalid input");
        introspectionResponseBuilder1.setErrorDescription("error_discription");

        List<String> filteredIntrospectionClaims = new ArrayList<>();
        filteredIntrospectionClaims.add(IntrospectionResponse.USERNAME);
        mockOAuthServerConfiguration(filteredIntrospectionClaims);

        JSONObject jsonObject = new JSONObject(introspectionResponseBuilder1.build());
        assertFalse(jsonObject.has(IntrospectionResponse.USERNAME));
    }

    /**
     * This method does unit test for build response with few filtered claim values
     */
    @Test (priority = 1)
    public void testResponseBuilderWithFilteredClaims() {

        String idToken = "eyJhbGciOiJSUzI1NiJ9.eyJhdXRoX3RpbWUiOjE0NTIxNzAxNzYsImV4cCI6MTQ1MjE3Mzc3Niwic3ViI" +
                "joidXNlQGNhcmJvbi5zdXBlciIsImF6cCI6IjF5TDFfZnpuekdZdXRYNWdCMDNMNnRYR3lqZ2EiLCJhdF9oYXNoI" +
                "joiWWljbDFlNTI5WlhZOE9zVDlvM3ktdyIsImF1ZCI6WyIxeUwxX2Z6bnpHWXV0WDVnQjAzTDZ0WEd5amdhIl0s" +
                "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImlhdCI6MTQ1MjE3MDE3Nn0.RqAgm0ybe7tQ" +
                "YvQYi7uqEtzWf6wgDv5sJq2UIQRC4OJGjn_fTqftIWerZc7rIMRYXi7jzuHxX_GabUhuj7m1iRzi1wgxbI9yQn825lDVF4Lt9" +
                "DMUTBfKLk81KIy6uB_ECtyxumoX3372yRgC7R56_L_hAElflgBsclEUwEH9psE";

        List<String> filteredIntrospectionClaims = new ArrayList<>();
        filteredIntrospectionClaims.add(IntrospectionResponse.SCOPE);
        filteredIntrospectionClaims.add(IntrospectionResponse.NBF);
        mockOAuthServerConfiguration(filteredIntrospectionClaims);

        introspectionResponseBuilder1.setActive(true);
        introspectionResponseBuilder1.setIssuedAt(1452170176);
        introspectionResponseBuilder1.setJwtId(idToken);
        introspectionResponseBuilder1.setSubject("admin@carbon.super");
        introspectionResponseBuilder1.setExpiration(7343678);
        introspectionResponseBuilder1.setUsername("admin@carbon.super");
        introspectionResponseBuilder1.setTokenType("Bearer");
        introspectionResponseBuilder1.setNotBefore(1452173776);
        introspectionResponseBuilder1.setAudience("1yL1_fznzGYutX5gB03L6tXGyjga");
        introspectionResponseBuilder1.setIssuer("https:\\/\\/localhost:9443\\/oauth2\\/token");
        introspectionResponseBuilder1.setScope("test");
        introspectionResponseBuilder1.setClientId("rgfKVdnMQnJSSr_pKFTxj3apiwYa");
        introspectionResponseBuilder1.setErrorCode("Invalid input");
        introspectionResponseBuilder1.setErrorDescription("error_discription");

        JSONObject jsonObject = new JSONObject(introspectionResponseBuilder1.build());
        assertTrue(jsonObject.has(IntrospectionResponse.AUD));
        assertFalse(jsonObject.has(IntrospectionResponse.SCOPE));
        assertFalse(jsonObject.has(IntrospectionResponse.NBF));
    }

    private void mockOAuthServerConfiguration(List<String> filteredIntrospectionClaims) {

        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        PowerMockito.when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        PowerMockito.when(oAuthServerConfiguration.getFilteredIntrospectionClaims())
                .thenReturn(filteredIntrospectionClaims);
    }
}
