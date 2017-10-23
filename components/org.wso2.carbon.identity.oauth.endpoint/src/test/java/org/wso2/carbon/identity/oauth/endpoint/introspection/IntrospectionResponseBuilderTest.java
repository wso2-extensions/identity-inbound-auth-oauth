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

import org.json.JSONObject;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

/**
 * This class does unit test coverage for RecoveryConfigImpl class
 */
public class IntrospectionResponseBuilderTest {

    private IntrospectionResponseBuilder introspectionResponseBuilder1;

    private IntrospectionResponseBuilder introspectionResponseBuilder2;

    @BeforeTest
    public void setUp() {
        introspectionResponseBuilder1 = new IntrospectionResponseBuilder();
        introspectionResponseBuilder2 = new IntrospectionResponseBuilder();
    }

    /**
     * This method does unit test for build response with values
     */
    @Test
    public void testResposeBuilderWithVal() {

        String id_token = "eyJhbGciOiJSUzI1NiJ9.eyJhdXRoX3RpbWUiOjE0NTIxNzAxNzYsImV4cCI6MTQ1MjE3Mzc3Niwic3ViI" +
                "joidXNlQGNhcmJvbi5zdXBlciIsImF6cCI6IjF5TDFfZnpuekdZdXRYNWdCMDNMNnRYR3lqZ2EiLCJhdF9oYXNoI" +
                "joiWWljbDFlNTI5WlhZOE9zVDlvM3ktdyIsImF1ZCI6WyIxeUwxX2Z6bnpHWXV0WDVnQjAzTDZ0WEd5amdhIl0s" +
                "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImlhdCI6MTQ1MjE3MDE3Nn0.RqAgm0ybe7tQ" +
                "YvQYi7uqEtzWf6wgDv5sJq2UIQRC4OJGjn_fTqftIWerZc7rIMRYXi7jzuHxX_GabUhuj7m1iRzi1wgxbI9yQn825lDVF4Lt9DMUTB" +
                "fKLk81KIy6uB_ECtyxumoX3372yRgC7R56_L_hAElflgBsclEUwEH9psE";

        introspectionResponseBuilder1.setActive(false);
        introspectionResponseBuilder1.setIssuedAt(1452170176);
        introspectionResponseBuilder1.setJwtId(id_token);
        introspectionResponseBuilder1.setSubject("admin@carbon.super");
        introspectionResponseBuilder1.setExpiration(1452173776);
        introspectionResponseBuilder1.setUsername("admin@carbon.super");
        introspectionResponseBuilder1.setTokenType("Bearer");
        introspectionResponseBuilder1.setNotBefore(7343678);
        introspectionResponseBuilder1.setAudience("1yL1_fznzGYutX5gB03L6tXGyjga");
        introspectionResponseBuilder1.setIssuer("https:\\/\\/localhost:9443\\/oauth2\\/token");
        introspectionResponseBuilder1.setScope("test");
        introspectionResponseBuilder1.setClientId("rgfKVdnMQnJSSr_pKFTxj3apiwYa");
        introspectionResponseBuilder1.setErrorCode("Invalid input");
        introspectionResponseBuilder1.setErrorDescription("error_discription");

        JSONObject jsonObject = new JSONObject(introspectionResponseBuilder1.build());
        // Here,if the token is not active we do not want to return back the expiration time.
        assertFalse(jsonObject.has(IntrospectionResponse.EXP), "EXP already exists in the response builder");
        // Here,if the token is not active we do not want to return back the nbf time.
        assertFalse(jsonObject.has(IntrospectionResponse.NBF), "NBF already exists in the response builder");

        assertEquals(jsonObject.get(IntrospectionResponse.IAT), 1452170176, "IAT values are not equal");
        assertEquals(jsonObject.get(IntrospectionResponse.JTI), id_token, "JTI values are not equal");
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
    }

    /**
     * This method does unit test for build response without values
     */
    @Test
    public void testResposeBuilderWithoutVal() {
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

        JSONObject jsonObject2 = new JSONObject(introspectionResponseBuilder2.build());
        assertFalse(jsonObject2.has(IntrospectionResponse.EXP), "EXP already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.NBF), "NBF already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.IAT), "IAT already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.JTI), "JTI already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.SUB), "SUB already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.USERNAME), "USERNAME already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.TOKEN_TYPE), "TOKEN_TYPE already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.AUD), "AUD already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.ISS), "ISS already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.SCOPE), "SCOPE already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.CLIENT_ID), "CLIENT_ID already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.Error.ERROR), "ERROR already exists in the response builder");
        assertFalse(jsonObject2.has(IntrospectionResponse.Error.ERROR_DESCRIPTION),
                "ERROR_DESCRIPTION already exists in the response builder");
    }

}
