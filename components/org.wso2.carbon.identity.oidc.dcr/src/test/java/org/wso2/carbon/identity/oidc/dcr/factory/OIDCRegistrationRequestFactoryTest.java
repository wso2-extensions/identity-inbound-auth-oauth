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

package org.wso2.carbon.identity.oidc.dcr.factory;

import org.apache.commons.collections.CollectionUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequestProfile;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Test class for OIDCRegistrationRequestFactory.
 */
public class OIDCRegistrationRequestFactoryTest extends IdentityBaseTest {

    private OIDCRegistrationRequestFactory testedRegistrationRequestFactory;

    @BeforeClass
    public void setUp() throws Exception {
        testedRegistrationRequestFactory = new OIDCRegistrationRequestFactory();
        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("admin");

    }

    @AfterClass
    public void tearDown() throws Exception {
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(null);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(null);
        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
    }

    @DataProvider(name = "OIDC can handle data")
    public Object[][] getCanHandleData() {
        return new Object[][]{
                {"https://example.com/identity/connect/register", "POST", true},
                {"https://example.com/identity/connect/register/", "POST", true},
                {"http://example.com/identity/connect/register/", "POST", true},
                {"https://example.com/identity/connect/register/", "GET", false},
                {"https://example.com/identity/connect/register/", "PUT", false},
                {"https://example.com/identity/connect/register/", "DELETE", false},
                {"https://example.com/identity/connect/register/7", "POST", false},
                {"https://example.com/identity/connect/", "POST", false},
        };
    }

    @Test(dataProvider = "OIDC can handle data")
    public void testCanHandle(String requestURI, String method, boolean expected) throws
            Exception {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn(requestURI);
        when(mockRequest.getMethod()).thenReturn(method);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        assertEquals(testedRegistrationRequestFactory.canHandle(mockRequest, mockResponse), expected, String.format
                ("Expected %b for requestURI: %s , method: %s .", expected, requestURI, method));
    }

    @Test
    public void testCanHandleNullRequest() throws
            Exception {
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        assertFalse(testedRegistrationRequestFactory.canHandle(null, mockResponse), "Expected false for null " +
                "request");
    }

    @DataProvider(name = "OIDCRequestBuilderCreationData")
    public Object[][] getRequestBuilderCreateData() {
        return new Object[][]{
                {"{\n" +
                        "   \"application_type\": \"web\",\n" +
                        "   \"redirect_uris\":\n" +
                        "     [\"https://client.example.org/callback\"],\n" +
                        "   \"client_name\": \"My Example\",\n" +
                        "   \"logo_uri\": \"https://client.example.org/logo.png\",\n" +
                        "   \"subject_type\": \"pairwise\",\n" +
                        "   \"sector_identifier_uri\":\n" +
                        "     \"https://other.example.net/file_of_redirect_uris.json\",\n" +
                        "   \"token_endpoint_auth_method\": \"client_secret_basic\",\n" +
                        "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\n" +
                        "   \"userinfo_encrypted_response_alg\": \"RSA1_5\",\n" +
                        "   \"sector_identifier_uri\": \"https://sectorid.example.org\",\n" +
                        "   \"id_token_signed_response_alg\": \"token_sig_alg\",\n" +
                        "   \"id_token_encrypted_response_alg\": \"token_enc_alg\",\n" +
                        "   \"id_token_encrypted_response_enc\": \"token_enc_enc\",\n" +
                        "   \"userinfo_signed_response_alg\": \"userinfo_signed_response_alg\",\n" +
                        "   \"userinfo_encrypted_response_alg\": \"userinfo_encrypted_response_alg\",\n" +
                        "   \"userinfo_encrypted_response_enc\": \"userinfo_encrypted_response_enc\",\n" +
                        "   \"request_object_encryption_alg\": \"request_object_encryption_alg\",\n" +
                        "   \"request_object_signing_alg\": \"request_object_signing_alg\",\n" +
                        "   \"request_object_encryption_enc\": \"request_object_encryption_enc\",\n" +
                        "   \"token_endpoint_auth_signing_alg\": \"token_endpoint_auth_signing_alg\",\n" +
                        "   \"require_auth_time\": \"require_auth_time\",\n" +
                        "   \"default_max_age\": \"default_max_age\",\n" +
                        "   \"default_acr_values\": \"default_acr_values\",\n" +
                        "   \"initiate_login_uri\": \"initiate_login_uri\",\n" +
                        "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\n" +
                        "   \"request_uris\":\n" +
                        "     [\"https://client.example.org/1\"," +
                        "      \"https://client.example.org/2\"," +
                        "     ]\n" +
                        "}",
                        "https://sectorid.example.org",
                        "pairwise",
                        "token_sig_alg",
                        "token_enc_alg",
                        "token_enc_enc",
                        "userinfo_signed_response_alg",
                        "userinfo_encrypted_response_alg",
                        "userinfo_encrypted_response_enc",
                        "request_object_signing_alg",
                        "request_object_encryption_alg",
                        "request_object_encryption_enc",
                        "token_endpoint_auth_signing_alg",
                        "default_max_age",
                        "require_auth_time",
                        "default_acr_values",
                        "initiate_login_uri",
                        Arrays.asList("https://client.example.org/1", "https://client.example.org/2")
                },
                {"{\n" +
                        "   \"application_type\": \"web\",\n" +
                        "   \"redirect_uris\":\n" +
                        "     [\"https://client.example.org/callback\"],\n" +
                        "   \"client_name\": \"My Example\",\n" +
                        "   \"logo_uri\": \"https://client.example.org/logo.png\",\n" +
                        "   \"subject_type\": \"pairwise\",\n" +
                        "   \"token_endpoint_auth_method\": \"client_secret_basic\",\n" +
                        "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\n" +
                        "   \"userinfo_encrypted_response_alg\": \"RSA1_5\",\n" +
                        "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\n" +
                        "   \"request_uris\":\"https://client.example.org/1\"" +
                        "}",
                        null,
                        "pairwise",
                        null,
                        null,
                        null,
                        null,
                        "RSA1_5",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        Collections.singletonList("https://client.example.org/1")
                }
        };
    }

    @Test(dataProvider = "OIDCRequestBuilderCreationData")
    public void testCreate(String request,
                           String sectorIdUrl,
                           String subjectType,
                           String tokenSignAlg,
                           String tokenEncrAlg,
                           String tokenEncrEnc,
                           String userInfoRespSignAlg,
                           String userInfoRespEncrAlg,
                           String userInfoRespEnceEnc,
                           String reqObjSignAlg,
                           String reqObjEncrAlg,
                           String reqObjEncrEnc,
                           String tokenEPAuthSignAlg,
                           String defaultMaxAge,
                           String requireAuthTime,
                           String defaultAcrValues,
                           String initLoginUrl,
                           List<String> requestUris) throws Exception {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        when(mockRequest.getReader()).thenReturn(new BufferedReader(new StringReader(request)));
        when(mockRequest.getHeaderNames()).thenReturn(Collections.<String>emptyEnumeration());
        when(mockRequest.getAttributeNames()).thenReturn(Collections.<String>emptyEnumeration());

        OIDCRegistrationRequest.OIDCRegistrationRequestBuilder requestBuilder = testedRegistrationRequestFactory
                .create(mockRequest, mockResponse);
        RegistrationRequest registrationRequest = requestBuilder.build();
        RegistrationRequestProfile requestProfile = registrationRequest.getRegistrationRequestProfile();
        assertTrue(requestProfile instanceof OIDCRegistrationRequestProfile, "Request profile should be an instance " +
                "of OIDCRegistrationRequestProfile");
        OIDCRegistrationRequestProfile oidcRegRequestProfile = (OIDCRegistrationRequestProfile) requestProfile;

        assertEquals(requestBuilder.getRequest(), mockRequest, "Builder should have the provided request.");
        assertEquals(requestBuilder.getResponse(), mockResponse, "Builder should have the provided response.");
        assertEquals(oidcRegRequestProfile.getSectorIdentifierUri(), sectorIdUrl, "Invalid Sector Id URL");
        assertEquals(oidcRegRequestProfile.getSubjectType(), subjectType, "Invalid subject type");
        assertEquals(oidcRegRequestProfile.getIdTokenSignedResponseAlg(), tokenSignAlg, "Invalid token sign " +
                "algorithm");
        assertEquals(oidcRegRequestProfile.getIdTokenEncryptedResponseAlg(), tokenEncrAlg, "Invalid token encryption" +
                " alg");
        assertEquals(oidcRegRequestProfile.getIdTokenEncryptedResponseEnc(), tokenEncrEnc, "Invalid token encryption" +
                " enc");
        assertEquals(oidcRegRequestProfile.getUserinfoSignedResponseAlg(), userInfoRespSignAlg, "Invalid userinfo " +
                "response sign alg");
        assertEquals(oidcRegRequestProfile.getUserinfoencryptedResponseAlg(), userInfoRespEncrAlg, "Invalid userinfo " +
                "response encr alg");
        assertEquals(oidcRegRequestProfile.getUserinfoEncryptedResponseEnc(), userInfoRespEnceEnc, "Invalid userinfo " +
                "response encr enc");
        assertEquals(oidcRegRequestProfile.getRequestObjectSigningAlg(), reqObjSignAlg, "Invalid request obj sign " +
                "alg");
        assertEquals(oidcRegRequestProfile.getRequestObjectEncryptionAlg(), reqObjEncrAlg, "Invalid request obj encr" +
                " alg");
        assertEquals(oidcRegRequestProfile.getRequestObjectEncryptionEnc(), reqObjEncrEnc, "Invalid request obj encr" +
                " enc");
        assertEquals(oidcRegRequestProfile.getTokenEndpointAuthSigningAlg(), tokenEPAuthSignAlg, "Invalid token " +
                "endpoint auth response alg.");
        assertEquals(oidcRegRequestProfile.getDefaultMaxAge(), defaultMaxAge, "Invalid default max age");
        assertEquals(oidcRegRequestProfile.getRequireAuthTime(), requireAuthTime, "Invalid require auth time");
        assertEquals(oidcRegRequestProfile.getDefaultAcrValues(), defaultAcrValues, "Invalid default acr values");
        assertEquals(oidcRegRequestProfile.getInitiateLoginUri(), initLoginUrl, "Invalid initiate login uri");
        assertTrue(CollectionUtils.isEqualCollection(oidcRegRequestProfile.getRequestUris(), requestUris), "Invalid " +
                "request URLs ");
    }
}
