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

package org.wso2.carbon.identity.oauth.dcr.factory;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;

import java.io.BufferedReader;
import java.nio.file.Paths;

import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doAnswer;

import static org.powermock.api.support.membermodification.MemberMatcher.methodsDeclaredIn;
import static org.powermock.api.support.membermodification.MemberModifier.suppress;
import static org.testng.Assert.assertEquals;

/**
 * Unit test covering RegistrationRequestFactory
 */
@PrepareForTest(RegistrationRequestFactory.class)
public class RegistrationRequestFactoryTest extends PowerMockIdentityBaseTest {

    private RegistrationRequestFactory registrationRequestFactory;
    private String dummyDescription = "dummyDescription";
    private String ownerName = "dummyOwnerName";

    @Mock
    private HttpServletRequest mockHttpRequest;

    @Mock
    private HttpServletResponse mockHttpResponse;

    @Mock
    private RegistrationRequest.RegistrationRequestBuilder mockRegistrationRequestBuilder;

    @Mock
    private HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder;

    @Mock
    private BufferedReader mockReader;

    @Mock
    private JSONParser jsonParser;

    @BeforeMethod
    private void setUp() {

        registrationRequestFactory = new RegistrationRequestFactory();
    }

    /**
     * DataProvider: requestURI, httpMethod, expected value
     */
    @DataProvider(name = "httpMethodAndUriProvider")
    public Object[][] getHttpMethodAndUri() {

        return new Object[][]{
                {"dummyVal/identity/register/", HttpMethod.POST, true},
                {"dummyVal/identity/register/dummyVal", HttpMethod.POST, false},
        };
    }

    @Test(dataProvider = "httpMethodAndUriProvider")
    public void testCanHandle(String requestURI, String httpMethod, boolean expected) throws Exception {

        when(mockHttpRequest.getRequestURI()).thenReturn(requestURI);
        when(mockHttpRequest.getMethod()).thenReturn(httpMethod);
        assertEquals(registrationRequestFactory.canHandle(mockHttpRequest, mockHttpResponse), expected,
                "Redirect Uri doesn't match");
    }

    @DataProvider(name = "jsonObjectDataProvider")
    public Object[][] getData() {

        String grantType = "dummyGrantType";
        String redirectUrl = "dummyRedirectUrl";
        String responseType = "dummyRedirectUri";
        String clientName = "dummyClientName";
        String scope = "dummyScope";
        String contact = "dummyContact";

        JSONArray grantTypes = new JSONArray();
        JSONArray redirectUrls = new JSONArray();
        JSONArray responseTypes = new JSONArray();
        JSONArray scopes = new JSONArray();
        JSONArray contacts = new JSONArray();
        grantTypes.add(grantType);
        redirectUrls.add(redirectUrl);
        responseTypes.add(responseType);
        contacts.add(contact);
        scopes.add(scope);

        JSONArray emptyGrantTypes = new JSONArray();
        JSONArray emptyRedirectUrls = new JSONArray();
        JSONArray emptyResponseTypes = new JSONArray();
        JSONArray emptyScopes = new JSONArray();
        JSONArray emptyContacts = new JSONArray();
        emptyGrantTypes.add("");
        emptyRedirectUrls.add("");
        emptyResponseTypes.add("");
        emptyScopes.add("");
        emptyContacts.add("");

        JSONArray grantTypeWithInt = new JSONArray();
        JSONArray redirectUrlsWithInt = new JSONArray();
        JSONArray responseTypesWithInt = new JSONArray();
        JSONArray scopesWithInt = new JSONArray();
        JSONArray contactsWithInt = new JSONArray();
        grantTypeWithInt.add(0);
        redirectUrlsWithInt.add(0);
        responseTypesWithInt.add(0);
        contactsWithInt.add(0);
        scopesWithInt.add(0);

        return new Object[][]{
                // Check with String values.
                {grantTypes, redirectUrls, responseTypes, clientName, scopes, contacts, grantTypes},
                // Check with jsonArray.
                {grantType, redirectUrl, responseType, clientName, scope, contact, grantType},
                // Check with empty jsonArray.
                {emptyGrantTypes, emptyRedirectUrls, emptyResponseTypes, clientName, emptyScopes, emptyContacts,
                        "empty"},
                // Check with wrong data type values.
                {0, 0, 0, clientName, 0, 0, "empty"},
                // Check with Wrong data type values.
                {grantTypeWithInt, redirectUrlsWithInt, responseTypesWithInt, null, scopesWithInt, contactsWithInt,
                        "empty"}
        };
    }

    @Test(dataProvider = "jsonObjectDataProvider")
    public void testCreate(Object grantType, Object redirectUrl, Object responseType, String clientName, Object
            scope, Object contact, Object expected) throws Exception {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrl);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.RESPONSE_TYPES, responseType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.CLIENT_NAME, clientName);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.SCOPE, scope);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.CONTACTS, contact);

        RegistrationRequestProfile registrationRequestProfile = new RegistrationRequestProfile();

        whenNew(RegistrationRequestProfile.class).withNoArguments().thenReturn(registrationRequestProfile);

        suppress(methodsDeclaredIn(HttpIdentityRequestFactory.class));

        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        whenNew(JSONParser.class).withNoArguments().thenReturn(jsonParser);

        when(jsonParser.parse(mockReader)).thenReturn(jsonObject);

        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);

            registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);

            if (clientName != null) {
                assertEquals(registrationRequestProfile.getClientName(), clientName,
                        "expected client name is not found in registrationRequestProfile");
            }

            if (!expected.equals("empty")) {
                if (expected instanceof String) {
                    assertEquals(registrationRequestProfile.getGrantTypes().get(0), grantType,
                            "expected grant type is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getRedirectUris().get(0), redirectUrl,
                            "expected redirectUrl is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getContacts().get(0), contact,
                            "expected contact is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getScopes().get(0), scope,
                            "expected scope is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getResponseTypes().get(0), responseType,
                            "expected response type is not found in registrationRequestProfile");
                } else {
                    assertEquals(registrationRequestProfile.getGrantTypes(), grantType,
                            "expected grant type is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getRedirectUris(), redirectUrl,
                            "expected redirect url is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getContacts(), contact,
                            "expected contact is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getScopes(), scope,
                            "expected scope is not found in registrationRequestProfile");
                    assertEquals(registrationRequestProfile.getResponseTypes(), responseType,
                            "expected response type is not found in registrationRequestProfile");
                }
            }
            assertEquals(registrationRequestProfile.getOwner(), ownerName,
                    "expected owner name is not found in registrationRequestProfile");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testCreateWithEmptyRedirectUri() throws Exception {

        String grantType = "implicit";
        // Check redirectUri by assigning wrong data type.
        int redirectUrl = 0;
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrl);

        RegistrationRequestProfile registrationRequestProfile = new RegistrationRequestProfile();

        whenNew(RegistrationRequestProfile.class).withNoArguments().thenReturn(registrationRequestProfile);

        suppress(methodsDeclaredIn(HttpIdentityRequestFactory.class));

        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        whenNew(JSONParser.class).withNoArguments().thenReturn(jsonParser);

        when(jsonParser.parse(mockReader)).thenReturn(jsonObject);
        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);
            registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testHandleException() throws Exception {

        whenNew(HttpIdentityResponse.HttpIdentityResponseBuilder.class).withNoArguments().thenReturn
                (mockHttpIdentityResponseBuilder);

        final Integer[] statusCode = new Integer[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                statusCode[0] = (Integer) invocation.getArguments()[0];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).setStatusCode(anyInt());

        final String[] header = new String[3];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[0] = (String) invocation.getArguments()[1];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).addHeader(eq(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL),
                anyString());

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[1] = (String) invocation.getArguments()[1];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).addHeader(eq(OAuthConstants.HTTP_RESP_HEADER_PRAGMA), anyString());

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[2] = (String) invocation.getArguments()[1];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).addHeader(eq(HttpHeaders.CONTENT_TYPE), anyString());

        FrameworkClientException exception = mock(FrameworkClientException.class);
        when(exception.getMessage()).thenReturn(dummyDescription);
        registrationRequestFactory.handleException(exception, mockHttpRequest, mockHttpResponse);

        assertEquals(header[0], OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE, "Wrong header value " +
                "for " + OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL);
        assertEquals(header[1], OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE, "Wrong header value for " +
                OAuthConstants.HTTP_RESP_HEADER_PRAGMA);
        assertEquals(header[2], MediaType.APPLICATION_JSON, "Wrong header value for " + HttpHeaders.CONTENT_TYPE);

        assertEquals((int) statusCode[0], HttpServletResponse.SC_BAD_REQUEST, "Status code doesn't match with "
                + HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    public void testGenerateErrorResponse() throws Exception {

        String dummyError = "dummyError";
        JSONObject jsonObject = registrationRequestFactory.generateErrorResponse(dummyError, dummyDescription);
        assertEquals(jsonObject.get("error"), dummyError, "Response error doesn't match with expected error");
        assertEquals(jsonObject.get("error_description"), dummyDescription, "Response description doesn't match " +
                "with expected error");
    }

    private void startTenantFlow() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
    }
}
