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
import org.json.simple.parser.ParseException;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit test covering RegistrationRequestFactory
 */
@Listeners(MockitoTestNGListener.class)
public class RegistrationRequestFactoryTest {

    private RegistrationRequestFactory registrationRequestFactory;
    private final String dummyDescription = "dummyDescription";
    private final String ownerName = "dummyOwnerName";

    @Mock
    private HttpServletRequest mockHttpRequest;

    @Mock
    private HttpServletResponse mockHttpResponse;

    private RegistrationRequest.RegistrationRequestBuilder mockRegistrationRequestBuilder;

    @Mock
    private BufferedReader mockReader;

    @Mock
    private JSONParser jsonParser;

    @Mock
    private UserRealm mockedUserRealm;

    @Mock
    private UserStoreManager mockedUserStoreManager;

    @BeforeMethod
    private void setUp() {

        registrationRequestFactory = new RegistrationRequestFactory();
        mockRegistrationRequestBuilder =
                new RegistrationRequest.RegistrationRequestBuilder(mockHttpRequest, mockHttpResponse);
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
        lenient().when(mockHttpRequest.getMethod()).thenReturn(httpMethod);
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

        mockHttpResponse = mock(HttpServletResponse.class);
        mockHttpRequest = mock(HttpServletRequest.class);
        mockRegistrationRequestBuilder =
                new RegistrationRequest.RegistrationRequestBuilder(mockHttpRequest, mockHttpResponse);

        return new Object[][]{
                // Check with String values.
                {grantTypes, redirectUrls, responseTypes, clientName, scopes, contacts, grantTypes,
                        mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse},
                // Check with jsonArray.
                {grantType, redirectUrl, responseType, clientName, scope, contact, grantType,
                        null, mockHttpRequest, mockHttpResponse},
                // Check with empty jsonArray.
                {emptyGrantTypes, emptyRedirectUrls, emptyResponseTypes, clientName, emptyScopes, emptyContacts,
                        "empty", mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse},
                // Check with wrong data type values.
                {0, 0, 0, clientName, 0, 0, "empty", mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse},
                // Check with Wrong data type values.
                {grantTypeWithInt, redirectUrlsWithInt, responseTypesWithInt, null, scopesWithInt, contactsWithInt,
                        "empty", null, mockHttpRequest, mockHttpResponse}
        };
    }

    @Test(dataProvider = "jsonObjectDataProvider")
    public void testCreate(Object grantType, Object redirectUrl, Object responseType, String clientName, Object
            scope, Object contact, Object expected, Object builder, Object request, Object response) throws Exception {

        mockHttpRequest = (HttpServletRequest) request;
        mockHttpResponse = (HttpServletResponse) response;

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrl);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.RESPONSE_TYPES, responseType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.CLIENT_NAME, clientName);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.SCOPE, scope);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.CONTACTS, contact);

        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));

        lenient().when(jsonParser.parse(mockReader)).thenReturn(jsonObject);
        try (MockedConstruction<JSONParser> mockedConstruction = mockConstruction(JSONParser.class,
                (mock, context) -> {
                    when(mock.parse(mockReader)).thenReturn(jsonObject);
                })) {

            try {
                startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);

                RegistrationRequestProfile registrationRequestProfile;
                if (builder == null) {
                    RegistrationRequest.RegistrationRequestBuilder registrationRequestBuilder =
                            registrationRequestFactory.create(mockHttpRequest, mockHttpResponse);
                    registrationRequestProfile = registrationRequestBuilder.getRegistrationRequestProfile();
                } else {
                    registrationRequestFactory.create((RegistrationRequest.RegistrationRequestBuilder) builder,
                            mockHttpRequest, mockHttpResponse);
                    registrationRequestProfile =
                            ((RegistrationRequest.RegistrationRequestBuilder) builder).getRegistrationRequestProfile();
                }

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
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testCreateWithEmptyRedirectUri() throws Exception {

        String grantType = "implicit";
        // Check redirectUri by assigning wrong data type.
        int redirectUrl = 0;
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrl);

        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        try (MockedConstruction<JSONParser> mockedConstruction = mockConstruction(JSONParser.class,
                (mock, context) -> {
                    when(mock.parse(mockReader)).thenReturn(jsonObject);
                })) {
            try {
                startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);
                registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    @DataProvider(name = "invalidApplicationDataProvider")
    public Object[][] getInvalidApplicationData() {

        return new Object[][]{
                {null, false, "Invalid application owner."},
                {"", true, "Invalid application owner, null"},
                {"", false, "Invalid application owner."}
        };
    }

    @Test(dataProvider = "invalidApplicationDataProvider")
    public void testCreateWithInvalidApplicationOwner(String userName, Boolean isThrowException,
                                                      String expected) throws Exception {

        JSONObject jsonObject = getTestCreateData();
        if (!Objects.isNull(userName)) {
            jsonObject.put(RegistrationRequest.RegisterRequestConstant.EXT_PARAM_OWNER, "dummyParam");
        }
        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));

        try (MockedConstruction<JSONParser> mockedConstruction = mockConstruction(JSONParser.class,
                (mock, context) -> {
                    when(mock.parse(mockReader)).thenReturn(jsonObject);
                })) {
            try {
                startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);

                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
                lenient().when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
                if (isThrowException) {
                    when(mockedUserStoreManager.isExistingUser(anyString())).
                            thenAnswer (i -> {
                                throw new UserStoreException("null");
                            });
                } else {
                    lenient().when(mockedUserStoreManager.isExistingUser("dummyParam")).thenReturn(false);
                }
                registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);
            } catch (IdentityException ex) {
                assertEquals(ex.getMessage(), expected);
                return;
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    private JSONObject getTestCreateData() throws Exception {

        String grantType = "implicit";
        JSONArray redirectUrls = new JSONArray();
        redirectUrls.add("redirectUrl");
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrls);

        return jsonObject;
    }

    @Test
    public void testCreateWithServerRequestReadingError() throws Exception {

        JSONObject jsonObject = getTestCreateData();
        when(mockHttpRequest.getReader()).thenThrow(IOException.class);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        try (MockedConstruction<JSONParser> mockedConstruction = mockConstruction(JSONParser.class,
                (mock, context) -> {
                    when(mock.parse(mockReader)).thenReturn(jsonObject);
                })) {
            try {
                startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);
                registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);
            } catch (IdentityException ex) {
                assertEquals(ex.getMessage(), "Error occurred while reading servlet request body, ");
                return;
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    @Test
    public void testCreateWithPassingError() throws Exception {

        getTestCreateData();
        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        try (MockedConstruction<JSONParser> mockedConstruction = mockConstruction(JSONParser.class,
                (mock, context) -> {
                    when(mock.parse(mockReader)).thenThrow(ParseException.class);
                })) {
            try {
                startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);
                registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);
            } catch (IdentityException ex) {
                assertEquals(ex.getMessage(), "Error occurred while parsing the json object, ");
                return;
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    @Test
    public void testHandleException() throws Exception {

        final Integer[] statusCode = new Integer[1];
        final String[] header = new String[3];

        try (MockedConstruction<HttpIdentityResponse.HttpIdentityResponseBuilder> mockedConstruction = mockConstruction(
                HttpIdentityResponse.HttpIdentityResponseBuilder.class,
                (mock, context) -> {
                    doAnswer((Answer<Object>) invocation -> {

                        statusCode[0] = (Integer) invocation.getArguments()[0];
                        return null;
                    }).when(mock).setStatusCode(anyInt());

                    doAnswer((Answer<Object>) invocation -> {

                        header[0] = (String) invocation.getArguments()[1];
                        return null;
                    }).when(mock).addHeader(eq(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL), anyString());

                    doAnswer((Answer<Object>) invocation -> {

                        header[1] = (String) invocation.getArguments()[1];
                        return null;
                    }).when(mock).addHeader(eq(OAuthConstants.HTTP_RESP_HEADER_PRAGMA), anyString());

                    doAnswer((Answer<Object>) invocation -> {

                        header[2] = (String) invocation.getArguments()[1];
                        return null;
                    }).when(mock).addHeader(eq(HttpHeaders.CONTENT_TYPE), anyString());
                })) {

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
