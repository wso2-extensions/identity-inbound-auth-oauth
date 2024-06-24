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

import org.json.simple.JSONObject;
import org.mockito.MockedConstruction;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.exception.RegistrationException;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit test covering HttpRegistrationResponseFactory
 */
public class HttpRegistrationResponseFactoryTest {

    private RegistrationResponse mockRegistrationResponse;
    private HttpRegistrationResponseFactory httpRegistrationResponseFactory;
    private final List<String> grantType = new ArrayList<>();
    private final List<String> redirectUrl = new ArrayList<>();
    private final String dummyDescription = "dummyDescription";

    @BeforeMethod
    private void setUp() {

        mockRegistrationResponse = mock(RegistrationResponse.class);
        httpRegistrationResponseFactory = new HttpRegistrationResponseFactory();
    }

    @Test
    public void testCanHandle() throws Exception {

        IdentityResponse identityResponse = mock(IdentityResponse.class);
        assertFalse(httpRegistrationResponseFactory.canHandle(identityResponse));
    }

    @Test
    public void testCanHandleFailed() {

        assertTrue(httpRegistrationResponseFactory.canHandle(mockRegistrationResponse));
    }

    @DataProvider(name = "exceptionInstanceProvider")
    public Object[][] getExceptionInstanceType() {

        return new Object[][]{
                {new RegistrationException("")},
                {new RegistrationException("", "dummyMessage")},
                {new RegistrationException("", new Throwable())}
        };
    }

    @Test(dataProvider = "exceptionInstanceProvider")
    public void testCanHandleException(Object exception) throws Exception {

        assertTrue(httpRegistrationResponseFactory.canHandle((RegistrationException) exception));
    }

    @Test
    public void testCanHandleExceptionFailed() {

        assertFalse(httpRegistrationResponseFactory.canHandle(new FrameworkException("")));
    }

    @Test
    public void testGenerateSuccessfulResponse() throws Exception {

        grantType.add("dummyGrantType");
        redirectUrl.add("dummyRedirectUrl");

        RegistrationResponseProfile registrationRequestProfile = mock(RegistrationResponseProfile.class);
        when(mockRegistrationResponse.getRegistrationResponseProfile()).thenReturn(registrationRequestProfile);
        String dummyClientId = "dummyClientId";
        when(registrationRequestProfile.getClientId()).thenReturn(dummyClientId);
        String dummyClientName = "dummyClientName";
        when(registrationRequestProfile.getClientName()).thenReturn(dummyClientName);
        when(registrationRequestProfile.getGrantTypes()).thenReturn(grantType);
        when(registrationRequestProfile.getRedirectUrls()).thenReturn(redirectUrl);
        String dummySecret = "dummySecret";
        when(registrationRequestProfile.getClientSecret()).thenReturn(dummySecret);
        String dummyTime = "dummyTime";
        when(registrationRequestProfile.getClientSecretExpiresAt()).thenReturn(dummyTime);

        JSONObject jsonObject = httpRegistrationResponseFactory.generateSuccessfulResponse(mockRegistrationResponse);

        assertEquals(jsonObject.get(RegistrationResponse.DCRegisterResponseConstants.CLIENT_ID), dummyClientId);
        assertEquals(jsonObject.get(RegistrationResponse.DCRegisterResponseConstants.CLIENT_NAME), dummyClientName);
        assertEquals(jsonObject.get(RegistrationResponse.DCRegisterResponseConstants.CLIENT_SECRET_EXPIRES_AT),
                dummyTime);
        assertEquals(jsonObject.get(RegistrationResponse.DCRegisterResponseConstants.CLIENT_SECRET), dummySecret);
        assertEquals(jsonObject.get(RegistrationResponse.DCRegisterResponseConstants.GRANT_TYPES), grantType);
        assertEquals(jsonObject.get(RegistrationResponse.DCRegisterResponseConstants.REDIRECT_URIS), redirectUrl);
    }

    @Test
    public void testCreate() throws Exception {

        RegistrationResponseProfile registrationRequestProfile = mock(RegistrationResponseProfile.class);

        when((mockRegistrationResponse).getRegistrationResponseProfile()).
                thenReturn(registrationRequestProfile);

        final Integer[] statusCode = new Integer[1];
        final String[] header = new String[1];
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
                    }).when(mock).addHeader(anyString(), anyString());
                })) {
            httpRegistrationResponseFactory.create(mockRegistrationResponse);

            assertEquals((int) statusCode[0], HttpServletResponse.SC_CREATED);
            assertEquals(header[0], MediaType.APPLICATION_JSON);
        }
    }

    @Test
    public void testCreateWithBuilder() throws Exception {

        RegistrationResponseProfile registrationRequestProfile = mock(RegistrationResponseProfile.class);
        HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder =
                mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);

        when((mockRegistrationResponse).getRegistrationResponseProfile()).
                thenReturn(registrationRequestProfile);

        final Integer[] statusCode = new Integer[1];
        doAnswer((Answer<Object>) invocation -> {

            statusCode[0] = (Integer) invocation.getArguments()[0];
            return null;
        }).when(mockHttpIdentityResponseBuilder).setStatusCode(anyInt());

        final String[] header = new String[1];
        doAnswer((Answer<Object>) invocation -> {

            header[0] = (String) invocation.getArguments()[1];
            return null;
        }).when(mockHttpIdentityResponseBuilder).addHeader(anyString(), anyString());

        httpRegistrationResponseFactory.create(mockHttpIdentityResponseBuilder,
                    (mockRegistrationResponse));
        assertEquals((int) statusCode[0], HttpServletResponse.SC_CREATED);
        assertEquals(header[0], MediaType.APPLICATION_JSON);
    }

    @Test
    public void testGenerateErrorResponse() throws Exception {

        String dummyError = "dummyError";
        JSONObject jsonObject = httpRegistrationResponseFactory.generateErrorResponse(dummyError, dummyDescription);
        assertEquals(jsonObject.get("error"), dummyError);
        assertEquals(jsonObject.get("error_description"), dummyDescription);
    }

    @DataProvider(name = "exceptionDataProvider")
    public Object[][] getExceptionData() {

        return new Object[][]{
                {ErrorCodes.FORBIDDEN.toString(), HttpServletResponse.SC_FORBIDDEN},
                {ErrorCodes.META_DATA_VALIDATION_FAILED.toString(), HttpServletResponse.SC_BAD_REQUEST},
                {ErrorCodes.GONE.toString(), HttpServletResponse.SC_GONE},
                {ErrorCodes.BAD_REQUEST.toString(), HttpServletResponse.SC_BAD_REQUEST},
                {null, HttpServletResponse.SC_BAD_REQUEST}
        };
    }

    @Test(dataProvider = "exceptionDataProvider")
    public void testHandleException(String errorCode, int expected) throws Exception {

        final Integer[] statusCode = new Integer[1];
        final String[] header = new String[1];

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
                    }).when(mock).addHeader(anyString(), anyString());
                })) {

            FrameworkException exception = mock(FrameworkException.class);
            when(exception.getMessage()).thenReturn(dummyDescription);

            when(exception.getErrorCode()).thenReturn(errorCode);
            httpRegistrationResponseFactory.handleException(exception);

            assertEquals((int) statusCode[0], expected);
        }
    }

}
