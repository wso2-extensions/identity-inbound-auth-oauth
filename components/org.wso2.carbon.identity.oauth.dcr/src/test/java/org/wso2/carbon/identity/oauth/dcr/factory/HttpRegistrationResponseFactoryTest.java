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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
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

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit test covering HttpRegistrationResponseFactory
 */
@PrepareForTest(HttpRegistrationResponseFactory.class)
public class HttpRegistrationResponseFactoryTest extends PowerMockTestCase {

    private RegistrationResponse mockRegistrationResponse;
    private HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder;
    private HttpRegistrationResponseFactory httpRegistrationResponseFactory;
    private final List<String> grantType = new ArrayList<>();
    private final List<String> redirectUrl = new ArrayList<>();
    private final String dummyDescription = "dummyDescription";

    @BeforeMethod
    private void setUp() {

        mockRegistrationResponse = mock(RegistrationResponse.class);
        httpRegistrationResponseFactory = new HttpRegistrationResponseFactory();
    }

    @DataProvider(name = "instanceProvider")
    public Object[][] getInstanceType() {

        mockRegistrationResponse = mock(RegistrationResponse.class);
        IdentityResponse identityResponse = mock(IdentityResponse.class);
        return new Object[][]{
                {mockRegistrationResponse, true},
                {identityResponse, false}
        };
    }

    @Test(dataProvider = "instanceProvider")
    public void testCanHandle(Object identityResponse, boolean expected) throws Exception {

        if (expected) {
            assertTrue(httpRegistrationResponseFactory.canHandle((RegistrationResponse) identityResponse));
        } else {
            assertFalse(httpRegistrationResponseFactory.canHandle((IdentityResponse) identityResponse));
        }
    }

    @DataProvider(name = "exceptionInstanceProvider")
    public Object[][] getExceptionInstanceType() {

        FrameworkException exception1 = new RegistrationException("");
        FrameworkException exception2 = new RegistrationException("", "dummyMessage");
        FrameworkException exception3 = new RegistrationException("", new Throwable());
        FrameworkException exception4 = new FrameworkException("");
        return new Object[][]{
                {exception1, true},
                {exception2, true},
                {exception3, true},
                {exception4, false}
        };
    }

    @Test(dataProvider = "exceptionInstanceProvider")
    public void testCanHandleException(Object exception, boolean expected) throws Exception {

        if (expected) {
            assertTrue(httpRegistrationResponseFactory.canHandle((RegistrationException) exception));
        } else {
            assertFalse(httpRegistrationResponseFactory.canHandle((FrameworkException) exception));
        }
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

    @DataProvider(name = "instanceDataProvider")
    public Object[][] getInstanceData() {
        mockHttpIdentityResponseBuilder = mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);
        mockRegistrationResponse = mock(RegistrationResponse.class);
        return new Object[][]{
                {mockHttpIdentityResponseBuilder, mockRegistrationResponse},
                {null, mockRegistrationResponse}
        };
    }

    @Test(dataProvider = "instanceDataProvider")
    public void testCreate(Object builder,
                           Object registrationResponse) throws Exception {

        if (builder == null) {
            mockHttpIdentityResponseBuilder = mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);
        } else {
            mockHttpIdentityResponseBuilder = (HttpIdentityResponse.HttpIdentityResponseBuilder) builder;
        }
        RegistrationResponseProfile registrationRequestProfile = mock(RegistrationResponseProfile.class);

        whenNew(HttpIdentityResponse.HttpIdentityResponseBuilder.class).withNoArguments().thenReturn
                (mockHttpIdentityResponseBuilder);
        when(((RegistrationResponse) registrationResponse).getRegistrationResponseProfile()).
                thenReturn(registrationRequestProfile);

        final Integer[] statusCode = new Integer[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                statusCode[0] = (Integer) invocation.getArguments()[0];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).setStatusCode(anyInt());

        final String[] header = new String[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[0] = (String) invocation.getArguments()[1];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).addHeader(anyString(), anyString());

        if (builder == null) {
            httpRegistrationResponseFactory.create((IdentityResponse) registrationResponse);
        } else {
            httpRegistrationResponseFactory.create((HttpIdentityResponse.HttpIdentityResponseBuilder) builder,
                    (IdentityResponse) registrationResponse);
        }
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

        mockHttpIdentityResponseBuilder = mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);
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

        final String[] header = new String[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[0] = (String) invocation.getArguments()[1];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).addHeader(anyString(), anyString());

        FrameworkException exception = mock(FrameworkException.class);
        when(exception.getMessage()).thenReturn(dummyDescription);

        when(exception.getErrorCode()).thenReturn(errorCode);
        httpRegistrationResponseFactory.handleException(exception);

        assertEquals((int) statusCode[0], expected);
    }

}
