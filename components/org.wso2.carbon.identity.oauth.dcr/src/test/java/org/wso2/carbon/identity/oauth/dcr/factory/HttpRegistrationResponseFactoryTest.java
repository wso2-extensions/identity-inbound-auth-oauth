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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doAnswer;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit test covering HttpRegistrationResponseFactory
 */
@PrepareForTest(HttpRegistrationResponseFactory.class)
public class HttpRegistrationResponseFactoryTest extends PowerMockIdentityBaseTest {

    private RegistrationResponse mockRegistrationResponse;
    private HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder;
    private HttpRegistrationResponseFactory httpRegistrationResponseFactory;
    private List<String> grantType = new ArrayList<>();
    private List<String> redirectUrl = new ArrayList<>();
    private String dummyDescription = "dummyDescription";

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
        mockHttpIdentityResponseBuilder = mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);
        when(mockRegistrationResponse.getRegistrationResponseProfile()).thenReturn(registrationRequestProfile);

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

        httpRegistrationResponseFactory.create(mockHttpIdentityResponseBuilder, mockRegistrationResponse);
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

    @Test
    public void testHandleException() throws Exception {

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
        httpRegistrationResponseFactory.handleException(exception);

        assertEquals(header[0], MediaType.APPLICATION_JSON);
        assertEquals((int) statusCode[0], HttpServletResponse.SC_BAD_REQUEST);
    }

}
