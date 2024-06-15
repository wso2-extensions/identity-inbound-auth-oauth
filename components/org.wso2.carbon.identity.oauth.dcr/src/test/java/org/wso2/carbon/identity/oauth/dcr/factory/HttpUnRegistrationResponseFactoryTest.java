/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.MockedConstruction;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.UnRegistrationException;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationResponse;

import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * This class is to cover unit tests for HttpUnregistrationResponseFactory
 */
public class HttpUnRegistrationResponseFactoryTest {

    private UnregistrationResponse mockUnregistrationResponse;
    private HttpUnregistrationResponseFactory httpUnregistrationResponseFactory;
    private HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder;

    @BeforeMethod
    private void setUp() {

        mockUnregistrationResponse = mock(UnregistrationResponse.class);
        httpUnregistrationResponseFactory = new HttpUnregistrationResponseFactory();
    }

    @Test
    public void testCanHandle() throws Exception {

        IdentityResponse identityResponse = mock(IdentityResponse.class);
        assertFalse(httpUnregistrationResponseFactory.canHandle(identityResponse));
    }

    @Test
    public void testCanHandleFailed() {

        assertTrue(httpUnregistrationResponseFactory.canHandle(mockUnregistrationResponse));
    }

    @DataProvider(name = "exceptionInstanceProvider")
    public Object[][] getExceptionInstanceType() {

        return new Object[][]{
                {new UnRegistrationException("")},
                {new UnRegistrationException("", "dummyMessage")},
                {new UnRegistrationException("", new Throwable())},
                {new UnRegistrationException("", "dummyMessage", new Throwable())}
        };
    }

    @Test(dataProvider = "exceptionInstanceProvider")
    public void testCanHandleException(Object exception) {

        Assert.assertTrue(httpUnregistrationResponseFactory.canHandle((UnRegistrationException) exception));
    }

    @Test
    public void testCanHandleExceptionFailed() {

        Assert.assertFalse(httpUnregistrationResponseFactory.canHandle(new FrameworkException("")));
    }

    @Test
    public void testCreate() throws Exception {

        final Integer[] statusCode = new Integer[1];

        try (MockedConstruction<HttpIdentityResponse.HttpIdentityResponseBuilder> mockedConstruction = mockConstruction(
                HttpIdentityResponse.HttpIdentityResponseBuilder.class,
                (mock, context) -> {
                    doAnswer((Answer<Object>) invocation -> {

                        statusCode[0] = (Integer) invocation.getArguments()[0];
                        return null;
                    }).when(mock).setStatusCode(anyInt());

                    final String[] header = new String[1];
                    doAnswer((Answer<Object>) invocation -> {

                        header[0] = (String) invocation.getArguments()[1];
                        return null;
                    }).when(mock).addHeader(anyString(), anyString());
                })) {
            httpUnregistrationResponseFactory.create(mockUnregistrationResponse);

            assertEquals((int) statusCode[0], HttpServletResponse.SC_NO_CONTENT);
        }
    }

    @Test
    public void testCreateWithBuilder() throws Exception {

        mockHttpIdentityResponseBuilder = mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);

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

        httpUnregistrationResponseFactory.create(mockHttpIdentityResponseBuilder, mockUnregistrationResponse);
        assertEquals((int) statusCode[0], HttpServletResponse.SC_NO_CONTENT);
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
                    }).when(mock).addHeader(eq(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL),
                            anyString());

                    doAnswer((Answer<Object>) invocation -> {

                        header[1] = (String) invocation.getArguments()[1];
                        return null;
                    }).when(mock).addHeader(eq(OAuthConstants.HTTP_RESP_HEADER_PRAGMA), anyString());
                })) {

            FrameworkClientException exception = mock(FrameworkClientException.class);
            when(exception.getMessage()).thenReturn("dummyDescription");
            httpUnregistrationResponseFactory.handleException(exception);

            assertEquals(header[0], OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE, "Wrong header value " +
                    "for " + OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL);
            assertEquals(header[1], OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE, "Wrong header value for " +
                    OAuthConstants.HTTP_RESP_HEADER_PRAGMA);
            assertEquals((int) statusCode[0], HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    "Status code doesn't match with "
                    + HttpServletResponse.SC_BAD_REQUEST);
        }
    }
}
