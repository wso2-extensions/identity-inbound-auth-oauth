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

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;

import java.util.ArrayList;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit test covering UnregistrationRequestFactory
 */
@Listeners(MockitoTestNGListener.class)
public class UnregistrationRequestFactoryTest {

    @Mock
    private HttpServletRequest mockHttpRequest;

    @Mock
    private HttpServletResponse mockHttpResponse;

    private UnregistrationRequestFactory registrationRequestFactory;

    @BeforeMethod
    private void setUp() {

        registrationRequestFactory = new UnregistrationRequestFactory();
    }

    /**
     * DataProvider: requestURI, httpMethod, expected value
     */
    @DataProvider(name = "httpMethodAndUriProvider")
    public Object[][] getHttpMethodAndUri() {

        return new Object[][]{
                {"dummyVal/identity/register/dummyVal", HttpMethod.DELETE, true},
                {"dummyVal/identity/register/", HttpMethod.DELETE, false},
        };
    }

    @Test(dataProvider = "httpMethodAndUriProvider")
    public void testCanHandle(String requestURI, String httpMethod, boolean expected) throws Exception {

        when(mockHttpRequest.getRequestURI()).thenReturn(requestURI);
        lenient().when(mockHttpRequest.getMethod()).thenReturn(httpMethod);
        assertEquals(registrationRequestFactory.canHandle(mockHttpRequest, mockHttpResponse), expected,
                "Redirect Uri doesn't match");
    }

    @Test
    public void testCreate() throws Exception {

        mockHttpResponse = mock(HttpServletResponse.class);
        mockHttpRequest = mock(HttpServletRequest.class);
        String dummyConsumerKey = "dummyConsumerKey";
        when(mockHttpRequest.getRequestURI()).thenReturn("dummyVal/identity/register/" + dummyConsumerKey);
        when(mockHttpRequest.getMethod()).thenReturn(HttpMethod.DELETE);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        String dummyApplicationName = "dummyApplicationName";
        when(mockHttpRequest.getParameter("applicationName")).thenReturn(dummyApplicationName);
        String dummyUserId = "dummyUserId";
        when(mockHttpRequest.getParameter("userId")).thenReturn(dummyUserId);

        final String[] header = new String[3];

        try (MockedConstruction<UnregistrationRequest.DCRUnregisterRequestBuilder> mockedConstruction =
                     mockConstruction(UnregistrationRequest.DCRUnregisterRequestBuilder.class,
                (mock, context) -> {
                    doAnswer((Answer<Object>) invocation -> {

                        header[0] = (String) invocation.getArguments()[0];
                        return null;
                    }).when(mock).setApplicationName(anyString());

                    doAnswer((Answer<Object>) invocation -> {

                        header[1] = (String) invocation.getArguments()[0];
                        return null;
                    }).when(mock).setUserId(anyString());

                    doAnswer((Answer<Object>) invocation -> {

                        header[2] = (String) invocation.getArguments()[0];
                        return null;
                    }).when(mock).setConsumerKey(anyString());
                })) {
            registrationRequestFactory.create(mockHttpRequest, mockHttpResponse);

            assertEquals(header[0], dummyApplicationName, "Application name doesn't match with the given " +
                    "application name");
            assertEquals(header[1], dummyUserId, "User id doesn't match with the given User id");
            assertEquals(header[2], dummyConsumerKey, "ConsumerKey doesn't match with the given ConsumerKey");
        }
    }

    @Test
    public void testCreateWithBuilder() throws Exception {

        mockHttpResponse = mock(HttpServletResponse.class);
        mockHttpRequest = mock(HttpServletRequest.class);
        String dummyConsumerKey = "dummyConsumerKey";
        when(mockHttpRequest.getRequestURI()).thenReturn("dummyVal/identity/register/" + dummyConsumerKey);
        when(mockHttpRequest.getMethod()).thenReturn(HttpMethod.DELETE);
        when(mockHttpRequest.getHeaderNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        when(mockHttpRequest.getAttributeNames()).thenReturn(Collections.enumeration(new ArrayList<>()));
        String dummyApplicationName = "dummyApplicationName";
        when(mockHttpRequest.getParameter("applicationName")).thenReturn(dummyApplicationName);
        String dummyUserId = "dummyUserId";
        when(mockHttpRequest.getParameter("userId")).thenReturn(dummyUserId);

        UnregistrationRequest.DCRUnregisterRequestBuilder identityRequestBuilder =
                (UnregistrationRequest.DCRUnregisterRequestBuilder) registrationRequestFactory.create(mockHttpRequest,
                        mockHttpResponse);
        UnregistrationRequest build = identityRequestBuilder.build();
        assertEquals(build.getApplicationName(), dummyApplicationName,
                "Application name doesn't match with the given " +
                        "application name");
        assertEquals(build.getUserId(), dummyUserId, "User id doesn't match with the given User id");
        assertEquals(build.getConsumerKey(), dummyConsumerKey, "ConsumerKey doesn't match with the given ConsumerKey");
    }
}
