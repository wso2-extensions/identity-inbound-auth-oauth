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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.support.membermodification.MemberMatcher.methodsDeclaredIn;
import static org.powermock.api.support.membermodification.MemberModifier.suppress;
import static org.testng.Assert.assertEquals;

/**
 * Unit test covering UnregistrationRequestFactory
 */
@PrepareForTest(UnregistrationRequestFactory.class)
public class UnregistrationRequestFactoryTest extends PowerMockIdentityBaseTest{

    @Mock
    private UnregistrationRequest.DCRUnregisterRequestBuilder unregisterRequestBuilder;

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
    public void testCanHandle(String requestURI, String httpMethod, boolean expected ) throws Exception {

        when(mockHttpRequest.getRequestURI()).thenReturn(requestURI);
        when(mockHttpRequest.getMethod()).thenReturn(httpMethod);
        assertEquals(registrationRequestFactory.canHandle(mockHttpRequest, mockHttpResponse), expected,
                "Redirect Uri doesn't match");
    }

    @Test
    public void testCreate() throws Exception {

        String dummyApplicationName = "dummyApplicationName";
        String dummyUserId = "dummyUserId";
        String dummyConsumerKey = "dummyConsumerKey";

        suppress(methodsDeclaredIn(HttpIdentityRequestFactory.class));
        when(mockHttpRequest.getRequestURI()).thenReturn("dummyVal/identity/register/" + dummyConsumerKey);
        when(mockHttpRequest.getMethod()).thenReturn(HttpMethod.DELETE);
        when(mockHttpRequest.getParameter("applicationName")).thenReturn(dummyApplicationName);
        when(mockHttpRequest.getParameter("userId")).thenReturn(dummyUserId);

        final String[] header = new String[3];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[0] = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(unregisterRequestBuilder).setApplicationName(anyString());

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[1] = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(unregisterRequestBuilder).setUserId(anyString());

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[2] = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(unregisterRequestBuilder).setConsumerKey(anyString());

        registrationRequestFactory.create(unregisterRequestBuilder, mockHttpRequest, mockHttpResponse);
        assertEquals(header[0], dummyApplicationName, "Application name doesn't match with the given " +
                "application name");
        assertEquals(header[1], dummyUserId, "User id doesn't match with the given User id");
        assertEquals(header[2], dummyConsumerKey, "ConsumerKey doesn't match with the given ConsumerKey");
    }

}