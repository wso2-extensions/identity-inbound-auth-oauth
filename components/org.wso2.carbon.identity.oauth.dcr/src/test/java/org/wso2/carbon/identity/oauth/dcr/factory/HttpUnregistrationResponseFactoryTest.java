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

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.exception.UnRegistrationException;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationResponse;

import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


public class HttpUnregistrationResponseFactoryTest extends PowerMockTestCase {

    private UnregistrationResponse mockUnregistrationResponse;
    private HttpUnregistrationResponseFactory httpUnregistrationResponseFactory;
    private HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder;

    @BeforeMethod
    private void setUp() {

        mockUnregistrationResponse = mock(UnregistrationResponse.class);
        httpUnregistrationResponseFactory = new HttpUnregistrationResponseFactory();

    }

    @DataProvider(name = "instanceProvider")
    public Object[][] getInstanceType() {

        mockUnregistrationResponse = mock(UnregistrationResponse.class);
        IdentityResponse identityResponse = mock(IdentityResponse.class);
        return new Object[][]{
                {mockUnregistrationResponse, true},
                {identityResponse, false}
        };
    }

    @Test(dataProvider = "instanceProvider")
    public void testCanHandle(Object identityResponse, Boolean expected) throws Exception {
        if (expected) {
            assertTrue(httpUnregistrationResponseFactory.canHandle((UnregistrationResponse) identityResponse));
        } else {
            assertFalse(httpUnregistrationResponseFactory.canHandle((IdentityResponse) identityResponse));
        }
    }

    @DataProvider(name = "exceptionInstanceProvider")
    public Object[][] getExceptionInstanceType() {

        FrameworkException exception1 = new UnRegistrationException("");
        FrameworkException exception2 = new FrameworkException("");
        return new Object[][]{
                {exception1, true},
                {exception2, false}
        };
    }

    @Test(dataProvider = "exceptionInstanceProvider")
    public void testCanHandleException(Object exception, boolean expected) throws Exception {

        if (expected) {
            Assert.assertTrue(httpUnregistrationResponseFactory.canHandle((UnRegistrationException) exception));
        } else {
            Assert.assertFalse(httpUnregistrationResponseFactory.canHandle((FrameworkException) exception));
        }
    }

    @Test
    public void testCreate()  {

        mockHttpIdentityResponseBuilder = mock(HttpIdentityResponse.HttpIdentityResponseBuilder.class);
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

        httpUnregistrationResponseFactory.create(mockHttpIdentityResponseBuilder, mockUnregistrationResponse);
        assertEquals((int) statusCode[0], HttpServletResponse.SC_NO_CONTENT);
    }

}
