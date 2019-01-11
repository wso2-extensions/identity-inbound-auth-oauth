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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.webfinger;

import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.DataProvider;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.webfinger.internal.WebFingerServiceComponentHolder;


import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Tests for DefaultWebFingerProcessor.
 */

@WithCarbonHome
@WithRealmService(injectToSingletons = { WebFingerServiceComponentHolder.class })
public class DefaultWebFingerProcessorTest {

    @Test
    public void testGetResponse() throws Exception {
        DefaultWebFingerProcessor defaultWebFingerProcessor = DefaultWebFingerProcessor.getInstance();
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        final Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(WebFingerConstants.RESOURCE, "TestResource1");
        Mockito.doAnswer(new Answer() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return parameterMap.get(invocationOnMock.getArguments()[0]);
            }
        }).when(request).getParameter(Matchers.anyString());
        Mockito.doAnswer(new Answer() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return new IteratorEnumeration(parameterMap.keySet().iterator());
            }
        }).when(request).getParameterNames();
        try {
            WebFingerResponse response = defaultWebFingerProcessor.getResponse(request);
            fail("WebFingerEndpointException should have been thrown");
        } catch (WebFingerEndpointException e) {
            //Expected exception
        }

        parameterMap.put(WebFingerConstants.REL, "TestRelates");

        try {
            WebFingerResponse response = defaultWebFingerProcessor.getResponse(request);
            assertNotNull(response);
            fail("WebFingerEndpointException should have been thrown");
        } catch (WebFingerEndpointException e) {
            //Expected exception
        }


    }

    //TODO: Need to fix this test as it gives java.lang.IllegalArgumentException: argument type mismatch
    //        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
    //        at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)

   /* @Test(dataProvider = "dataProviderForHandleError")
    public void testHandleError(String code, String exception, String expectedCode)  {
        DefaultWebFingerProcessor defaultWebFingerProcessor = DefaultWebFingerProcessor.getInstance();
        WebFingerEndpointException e = new WebFingerEndpointException(code, exception);
        assertEquals(defaultWebFingerProcessor.handleError(e), Integer.parseInt(expectedCode),
                "Status Code must match for Exception Type: " + e.getErrorCode());
    }*/

    @DataProvider
    private Object[][] dataProviderForHandleError() {
        return new Object[][] {
                { "400", WebFingerConstants.ERROR_CODE_INVALID_REQUEST, HttpServletResponse.SC_BAD_REQUEST },
                { "404", WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, HttpServletResponse.SC_NOT_FOUND },
                { "500", WebFingerConstants.ERROR_CODE_INVALID_TENANT, HttpServletResponse.SC_INTERNAL_SERVER_ERROR },
                { "415", WebFingerConstants.ERROR_CODE_JSON_EXCEPTION, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE },
                { "404", WebFingerConstants.ERROR_CODE_NO_WEBFINGER_CONFIG, HttpServletResponse.SC_NOT_FOUND } };
    }

}
