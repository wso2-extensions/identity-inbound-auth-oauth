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

        import static org.testng.Assert.assertEquals;
        import static org.testng.Assert.assertNotNull;
        import static org.testng.Assert.fail;

/**
 * Tests for DefaultWebFingerProcessor.
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = { WebFingerServiceComponentHolder.class })
public class BackwordDefaultWebfingerProcessorTest {

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
            fail("WebFingerEndpointException should have been thrown");
        } catch (WebFingerEndpointException e) {
            //Expected exception
        }

        parameterMap.put(WebFingerConstants.RESOURCE, "http://test.t/TestResource1");
        WebFingerResponse response = defaultWebFingerProcessor.getResponse(request);
        assertNotNull(response);
    }

    @Test(dataProvider = "dataProviderForHandleError")
    public void testHandleError(WebFingerEndpointException exception, int expectedCode) throws Exception {
        DefaultWebFingerProcessor defaultWebFingerProcessor = DefaultWebFingerProcessor.getInstance();
        assertEquals(defaultWebFingerProcessor.handleError(exception), expectedCode,
                "Status Code must match for Exception Type: " + exception.getErrorCode());
    }

    @DataProvider
    private Object[][] dataProviderForHandleError() {
        return new Object[][] { { new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_REQUEST,
                WebFingerConstants.ERROR_CODE_INVALID_REQUEST), HttpServletResponse.SC_BAD_REQUEST },
                { new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE,
                        WebFingerConstants.ERROR_CODE_INVALID_RESOURCE), HttpServletResponse.SC_NOT_FOUND },
                { new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_TENANT,
                        WebFingerConstants.ERROR_CODE_INVALID_TENANT), HttpServletResponse.SC_INTERNAL_SERVER_ERROR },
                { new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_JSON_EXCEPTION,
                        WebFingerConstants.ERROR_CODE_JSON_EXCEPTION), HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE },
                { new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_NO_WEBFINGER_CONFIG,
                        WebFingerConstants.ERROR_CODE_NO_WEBFINGER_CONFIG), HttpServletResponse.SC_NOT_FOUND } };
    }

}

