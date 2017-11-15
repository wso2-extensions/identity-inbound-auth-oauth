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

package org.wso2.carbon.identity.webfinger.servlet;

import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.internal.WebFingerServiceComponentHolder;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests web-finger servlet.
 */
public class WebFingerServletTest {

    @BeforeClass
    protected void setUp() {
        WebFingerServiceComponentHolder.setWebFingerProcessor(DefaultWebFingerProcessor.getInstance());
    }

    @Test
    public void testDoGet() throws Exception {
        final Map<String, String> parameters = new HashMap<>();

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getParameterNames()).thenReturn(new IteratorEnumeration(parameters.keySet().iterator()));
        Mockito.when(request.getParameter(Matchers.anyString())).thenAnswer(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return parameters.get(invocationOnMock.getArgumentAt(0, String.class));
            }
        });

        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        
        Mockito.doAnswer(new Answer() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return null;
            }
        }).when(response).setStatus(Matchers.anyInt());

        WebFingerServlet webFingerServlet = new WebFingerServlet();
        webFingerServlet.doGet(request, response);
    }

    @Test
    public void testGetOIDProviderIssuer() throws Exception {
    }

}
