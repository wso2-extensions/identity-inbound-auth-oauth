/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.par.core;

import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.internal.ParAuthServiceComponentDataHolder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

/**
 * Test class for ParRequestBuilder.
 */
@PrepareForTest({LoggerUtils.class, ParAuthServiceComponentDataHolder.class})
public class ParRequestBuilderTest extends PowerMockTestCase {

    @Mock
    private ParAuthServiceImpl parAuthService;
    @Mock
    private ParAuthServiceComponentDataHolder parAuthServiceComponentDataHolder;
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String RESPONSE_TYPE = "code";
    private static final String VALID_REQUEST_URI = "urn:ietf:params:oauth:par:request_uri:c0143cb3-7ae0-43a3" +
            "-a023b7218c7182df";
    private static final String INVALID_REQUEST_URI = "urn:ietf:params:oauth:request_uri:c0143cb3-7ae0-43a3" +
            "-a023b7218c7182df";
    HttpServletRequest request;
    private ParRequestBuilder parRequestBuilder;
    private Map<String, String> params;

    @BeforeClass
    public void setUp() throws Exception {

        parRequestBuilder = new ParRequestBuilder();
        params = new HashMap<>();
    }

    @DataProvider(name = "testCanHandleData")
    public Object[][] testCanHandleData() {

        Map<String, String> requestParams1 = new HashMap<>();
        requestParams1.put(OAuthConstants.OAuth20Params.REQUEST_URI, VALID_REQUEST_URI);

        Map<String, String> requestParams2 = new HashMap<>();
        requestParams2.put(OAuthConstants.OAuth20Params.REQUEST_URI, INVALID_REQUEST_URI);
        requestParams2.put(OAuthConstants.OAuth20Params.SCOPE, "openid email");

        Map<String, String> requestParams3 = new HashMap<>();
        requestParams3.put(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);

        return new Object[][]{

                {requestParams1, true},
                {requestParams2, false},
                {requestParams3, false}
        };
    }

    @Test(dataProvider = "testCanHandleData")
    public void testCanHandle(Object requestParamsObj, boolean expectedStatus) {

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        Map<String, String> requestParams = (Map<String, String>) requestParamsObj;
        request = mockHttpRequest(requestParams);

        assertEquals(parRequestBuilder.canHandle(request), expectedStatus);
        // Test for null request.
        assertFalse(parRequestBuilder.canHandle(null));
    }

    @Test
    public void testBuildRequest() throws Exception {

        Map<String, String> requestParams = new HashMap<>();
        requestParams.put(OAuthConstants.OAuth20Params.REQUEST_URI, VALID_REQUEST_URI);
        requestParams.put(OAuthConstants.OAuth20Params.CLIENT_ID, CLIENT_ID_VALUE);
        request = mockHttpRequest(requestParams);
        params.put(OAuthConstants.OAuth20Params.CLIENT_ID, CLIENT_ID_VALUE);
        params.put(OAuthConstants.OAuth20Params.REDIRECT_URI, APP_REDIRECT_URL);
        params.put(OAuthConstants.OAuth20Params.RESPONSE_TYPE, RESPONSE_TYPE);

        mockStatic(ParAuthServiceComponentDataHolder.class);
        when(ParAuthServiceComponentDataHolder.getInstance()).thenReturn(parAuthServiceComponentDataHolder);
        when(parAuthServiceComponentDataHolder.getParAuthService()).thenReturn(parAuthService);
        when(parAuthService.retrieveParams(anyString(), anyString())).thenReturn(params);

        HttpServletRequest builtRequest = parRequestBuilder.buildRequest(request);

        assertEquals(builtRequest.getParameter(OAuthConstants.OAuth20Params.CLIENT_ID), CLIENT_ID_VALUE);
        assertEquals(builtRequest.getParameter(OAuthConstants.OAuth20Params.REDIRECT_URI), APP_REDIRECT_URL);
        assertEquals(builtRequest.getParameter(OAuthConstants.OAuth20Params.RESPONSE_TYPE), RESPONSE_TYPE);
    }

    private HttpServletRequest mockHttpRequest(final Map<String, String> requestParams) {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        doAnswer(invocation -> {
            String key = (String) invocation.getArguments()[0];
            return requestParams.get(key);
        }).when(httpServletRequest).getParameter(anyString());

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameterNames()).thenReturn(Collections.enumeration(requestParams.keySet()));
        when(httpServletRequest.getMethod()).thenReturn(HttpMethod.POST);
        when(httpServletRequest.getContentType()).thenReturn(OAuth.ContentType.URL_ENCODED);

        return httpServletRequest;
    }
}
