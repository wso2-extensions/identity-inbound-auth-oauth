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
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuthParRequestWrapperTest {

    private static final String REQUEST_URI = "urn:ietf:params:oauth:par:request_uri:c0143cb3-7ae0-43a3" +
            "-a023b7218c7182df";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String RESPONSE_TYPE = "code";
    private OAuthParRequestWrapper oAuthParRequestWrapper;
    private Map<String, String> params;

    @BeforeClass
    public void setUp() throws Exception {

        Map<String, String> requestParams1 = new HashMap<>();
        requestParams1.put(OAuthConstants.OAuth20Params.REQUEST_URI, REQUEST_URI);
        requestParams1.put(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        HttpServletRequest request = mockHttpRequest(requestParams1);
        params = new HashMap<>();
        params.put(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        params.put(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);
        params.put(OAuth.OAUTH_RESPONSE_TYPE, RESPONSE_TYPE);
        oAuthParRequestWrapper = new OAuthParRequestWrapper(request, params);
    }

    @Test
    public void testGetParameter() {

        assert oAuthParRequestWrapper.getParameter(OAuth.OAUTH_CLIENT_ID).equals(CLIENT_ID_VALUE);
        assert oAuthParRequestWrapper.getParameter(OAuth.OAUTH_REDIRECT_URI).equals(APP_REDIRECT_URL);
        assert oAuthParRequestWrapper.getParameter(OAuth.OAUTH_RESPONSE_TYPE).equals(RESPONSE_TYPE);
        assert oAuthParRequestWrapper.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI) == null;
    }

    @Test
    public void testGetParameterMap() {

        assert oAuthParRequestWrapper.getParameterMap().get(OAuth.OAUTH_CLIENT_ID)[0].equals(CLIENT_ID_VALUE);
        assert oAuthParRequestWrapper.getParameterMap().get(OAuth.OAUTH_REDIRECT_URI)[0].equals(APP_REDIRECT_URL);
        assert oAuthParRequestWrapper.getParameterMap().get(OAuth.OAUTH_RESPONSE_TYPE)[0].equals(RESPONSE_TYPE);
        assert oAuthParRequestWrapper.getParameterMap().get(OAuthConstants.OAuth20Params.REQUEST_URI) == null;
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
