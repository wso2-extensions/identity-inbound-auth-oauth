/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Test cases for {@link UserInforRequestDefaultValidator}.
 */
public class UserInforRequestDefaultValidatorTest {

    private UserInforRequestDefaultValidator validator;

    @BeforeMethod
    public void setUp() {

        validator = new UserInforRequestDefaultValidator();
    }

    @Test(expectedExceptions = UserInfoEndpointException.class)
    public void testMultipleAuthorizationHeadersRejected() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);

        Enumeration<String> multipleHeaders =
                Collections.enumeration(Arrays.asList("Bearer token1", "Bearer token2"));
        when(request.getHeaders(HttpHeaders.AUTHORIZATION)).thenReturn(multipleHeaders);

        validator.validateRequest(request);
    }

    @Test
    public void testSingleAuthorizationHeaderAccepted() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);

        Enumeration<String> singleHeader =
                Collections.enumeration(Collections.singletonList("Bearer token1"));
        when(request.getHeaders(HttpHeaders.AUTHORIZATION)).thenReturn(singleHeader);

        String token = validator.validateRequest(request);
        assertEquals(token, "token1", "Validator should return the token from a single Authorization header.");
    }

    @Test
    public void testNoAuthorizationHeaderFallsBackToBody() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);

        // No Authorization header -> empty enumeration
        when(request.getHeaders(HttpHeaders.AUTHORIZATION))
                .thenReturn(Collections.emptyEnumeration());

        // Form-encoded content type so it enters the body-parsing path
        when(request.getHeader(HttpHeaders.CONTENT_TYPE))
                .thenReturn("application/x-www-form-urlencoded");

        // Non-GET method (GET is rejected on this path)
        when(request.getMethod()).thenReturn("POST");

        // Body carrying the access token
        String body = "access_token=token1";
        when(request.getInputStream()).thenReturn(toServletInputStream(body));

        String token = validator.validateRequest(request);
        assertEquals(token, "token1",
                "Validator should extract the token from the body when no Authorization header is present.");
    }

    /**
     * Wraps a string in a ServletInputStream for mocking request bodies.
     */
    private ServletInputStream toServletInputStream(String content) {

        ByteArrayInputStream byteStream =
                new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        return new ServletInputStream() {
            @Override
            public int read() {

                return byteStream.read();
            }
        };
    }
}