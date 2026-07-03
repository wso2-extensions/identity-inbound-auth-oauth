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

import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

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
}
