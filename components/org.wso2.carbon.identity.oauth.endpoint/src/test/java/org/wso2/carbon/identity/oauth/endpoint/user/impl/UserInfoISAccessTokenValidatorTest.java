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

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;

import java.io.IOException;
import java.util.Scanner;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

@PrepareForTest(UserInforRequestDefaultValidator.class)
public class UserInfoISAccessTokenValidatorTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private Scanner scanner;
    private UserInforRequestDefaultValidator userInforRequestDefaultValidator;
    private final String TOKEN = "ZWx1c3VhcmlvOnlsYWNsYXZl";
    private final String BASIC_AUTH_HEADER = "Bearer " + TOKEN;
    private static String CONTENT_TYPE_HEADER_VALUE = "application/x-www-form-urlencoded";

    @BeforeClass
    public void setup() {
        userInforRequestDefaultValidator = new UserInforRequestDefaultValidator();
    }

    @Test
    public void testValidateToken() throws Exception {
        prepareHttpServletRequest(BASIC_AUTH_HEADER, null);
        assertEquals(BASIC_AUTH_HEADER.split(" ")[1], userInforRequestDefaultValidator.validateRequest
                (httpServletRequest));
    }

    @DataProvider
    public Object[][] getInvalidAuthorizations() {
        return new Object[][]{
                {TOKEN, null},
                {"Bearer", null},
                {null, "application/text"},
                {null, ""},
        };
    }

    @Test(dataProvider = "getInvalidAuthorizations", expectedExceptions = UserInfoEndpointException.class)
    public void testValidateTokenInvalidAuthorization(String authorization, String contentType) throws Exception {
        prepareHttpServletRequest(authorization, contentType);
        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }

    @DataProvider
    public Object[][] requestBodyWithNonASCII() {
        return new Object[][]{
                {CONTENT_TYPE_HEADER_VALUE, "access_token=" + "¥" + TOKEN, TOKEN},
                {CONTENT_TYPE_HEADER_VALUE, "access_token=" + "§" + TOKEN +
                        "&someOtherParam=value", TOKEN},
                {CONTENT_TYPE_HEADER_VALUE, "otherParam=value2©&access_token=" + TOKEN +
                        "&someOtherParam=value", TOKEN},
        };
    }

//    @Test(dataProvider = "requestBodyWithNonASCII", expectedExceptions = UserInfoEndpointException.class)
//    public void testValidateTokenWithRequestBodyNonASCII(String contentType, String requestBody, String expected) throws
//            Exception {
//        testValidateTokenWithRequestBody(contentType, requestBody, true);
//    }

    @Test(expectedExceptions = UserInfoEndpointException.class)
    public void testValidateTokenWithWrongInputStream() throws Exception {
        testValidateTokenWithRequestBody(CONTENT_TYPE_HEADER_VALUE, "access_token=" + TOKEN, false);
    }

    private String testValidateTokenWithRequestBody(String contentType, String requestBody, boolean mockScanner)
            throws Exception {
        prepareHttpServletRequest(null, contentType);
        if (mockScanner) {
            whenNew(Scanner.class).withAnyArguments().thenReturn(scanner);
            when(scanner.hasNextLine()).thenReturn(true, false);
            when(scanner.nextLine()).thenReturn(requestBody);
        } else {
            when(httpServletRequest.getInputStream()).thenThrow(new IOException());
        }

        String token = userInforRequestDefaultValidator.validateRequest(httpServletRequest);
        return token;
    }

    private void prepareHttpServletRequest(String authorization, String contentType) {
        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorization);
        when(httpServletRequest.getHeader(HttpHeaders.CONTENT_TYPE)).thenReturn(contentType);
    }
}
