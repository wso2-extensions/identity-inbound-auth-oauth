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

package org.wso2.carbon.identity.oauth.ciba.grant;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CibaGrantValidatorTest {

    private CibaGrantValidator cibaGrantValidator;

    @BeforeMethod
    public void setUp() {
        cibaGrantValidator = new CibaGrantValidator();
    }

    @Test
    public void testValidateRequiredParams() throws OAuthProblemException {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getContentType()).thenReturn("application/x-www-form-urlencoded");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getParameter("grant_type")).thenReturn("ciba");
        when(mockRequest.getParameter(CibaConstants.AUTH_REQ_ID)).thenReturn("test-auth-req-id");

        cibaGrantValidator.validateMethod(mockRequest);
        cibaGrantValidator.validateContentType(mockRequest);
        cibaGrantValidator.validateRequiredParameters(mockRequest);
    }

    @Test(expectedExceptions = OAuthProblemException.class)
    public void testValidateMissingAuthReqId() throws OAuthProblemException {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getContentType()).thenReturn("application/x-www-form-urlencoded");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getParameter("grant_type")).thenReturn("ciba");
        // auth_req_id missing

        cibaGrantValidator.validateRequiredParameters(mockRequest);
    }
}
