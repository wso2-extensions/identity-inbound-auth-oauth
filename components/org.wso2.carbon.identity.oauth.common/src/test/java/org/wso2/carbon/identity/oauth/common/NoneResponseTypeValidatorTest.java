/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.common;

import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

/**
 * Test class for NoneResponseType Validator.
 */
public class NoneResponseTypeValidatorTest {

    protected NoneResponseTypeValidator testedResponseValidator;

    @BeforeMethod
    public void setUp() throws Exception {

        testedResponseValidator = new NoneResponseTypeValidator();
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @DataProvider(name = "successRequestMethodProvider")
    public Object[][] getSuccessRequestMethod() {

        return new Object[][]{
                {"GET"},
                {"POST"}
        };
    }

    @DataProvider(name = "failureRequestMethodProvider")
    public Object[][] getFailureRequestMethod() {

        return new Object[][]{
                {"HEAD"},
                {"DELETE"},
                {"OPTIONS"},
                {"PUT"},
                {""},
                {null}
        };
    }

    @Test(dataProvider = "successRequestMethodProvider")
    public void testValidateMethodSuccess(String method) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getMethod()).thenReturn(method);
        testedResponseValidator.validateMethod(mockRequest);
        // Nothing to assert here. The above method will only throw an exception if not valid
    }

    @Test(dataProvider = "failureRequestMethodProvider")
    public void testValidateMethodFailure(String method) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getMethod()).thenReturn(method);

        try {
            testedResponseValidator.validateMethod(mockRequest);
            fail(method + " method should not be allowed.");
        } catch (OAuthProblemException e) {
            assertEquals(e.getError(), OAuthError.CodeResponse.INVALID_REQUEST);
        }
    }

}
