/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.common;

import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.NONCE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.SCOPE;

/**
 * Test class for CodeTokenResponse Validator.
 */
public class CodeTokenResponseValidatorTest {

    protected CodeTokenResponseValidator testedResponseValidator;

    @BeforeMethod
    public void setUp() throws Exception {

        testedResponseValidator = new CodeTokenResponseValidator();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @DataProvider(name = "Request Provider")
    public Object[][] getRequestParams() {

        Map<String, String> validOIDCScopeMap = new HashMap<>();
        validOIDCScopeMap.put(SCOPE, OAuthConstants.Scope.OPENID);
        Map<String, String> nonOIDCScopeMap = new HashMap<>();
        nonOIDCScopeMap.put(SCOPE, "notOpenid");
        Map<String, String> blankScopeMap = new HashMap<>();
        blankScopeMap.put(SCOPE, "");
        return new Object[][]{
                {validOIDCScopeMap, true},
                {nonOIDCScopeMap, false},
                {blankScopeMap, false},
        };
    }

    @Test(dataProvider = "Request Provider")
    public void testValidateRequiredParameters(Map<String, String> headerMap, boolean shouldPass) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            when(mockRequest.getParameter(entry.getKey())).thenReturn(entry.getValue());
        }
        when(mockRequest.getParameter("response_type")).thenReturn(getResponseTypeValue());
        when(mockRequest.getParameter(CLIENT_ID)).thenReturn(CLIENT_ID);
        when(mockRequest.getParameter("redirect_uri")).thenReturn("www.oidc.test.com");
        if (shouldPass) {
            testedResponseValidator.validateRequiredParameters(mockRequest);
            // Nothing to assert here. The above method will only throw an exception if not valid
        } else {
            try {
                testedResponseValidator.validateRequiredParameters(mockRequest);
                fail("Request validation should have failed");
            } catch (OAuthProblemException e) {
                assertTrue(e.getMessage().startsWith(OAuthError.TokenResponse.INVALID_REQUEST), "Invalid error " +
                        "message received");
            }
        }
    }

    @DataProvider(name = "Request Method Provider")
    public Object[][] getRequestMethod() {

        return new Object[][]{
                {"GET", true},
                {"POST", true},
                {"HEAD", false},
                {"DELETE", false},
                {"OPTIONS", false},
                {"PUT", false},
                {"", false},
                {null, false}
        };
    }

    @Test(dataProvider = "Request Method Provider")
    public void testValidateMethod(String method, boolean shouldPass) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getMethod()).thenReturn(method);
        if (shouldPass) {
            testedResponseValidator.validateMethod(mockRequest);
            // Nothing to assert here. The above method will only throw an exception if not valid
        } else {
            try {
                testedResponseValidator.validateMethod(mockRequest);
                fail();
            } catch (OAuthProblemException e) {
                assertTrue(e.getMessage().startsWith(OAuthError.TokenResponse.INVALID_REQUEST), "Invalid error " +
                        "message received. Received was: " + e.getMessage());
            }
        }
    }

    /**
     * Method returns the response type associated with the class.
     *
     * @return response_type
     */
    protected String getResponseTypeValue() {
        return "code token";
    }
}
