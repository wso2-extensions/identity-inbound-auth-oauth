/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.common;

import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.json.JSONObject;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REQUEST;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.RESPONSE_MODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.RESPONSE_TYPE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ResponseModes.JWT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ResponseModes.QUERY;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ResponseModes.QUERY_JWT;

/**
 * Test class for Code Response Validator.
 */
@PrepareForTest({OAuthCommonUtil.class})
public class CodeResponseValidatorTest extends PowerMockTestCase {

    protected CodeResponseValidator testedResponseValidator;

    @BeforeMethod
    public void setUp() throws Exception {

        testedResponseValidator = new CodeResponseValidator();
    }

    @DataProvider(name = "Request Provider")
    public Object[][] getRequestParams() {

        JSONObject validReqObj = new JSONObject();
        validReqObj.put(RESPONSE_MODE, JWT);
        JSONObject invalidReqObj = new JSONObject();
        invalidReqObj.put(RESPONSE_MODE, QUERY_JWT);

        Map<String, String> noResponseModeMap = new HashMap<>();
        Map<String, String> invalidResponseModeParameterMap = new HashMap<>();
        invalidResponseModeParameterMap.put(RESPONSE_MODE, QUERY);
        Map<String, String> validResponseModeParameterMap = new HashMap<>();
        validResponseModeParameterMap.put(RESPONSE_MODE, JWT);
        Map<String, String> validResponseModeRequestParameterMap = new HashMap<>();
        validResponseModeRequestParameterMap.put(REQUEST, validReqObj.toString());
        Map<String, String> invalidResponseModeRequestParameterMap = new HashMap<>();
        invalidResponseModeRequestParameterMap.put(REQUEST, invalidReqObj.toString());
        Map<String, String> validParamInvalidRequestMap = new HashMap<>();
        validParamInvalidRequestMap.put(RESPONSE_MODE, JWT);
        validParamInvalidRequestMap.put(REQUEST, invalidReqObj.toString());
        Map<String, String> invalidParamValidRequestMap = new HashMap<>();
        invalidParamValidRequestMap.put(REQUEST, validReqObj.toString());
        invalidParamValidRequestMap.put(RESPONSE_MODE, QUERY);
        return new Object[][]{
                {noResponseModeMap, true, false},
                {invalidResponseModeParameterMap, true, false},
                {invalidResponseModeParameterMap, false, true},
                {validResponseModeParameterMap, true, true},
                {validResponseModeRequestParameterMap, true, true},
                {invalidResponseModeRequestParameterMap, true, false},
                {validParamInvalidRequestMap, true, false},
                {validParamInvalidRequestMap, false, true},
                {invalidParamValidRequestMap, true, true},
        };
    }

    @Test(dataProvider = "Request Provider")
    public void testValidateRequiredParameters(Map<String, Object> headerMap,
                                               boolean isFapiEnabled, boolean shouldPass) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(RESPONSE_TYPE)).thenReturn(CODE);
        when(mockRequest.getParameter(CLIENT_ID)).thenReturn(CLIENT_ID);
        when(mockRequest.getParameter(RESPONSE_MODE))
                .thenReturn(headerMap.containsKey(RESPONSE_MODE) ? headerMap.get(RESPONSE_MODE).toString() : null);
        when(mockRequest.getParameter(REQUEST))
                .thenReturn(headerMap.containsKey(REQUEST) ? headerMap.get(REQUEST).toString() : null);
        when(mockRequest.getAttribute(OAuthConstants.IS_FAPI_CONFORMANT_APP)).thenReturn(isFapiEnabled);
        mockStatic(OAuthCommonUtil.class);
        when(OAuthCommonUtil.decodeRequestObject(anyString()))
                .thenReturn(headerMap.containsKey(REQUEST) ? new JSONObject(headerMap.get(REQUEST).toString()) : null);

        if (shouldPass) {
            testedResponseValidator.validateRequiredParameters(mockRequest);
            // Nothing to assert here. The above method will only throw an exception if not valid
        } else {
            try {
                testedResponseValidator.validateRequiredParameters(mockRequest);
                fail("Request validation should have failed");
            } catch (OAuthProblemException e) {
                assertTrue(e.getMessage().startsWith(OAuthError.TokenResponse.INVALID_REQUEST),
                        "Invalid error message received");
            }
        }
    }

}
