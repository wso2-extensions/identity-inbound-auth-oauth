/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Unit tests for {@link ApiAuthnUtils}.
 */
public class ApiAuthnUtilsTest {

    @Test
    public void testBase64URLDecodeWithValidValue() throws AuthServiceClientException {

        String plainText = "authenticatorId";
        String encoded = Base64.getUrlEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));

        String decoded = ApiAuthnUtils.base64URLDecode(encoded);

        Assert.assertEquals(decoded, plainText);
    }

    @DataProvider(name = "invalidBase64URLValues")
    public Object[][] invalidBase64URLValues() {

        return new Object[][]{
                {"%^"},
                {"not-a-valid-base64-value!!"},
                {"a\r\nInjected-Header: malicious"},
        };
    }

    @Test(dataProvider = "invalidBase64URLValues")
    public void testBase64URLDecodeWithInvalidValueThrowsClientException(String invalidValue) {

        try {
            ApiAuthnUtils.base64URLDecode(invalidValue);
            Assert.fail("Expected AuthServiceClientException was not thrown for value: " + invalidValue);
        } catch (AuthServiceClientException e) {
            Assert.assertEquals(e.getErrorCode(), AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code());
            Assert.assertEquals(e.getMessage(), "Error occurred while decoding the Base64 URL value.");
            Assert.assertFalse(e.getMessage().contains(invalidValue),
                    "Decode error message must not reflect the raw, request-controlled value.");
            Assert.assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }
}
