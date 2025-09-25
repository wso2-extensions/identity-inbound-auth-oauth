/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.validators;

import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

import java.lang.reflect.Method;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.CALLBACK_URL_REGEXP_PREFIX;

/**
 * Tests for private method validateCallbackURI in {@link AbstractResponseTypeRequestValidator} using reflection.
 * This validates normal, regex, loopback and literal character enforcement scenarios with a data provider.
 */
public class AbstractResponseTypeRequestValidatorCallbackURITest {

    @DataProvider(name = "callbackValidationDataProvider")
    public Object[][] callbackValidationDataProvider() {

        return new Object[][]{
                // registeredCallback, providedCallback, enforceLiteralCharacters, expected
                {"https://example.com/callback", "https://example.com/callback", "true", true},
                {"https://example.com/callback", "https://example.com/callback", "false", true},
                {"https://example.com/callback", "https://evil.com/callback", "true", false},
                {"https://example.com/callback", "https://evil.com/callback", "false", false},
                {"http://127.0.0.1:49152/return", "http://127.0.0.1:60000/return", "true", true},
                {CALLBACK_URL_REGEXP_PREFIX + "https://app.example.com/callback?scope=read+write",
                        "https://app.example.com/callback?scope=read+write", "true", true},
                {CALLBACK_URL_REGEXP_PREFIX + "https://app.example.com/callback?scope=read+write",
                        "https://app.example.com/callback?scope=read+write", "false", false},
                {CALLBACK_URL_REGEXP_PREFIX + "https://app.example.com/callback",
                        "https://app-example.com/callback", "false", true},
                {CALLBACK_URL_REGEXP_PREFIX + "https://app.example.com/callback",
                        "https://app-example.com/callback", "true", false},
                {CALLBACK_URL_REGEXP_PREFIX + "https://example.com/callback+v1",
                        "https://example.com/callbackv1", "false", true},
                {CALLBACK_URL_REGEXP_PREFIX + "https://example.com/callback+v1",
                        "https://example.com/callbackv1", "true", false},
                {CALLBACK_URL_REGEXP_PREFIX + "(https://a.example.com/cb|https://b.example.com/cb)",
                        "https://b.example.com/cb", "true", true},
                {CALLBACK_URL_REGEXP_PREFIX + "(https://a.example.com/cb|https://b.example.com/cb)",
                        "https://c.example.com/cb", "true", false},
                {"https://example.com/callback", null, "true", false},

                // Regular redirect URL registered.
                {"https://sampleapp.com/callback", "https://sampleapp.com/callback", "false", true},
                {"https://sampleapp.com/callback", "https://127.0.0.1:8080/callback", "false", false},

                // Loopback redirect URL registered.
                {"https://127.0.0.1:8080/callback", "https://127.0.0.1:8081/callback", "false", true},
                {"https://127.0.0.1:8080/anothercallback", "https://127.0.0.1:8080/callback", "false", false},
                {"https://127.0.0.1:8080/callback", "https://localhost:8080/callback", "false", false},
                {"https://127.0.0.1:8080/callback", "https://sampleapp.com/callback", "false", false},

                // Simple regex based registered callback URI with loopback URL.
                {"regexp=(https://((sampleapp.com)|(127.0.0.1:8000))(/callback))",
                        "https://sampleapp.com/callback", "false", true},
                {"regexp=(https://((sampleapp.com)|(127.0.0.1:8000))(/callback))",
                        "https://127.0.0.1:8001/callback", "false", true},
                {"regexp=(https://((sampleapp.com)|(127.0.0.1:8000))(/callback))",
                        "https://127.0.0.1:8001/callback", "false", true},

                // Regex with dynamic query values.
                {"regexp=https://127.0.0.1:8090\\?id=(.*)", "https://127.0.0.1:8080?id=hg7", "false", true},
                {"regexp=https://127.0.0.1:8090\\?id=(.*)", "https://127.0.0.1:8080?id=hg7", "true", true},
                {"regexp=https://127.0.0.1:8090/callbak\\?id=(.*)", "https://127.0.0.1:8080?id=hg7", "false", false},
                {"regexp=https://127.0.0.1:8090/callbak\\?id=(.*)", "https://127.0.0.1:8080?id=hg7", "true", false},

                // Regex with a range of port numbers.
                {"regexp=((https://127.0.0.1:)([8][0]{2}[0-7])(/callback))",
                        "https://127.0.0.1:8089/callback", "false", false},
                {"regexp=((https://127.0.0.1:)([8][0]{2}[0-7])(/callback))",
                        "https://127.0.0.1:8007/callback", "false", false},
                {"regexp=(((https://127.0.0.1)|((https://sampleapp.com:)([8][0]{2}[0-7])))(/callback))",
                        "https://127.0.0.1:10000/callback", "false", true},
                {"regexp=(((https://127.0.0.1)|((https://127.0.0.2:)([8][0]{2}[0-7])))(/callback))",
                        "https://127.0.0.2:8007/callback", "false", true},
                {"regexp=((https://127.0.0.2:)([8][0]{2}[0-7])(/callback))",
                        "https://127.0.0.2:8089/callback", "false", false},
                {"regexp=((https://127.0.0.2:)([8][0]{2}[0-7])(/callback))",
                        "https://127.0.0.2:8007/callback", "false", true},
        };
    }

    @Test(dataProvider = "callbackValidationDataProvider")
    public void testValidateCallbackURI(String registeredCallback, String providedCallback,
                                        String enforceLiteralCharacters, boolean expected) throws Exception {

        // Concrete minimal implementation to access the private method through reflection.
        AbstractResponseTypeRequestValidator validator = new AbstractResponseTypeRequestValidator() {
            @Override
            public String getResponseType() {
                return "code";
            }
        };

        OAuthAppDO app = new OAuthAppDO();
        app.setCallbackUrl(registeredCallback);

        Method m = AbstractResponseTypeRequestValidator.class
                .getDeclaredMethod("validateCallbackURI", String.class, OAuthAppDO.class);
        m.setAccessible(true);

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty("OAuth.Callback.EnforceLiteralCharacters"))
                    .thenReturn(enforceLiteralCharacters);
            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
            boolean result = (boolean) m.invoke(validator, providedCallback, app);
            assertEquals(result, expected, "Failed for registered callback '" +
                    registeredCallback + "' and provided callback '" + providedCallback + "'.");
        }
    }
}
