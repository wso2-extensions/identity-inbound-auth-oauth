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
