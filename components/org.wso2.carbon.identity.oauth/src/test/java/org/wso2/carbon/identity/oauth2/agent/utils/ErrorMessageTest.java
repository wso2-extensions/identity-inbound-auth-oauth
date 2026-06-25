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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.agent.utils;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for {@link ErrorMessage}.
 */
public class ErrorMessageTest {

    @DataProvider(name = "errorMessages")
    public Object[][] errorMessages() {

        return new Object[][]{
                {ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, "60004"},
                {ErrorMessage.ERROR_CODE_AGENT_CONFIG_RETRIEVE, "65023"},
                {ErrorMessage.ERROR_CODE_AGENT_CONFIG_UPDATE, "65024"},
                {ErrorMessage.ERROR_CODE_AGENT_CONFIG_DELETE, "65025"},
        };
    }

    @Test(dataProvider = "errorMessages")
    public void testErrorMessageFields(ErrorMessage errorMessage, String expectedCode) {

        assertEquals(errorMessage.getCode(), expectedCode);
        assertNotNull(errorMessage.getMessage());
        assertNotNull(errorMessage.getDescription());
        assertEquals(errorMessage.toString(), expectedCode + ":" + errorMessage.getMessage());
    }
}
