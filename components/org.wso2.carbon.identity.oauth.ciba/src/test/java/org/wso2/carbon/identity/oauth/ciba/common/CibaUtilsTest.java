/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.ciba.common;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class CibaUtilsTest {

    @DataProvider(name = "expiryTimeProvider")
    public Object[][] expiryTimeProvider() {
        return new Object[][] {
                { 3600L, "1 hour" },
                { 7200L, "2 hours" },
                { 3660L, "1 hour" }, // Integer division check
                { 60L, "1 minute" },
                { 120L, "2 minutes" },
                { 90L, "1 minute" }, // Integer division check
                { 59L, "59 seconds" },
                { 1L, "1 second" },
                { 0L, "0 seconds" }
        };
    }

    @Test(dataProvider = "expiryTimeProvider")
    public void testGetExpiryTimeAsString(long expiresIn, String expected) {
        Assert.assertEquals(CibaUtils.getExpiryTimeAsString(expiresIn), expected);
    }
}
