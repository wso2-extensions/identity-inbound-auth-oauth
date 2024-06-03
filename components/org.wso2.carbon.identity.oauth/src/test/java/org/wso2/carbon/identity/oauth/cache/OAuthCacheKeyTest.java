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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.junit.Assert.assertNotEquals;
import static org.testng.Assert.assertEquals;

public class OAuthCacheKeyTest {
    String cacheKeyString = "cacheKey1";
    Integer cacheKeyStringHashCode = cacheKeyString.hashCode();

    @Test
    public void testGetCacheKeyString() throws Exception {
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKeyString);
        assertEquals(oAuthCacheKey.getCacheKeyString(), cacheKeyString, "Get cachekeyString successfully.");
    }

    @DataProvider(name = "TestEqualsOauthCache")
    public Object[][] testEquals() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "TestEqualsOauthCache")
    public void testEquals(boolean isTrue) throws Exception {
        Object object = new Object();
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKeyString);
        OAuthCacheKey oAuthCacheKeySample = new OAuthCacheKey(cacheKeyString);
        if (isTrue) {
            assertEquals(oAuthCacheKey, oAuthCacheKeySample);
        }
        assertNotEquals(oAuthCacheKey, object);
    }

    @Test
    public void testHashCode() throws Exception {
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKeyString);
        Integer oAuthCacheIdHashCodeSample = oAuthCacheKey.hashCode();
        assertEquals(oAuthCacheIdHashCodeSample, cacheKeyStringHashCode, "Get cachekeyHashcode successfully.");
    }
}
