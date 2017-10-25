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

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.testng.Assert.assertEquals;

public class SessionDataCacheKeyTest {
    String sessionDataId = "org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey@54d4dc7";
    Integer sessionDataIdHashcode = sessionDataId.hashCode();

    @Test
    public void testGetSessionDataId() throws Exception {
        SessionDataCacheKey sessionDataCacheKey = new SessionDataCacheKey(sessionDataId);
        assertEquals(sessionDataCacheKey.getSessionDataId(), sessionDataId, "Get sessionDataId successfully.");
    }

    @DataProvider(name = "TestEquals")
    public Object[][] testequals() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "TestEquals")
    public void testEquals(boolean istrue) throws Exception {
        Object object = new Object();
        SessionDataCacheKey sessionDataCacheKey = new SessionDataCacheKey(sessionDataId);
        SessionDataCacheKey sessionDataCacheKeySample = new SessionDataCacheKey(sessionDataId);
        if (istrue) {
            assertTrue(sessionDataCacheKey.equals(sessionDataCacheKeySample));
        }
        assertFalse(sessionDataCacheKey.equals(object));
    }

    @Test
    public void testHashCode() throws Exception {
        SessionDataCacheKey sessionDataCacheKey = new SessionDataCacheKey(sessionDataId);
        Integer sessionDataIdHashCodeSample = sessionDataCacheKey.hashCode();
        assertEquals(sessionDataIdHashCodeSample
                , sessionDataIdHashcode, "Get SessionDataHashCode successfully.");
    }
}
