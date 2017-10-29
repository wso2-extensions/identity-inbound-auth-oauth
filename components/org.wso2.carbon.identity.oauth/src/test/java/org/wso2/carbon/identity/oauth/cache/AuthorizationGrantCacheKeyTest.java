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

public class AuthorizationGrantCacheKeyTest {
    String userAttributesId = "UserID123";
    Integer userAttributeHashCode = userAttributesId.hashCode();

    @Test
    public void testGetUserAttributesId() throws Exception {
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(userAttributesId);
        assertEquals(authorizationGrantCacheKey.getUserAttributesId(), userAttributesId
                , "Get userattributeId successfully.");
    }

    @DataProvider(name = "TestEqualsAuthorizationGrant")
    public Object[][] testequals() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "TestEqualsAuthorizationGrant")
    public void testEquals(boolean istrue) throws Exception {
        Object object = new Object();
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(userAttributesId);
        AuthorizationGrantCacheKey authorizationGrantCacheKeySample = new AuthorizationGrantCacheKey(userAttributesId);
        if (istrue) {
            assertTrue(authorizationGrantCacheKey.equals(authorizationGrantCacheKeySample));
        }
        assertFalse(authorizationGrantCacheKey.equals(object));
    }

    @Test
    public void testHashCode() throws Exception {
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(userAttributesId);
        Integer authorizationGrantHashCodeSample = authorizationGrantCacheKey.hashCode();
        assertEquals(authorizationGrantHashCodeSample, userAttributeHashCode
                , "Get userattribute Hashcode successfully.");
    }
}
