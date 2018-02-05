/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.util;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

/**
 * Test Class for the ClaimMetaDataCacheKey.
 */
public class ClaimMetaDataCacheKeyTest {

    ClaimMetaDataCacheKey testclass;
    DummyAuthenticatedUser dummy = new DummyAuthenticatedUser();

    @Test
    public void testEquals() throws Exception {

        dummy.setTenantDomain("test1Domain");
        testclass = new ClaimMetaDataCacheKey(dummy);
        assertFalse(testclass.equals("test"));

        ClaimMetaDataCacheKey testclass2 = new ClaimMetaDataCacheKey(dummy);
        assertTrue(testclass.equals(testclass2));

        DummyAuthenticatedUser dummy2 = new DummyAuthenticatedUser();
        dummy2.setTenantDomain("test2Domain");
        testclass2 = new ClaimMetaDataCacheKey(dummy2);
        assertFalse(testclass.equals(testclass2));
    }

    @Test
    public void testHashCode() throws Exception {

        testclass = new ClaimMetaDataCacheKey(null);
        assertEquals(testclass.hashCode(), 0);
        dummy.setHashValue(10);
        testclass = new ClaimMetaDataCacheKey(dummy);
        assertEquals(testclass.hashCode(), 10);
    }

    @Test
    public void testSetAuthenticatedUser() throws Exception {

        dummy.setTenantDomain("test1Domain");
        testclass = new ClaimMetaDataCacheKey(dummy);
        DummyAuthenticatedUser dummy2 = new DummyAuthenticatedUser();
        dummy2.setTenantDomain("test2Domain");
        testclass.setAuthenticatedUser(dummy2);
        assertEquals(testclass.getAuthenticatedUser(), dummy2);
    }

    static class DummyAuthenticatedUser extends AuthenticatedUser {
        int hashValue;

        @Override
        public String toString() {
            return "test";
        }

        public void setHashValue(int hashValue) {
            this.hashValue = hashValue;
        }

        @Override
        public int hashCode() {
            return hashValue;
        }

    }

}
