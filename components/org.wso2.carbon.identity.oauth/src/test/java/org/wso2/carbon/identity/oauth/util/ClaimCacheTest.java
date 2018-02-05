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

import static org.testng.Assert.assertTrue;

/**
 * Test Class for the ClaimCache.
 */
public class ClaimCacheTest {

    @Test
    public void testGetInstance() throws Exception {
        //test a sigleton class with empty instance
        assertTrue(ClaimCache.getInstance() instanceof ClaimCache);
        //test a singleton class with existing instance
        assertTrue(ClaimCache.getInstance() instanceof ClaimCache);
    }

}
