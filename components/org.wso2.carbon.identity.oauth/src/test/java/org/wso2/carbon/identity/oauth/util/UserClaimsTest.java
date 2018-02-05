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

import java.util.TreeMap;

import static org.testng.Assert.assertEquals;

/**
 * Test Class for the UserClaims.
 */
public class UserClaimsTest {

    TreeMap<String, String> testval = new TreeMap<>();
    UserClaims tesclass = new UserClaims(testval);

    @Test
    public void testSetClaimValues() throws Exception {

        TreeMap<String, String> testval2 = new TreeMap<>();
        tesclass.setClaimValues(testval2);
        assertEquals(tesclass.getClaimValues(), testval2);
    }

}
