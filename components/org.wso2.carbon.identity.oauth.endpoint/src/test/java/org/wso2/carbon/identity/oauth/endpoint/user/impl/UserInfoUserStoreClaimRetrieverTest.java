/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertNotNull;

public class UserInfoUserStoreClaimRetrieverTest {

    @DataProvider
    public Object[][] getUserAttributes() {

        ClaimMapping map1 = ClaimMapping.build("localClaimUri1", "remoteClaimUri1", "defaultValue1", true);
        ClaimMapping map2 = ClaimMapping.build("localClaimUri2", "remoteClaimUri2", "defaultValue1", true);
        Map<ClaimMapping, Object> claims1 = new HashMap<ClaimMapping, Object>();
        Map<ClaimMapping, Object> claims2 = new HashMap<ClaimMapping, Object>();
        claims1.put(map1, "User1");
        claims2.put(map2, "User1, User2");
        return new Object[][] {
                {claims1},
                {claims2}
        };
    }

    @Test(dataProvider = "getUserAttributes")
    public void testUserInfoUserStoreClaimRetriever(HashMap<ClaimMapping, String> claims) {

        UserInfoUserStoreClaimRetriever claimsRetriever = new UserInfoUserStoreClaimRetriever();
        assertNotNull(claimsRetriever.getClaimsMap(claims));
    }
}
