/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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
 *
 */

package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class ImpersonatedAccessTokenClaimProviderTest {

    private OAuthTokenReqMessageContext tokReqMsgCtx;
    public static final String IMPERSONATING_ACTOR = "IMPERSONATING_ACTOR";
    private static final String ACT = "act";
    private static final String SUB = "sub";

    @BeforeMethod
    public void init() {

        tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
    }

    @DataProvider(name = "GetAdditionalClaimsDataProvider")
    public Object[][] getAdditionalClaimsDataProvider() {

        Map<String, Object> validActorMap = new HashMap<>();
        validActorMap.put(ACT, Collections.singletonMap(SUB, IMPERSONATING_ACTOR));
        return new Object[][]{
                {true, IMPERSONATING_ACTOR, validActorMap},
                {true, null, null},
                {true, "", null},
                {true, " ", null},
                {false, IMPERSONATING_ACTOR, null},
        };
    }

    @Test(dataProvider = "GetAdditionalClaimsDataProvider")
    public void testGetAdditionalClaimsData(boolean isImpersonationRequest, String impersonator,
                                            Map<String, Object> claimMapping)
            throws Exception {

        JWTAccessTokenClaimProvider claimProvider = new ImpersonatedAccessTokenClaimProvider();
        when(tokReqMsgCtx.isImpersonationRequest()).thenReturn(isImpersonationRequest);
        when(tokReqMsgCtx.getProperty(IMPERSONATING_ACTOR)).thenReturn(impersonator);

        Map<String, Object> actorMap;
        actorMap = claimProvider.getAdditionalClaims(tokReqMsgCtx);

        if (claimMapping != null) {

            assertTrue(actorMap.containsKey(ACT), "Expected 'act' claim in the claim mapping");
            assertEquals(IMPERSONATING_ACTOR, ((Map<String, Object>) actorMap.get(ACT)).get(SUB),
                    "Expected 'act' claim in the claim mapping has 'sub' claim.");
        } else {
            assertNull(actorMap, " Expected Null mapping but retrieved non null object.");
        }
    }
}
