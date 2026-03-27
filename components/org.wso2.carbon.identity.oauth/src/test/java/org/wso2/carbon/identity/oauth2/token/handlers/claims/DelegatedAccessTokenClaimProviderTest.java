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

package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.DELEGATING_ACTOR;

/**
 * Unit tests for {@link DelegatedAccessTokenClaimProvider}.
 */
public class DelegatedAccessTokenClaimProviderTest {

    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private static final String ACT = "act";
    private static final String SUB = "sub";

    @BeforeMethod
    public void init() {

        tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
    }

    @DataProvider(name = "delegationClaimsDataProvider")
    public Object[][] delegationClaimsDataProvider() {

        return new Object[][]{
                // isDelegationRequest, delegatingActor, expectActClaim
                {true, "delegating-actor-id", true},
                {true, null, false},
                {true, "", false},
                {true, "   ", false},
                {false, "delegating-actor-id", false},
        };
    }

    @Test(dataProvider = "delegationClaimsDataProvider")
    public void testGetAdditionalClaimsForTokenContext(boolean isDelegationRequest, String delegatingActor,
                                                       boolean expectActClaim) throws Exception {

        when(tokReqMsgCtx.isDelegationRequest()).thenReturn(isDelegationRequest);
        when(tokReqMsgCtx.getProperty(DELEGATING_ACTOR)).thenReturn(delegatingActor);

        JWTAccessTokenClaimProvider claimProvider = new DelegatedAccessTokenClaimProvider();
        Map<String, Object> claims = claimProvider.getAdditionalClaims(tokReqMsgCtx);

        if (expectActClaim) {
            assertTrue(claims.containsKey(ACT), "Expected 'act' claim to be present");
            Map<String, Object> actClaim = (Map<String, Object>) claims.get(ACT);
            assertEquals(actClaim.get(SUB), delegatingActor,
                    "Expected 'act.sub' to match the delegating actor identifier");
        } else {
            assertNull(claims, "Expected null claims for non-delegation request or blank actor");
        }
    }

    @Test
    public void testGetAdditionalClaimsForAuthzContextReturnsNull() throws Exception {

        OAuthAuthzReqMessageContext authzContext = mock(OAuthAuthzReqMessageContext.class);
        JWTAccessTokenClaimProvider claimProvider = new DelegatedAccessTokenClaimProvider();
        Map<String, Object> claims = claimProvider.getAdditionalClaims(authzContext);
        assertNull(claims, "Authz context should always return null for delegation claim provider");
    }
}
