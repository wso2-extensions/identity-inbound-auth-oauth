/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class AgentAccessTokenClaimProviderTest {

    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private static final String AGENT_USERSTORE = "AGENT_STORE";
    private static final String AGENT = "AGENT";
    private static final String AUT = "aut";
    private static final String ACT = "act";
    private static final String SUB = "sub";
    private static final String REQUESTED_ACTOR = "requested-actor";

    @BeforeMethod
    public void setUp() {

        tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
    }

    @Test
    public void testGetAdditionalClaims_AgentUserStore() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(AGENT_USERSTORE);
            when(tokReqMsgCtx.getAuthorizedUser())
                    .thenReturn(mock(org.wso2.carbon.identity.application.authentication.framework.model
                            .AuthenticatedUser.class));
            when(tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain()).thenReturn(AGENT_USERSTORE);

            AgentAccessTokenClaimProvider provider = new AgentAccessTokenClaimProvider();
            Map<String, Object> claims = provider.getAdditionalClaims(tokReqMsgCtx);

            assertNotNull(claims);
            assertEquals(claims.get(AUT), AGENT);
        }
    }

    @Test
    public void testGetAdditionalClaims_AuthorizationCodeGrantWithRequestedActor() throws Exception {

        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(mock(org.wso2.carbon.identity.oauth2.dto
                .OAuth2AccessTokenReqDTO.class));
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType()).thenReturn("authorization_code");
        when(tokReqMsgCtx.getRequestedActor()).thenReturn(REQUESTED_ACTOR);

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn("AGENT_USER_STORE");
            when(tokReqMsgCtx.getAuthorizedUser()).thenReturn(mock(org.wso2.carbon.identity.application.authentication
                    .framework.model.AuthenticatedUser.class));
            when(tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain()).thenReturn("PRIMARY_USER_STORE");

            AgentAccessTokenClaimProvider provider = new AgentAccessTokenClaimProvider();
            Map<String, Object> claims = provider.getAdditionalClaims(tokReqMsgCtx);

            assertNotNull(claims);
            assertTrue(claims.containsKey(ACT));
            Map<String, Object> actMap = (Map<String, Object>) claims.get(ACT);
            assertEquals(actMap.get(SUB), REQUESTED_ACTOR);
            assertEquals(actMap.get(AUT), AGENT);
        }
    }

    @Test
    public void testGetAdditionalClaims_NoAgentClaims() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn("AGENT_USER_STORE");
            when(tokReqMsgCtx.getAuthorizedUser()).thenReturn(mock(org.wso2.carbon.identity.application.authentication
                    .framework.model.AuthenticatedUser.class));
            when(tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain()).thenReturn("PRIMARY_USER_STORE");
            when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(mock(org.wso2.carbon.identity.oauth2
                    .dto.OAuth2AccessTokenReqDTO.class));
            when(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType()).thenReturn("password");
            when(tokReqMsgCtx.getRequestedActor()).thenReturn(null);

            AgentAccessTokenClaimProvider provider = new AgentAccessTokenClaimProvider();
            Map<String, Object> claims = provider.getAdditionalClaims(tokReqMsgCtx);

            assertNull(claims);
        }
    }

    @Test
    public void testGetAdditionalClaims_AuthzReqContext() throws Exception {

        AgentAccessTokenClaimProvider provider = new AgentAccessTokenClaimProvider();
        OAuthAuthzReqMessageContext authzCtx = mock(OAuthAuthzReqMessageContext.class);
        assertNull(provider.getAdditionalClaims(authzCtx));
    }
}
