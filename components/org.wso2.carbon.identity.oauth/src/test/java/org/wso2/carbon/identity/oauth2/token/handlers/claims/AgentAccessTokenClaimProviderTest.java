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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@Listeners(MockitoTestNGListener.class)
public class AgentAccessTokenClaimProviderTest {

    private static final String AGENT_STORE = "AGENT_STORE";
    private static final String PRIMARY_STORE = "PRIMARY";
    private static final String CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    private static final String ACT = "act";
    private static final String AUT = "aut";
    private static final String SUB = "sub";
    private static final String AGENT = "AGENT";

    @Mock
    private OAuthTokenReqMessageContext mockTokenReqCtx;

    @Mock
    private OAuth2AccessTokenReqDTO mockTokenReqDTO;

    @Mock
    private AuthenticatedUser mockAuthorizedUser;

    @Mock
    private OAuthAuthzReqMessageContext mockAuthzReqCtx;

    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private AgentAccessTokenClaimProvider provider;

    @BeforeMethod
    public void setUp() {

        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        provider = new AgentAccessTokenClaimProvider();
        // Lenient: tests that use authzReqCtx path don't call these on the token request context
        lenient().when(mockTokenReqCtx.getOauth2AccessTokenReqDTO()).thenReturn(mockTokenReqDTO);
        lenient().when(mockTokenReqCtx.getAuthorizedUser()).thenReturn(mockAuthorizedUser);
    }

    @AfterMethod
    public void tearDown() {

        if (mockedIdentityUtil != null) {
            mockedIdentityUtil.close();
        }
    }

    @Test
    public void testGetAdditionalClaims_authzContext_alwaysReturnsNull() throws Exception {

        Map<String, Object> result = provider.getAdditionalClaims(mockAuthzReqCtx);

        Assert.assertNull(result);
    }

    @Test
    public void testGetAdditionalClaims_agentUserStoreDomainMatchesExactly_returnsAutClaim() throws Exception {

        mockedIdentityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(AGENT_STORE);
        when(mockAuthorizedUser.getUserStoreDomain()).thenReturn(AGENT_STORE);

        Map<String, Object> result = provider.getAdditionalClaims(mockTokenReqCtx);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.get(AUT), AGENT);
        Assert.assertFalse(result.containsKey(ACT));
    }

    @Test
    public void testGetAdditionalClaims_agentUserStoreDomainMatchesCaseInsensitive_returnsAutClaim() throws Exception {

        mockedIdentityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(AGENT_STORE);
        when(mockAuthorizedUser.getUserStoreDomain()).thenReturn("agent_store");

        Map<String, Object> result = provider.getAdditionalClaims(mockTokenReqCtx);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.get(AUT), AGENT);
    }

    @DataProvider(name = "grantTypeAndActorProvider")
    public Object[][] grantTypeAndActorProvider() {

        return new Object[][]{
                // {grantType, requestedActor, expectActClaim}
                {GrantType.AUTHORIZATION_CODE.toString(), "actor-sub", true},
                {CIBA_GRANT_TYPE, "actor-sub", true},
                {GrantType.AUTHORIZATION_CODE.toString(), null, false},
                {"password", "actor-sub", false},
                {"client_credentials", "actor-sub", false},
        };
    }

    @Test(dataProvider = "grantTypeAndActorProvider")
    public void testGetAdditionalClaims_grantTypeAndActor(
            String grantType, String requestedActor, boolean expectActClaim) throws Exception {

        mockedIdentityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(AGENT_STORE);
        when(mockAuthorizedUser.getUserStoreDomain()).thenReturn(PRIMARY_STORE);
        when(mockTokenReqDTO.getGrantType()).thenReturn(grantType);
        // Lenient: non-eligible grant types short-circuit before getRequestedActor() is called
        lenient().when(mockTokenReqCtx.getRequestedActor()).thenReturn(requestedActor);

        Map<String, Object> result = provider.getAdditionalClaims(mockTokenReqCtx);

        if (expectActClaim) {
            Assert.assertNotNull(result);
            @SuppressWarnings("unchecked")
            Map<String, String> actClaim = (Map<String, String>) result.get(ACT);
            Assert.assertNotNull(actClaim);
            Assert.assertEquals(actClaim.get(SUB), requestedActor);
            Assert.assertFalse(result.containsKey(AUT));
        } else {
            Assert.assertNull(result);
        }
    }

    @Test
    public void testGetAdditionalClaims_nullAgentStoreName_cibaGrantWithActor_returnsActClaim() throws Exception {

        mockedIdentityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn(null);
        // agentStoreName is null → StringUtils.isNotEmpty() = false → getUserStoreDomain() never called
        when(mockTokenReqDTO.getGrantType()).thenReturn(CIBA_GRANT_TYPE);
        when(mockTokenReqCtx.getRequestedActor()).thenReturn("actor-x");

        Map<String, Object> result = provider.getAdditionalClaims(mockTokenReqCtx);

        Assert.assertNotNull(result);
        @SuppressWarnings("unchecked")
        Map<String, String> actClaim = (Map<String, String>) result.get(ACT);
        Assert.assertNotNull(actClaim);
        Assert.assertEquals(actClaim.get(SUB), "actor-x");
    }

    @Test
    public void testGetAdditionalClaims_emptyAgentStoreName_noActorOrAgentClaim_returnsNull() throws Exception {

        mockedIdentityUtil.when(IdentityUtil::getAgentIdentityUserstoreName).thenReturn("");
        // agentStoreName is empty → StringUtils.isNotEmpty() = false → getUserStoreDomain() never called
        // grantType irrelevant since no actor claim path is taken either
        when(mockTokenReqDTO.getGrantType()).thenReturn("password");

        Map<String, Object> result = provider.getAdditionalClaims(mockTokenReqCtx);

        Assert.assertNull(result);
    }
}
