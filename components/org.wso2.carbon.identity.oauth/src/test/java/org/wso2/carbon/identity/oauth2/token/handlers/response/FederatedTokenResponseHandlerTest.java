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

package org.wso2.carbon.identity.oauth2.token.handlers.response;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.FederatedTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class FederatedTokenResponseHandlerTest {

    private static final String CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    private static final String AUTH_REQ_ID = "auth_req_id";
    private static final String TEST_AUTH_CODE = "test-auth-code";
    private static final String TEST_AUTH_REQ_ID = "test-auth-req-id";

    @Test
    public void testGetFederatedTokensWithAuthorizationCode() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(TEST_AUTH_CODE);

        List<FederatedTokenDO> federatedTokens = new ArrayList<>();
        federatedTokens.add(new FederatedTokenDO("testIdp", "test-access-token"));

        AuthorizationGrantCacheEntry cacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(cacheEntry.getFederatedTokens()).thenReturn(federatedTokens);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);

            Assert.assertNotNull(result);
            Assert.assertTrue(result.containsKey(FrameworkConstants.FEDERATED_TOKENS));
            List<FederatedTokenDO> returnedTokens =
                    (List<FederatedTokenDO>) result.get(FrameworkConstants.FEDERATED_TOKENS);
            Assert.assertEquals(returnedTokens.size(), 1);
            Assert.assertEquals(returnedTokens.get(0).getIdp(), "testIdp");
        }
    }

    @Test
    public void testGetFederatedTokensWithCibaGrant() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(null);
        when(reqDTO.getGrantType()).thenReturn(CIBA_GRANT_TYPE);

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter(AUTH_REQ_ID, new String[]{TEST_AUTH_REQ_ID})
        };
        when(reqDTO.getRequestParameters()).thenReturn(parameters);

        List<FederatedTokenDO> federatedTokens = new ArrayList<>();
        federatedTokens.add(new FederatedTokenDO("federatedIdp", "federated-access-token"));

        AuthorizationGrantCacheEntry cacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(cacheEntry.getFederatedTokens()).thenReturn(federatedTokens);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);

            Assert.assertNotNull(result);
            Assert.assertTrue(result.containsKey(FrameworkConstants.FEDERATED_TOKENS));
            List<FederatedTokenDO> returnedTokens =
                    (List<FederatedTokenDO>) result.get(FrameworkConstants.FEDERATED_TOKENS);
            Assert.assertEquals(returnedTokens.size(), 1);
            Assert.assertEquals(returnedTokens.get(0).getIdp(), "federatedIdp");
        }
    }

    @Test
    public void testReturnsNullWhenNoAuthCodeAndNotCibaGrant() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(null);
        when(reqDTO.getGrantType()).thenReturn("client_credentials");

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenCibaGrantButNoAuthReqId() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(null);
        when(reqDTO.getGrantType()).thenReturn(CIBA_GRANT_TYPE);

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter("other_param", new String[]{"value"})
        };
        when(reqDTO.getRequestParameters()).thenReturn(parameters);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenCibaGrantWithNullRequestParameters() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(null);
        when(reqDTO.getGrantType()).thenReturn(CIBA_GRANT_TYPE);
        when(reqDTO.getRequestParameters()).thenReturn(null);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenCacheEntryIsNull() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(TEST_AUTH_CODE);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(null);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenFederatedTokensAreEmpty() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(TEST_AUTH_CODE);

        AuthorizationGrantCacheEntry cacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(cacheEntry.getFederatedTokens()).thenReturn(Collections.emptyList());

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenFederatedTokensAreNull() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(TEST_AUTH_CODE);

        AuthorizationGrantCacheEntry cacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(cacheEntry.getFederatedTokens()).thenReturn(null);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenCibaGrantWithAuthReqIdHavingNullValue() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(null);
        when(reqDTO.getGrantType()).thenReturn(CIBA_GRANT_TYPE);

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter(AUTH_REQ_ID, (String[]) null)
        };
        when(reqDTO.getRequestParameters()).thenReturn(parameters);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testReturnsNullWhenCibaGrantWithAuthReqIdHavingEmptyValue() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        when(reqDTO.getAuthorizationCode()).thenReturn(null);
        when(reqDTO.getGrantType()).thenReturn(CIBA_GRANT_TYPE);

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter(AUTH_REQ_ID, new String[]{})
        };
        when(reqDTO.getRequestParameters()).thenReturn(parameters);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            Assert.assertNull(result);
        }
    }

    @Test
    public void testAuthCodeTakesPrecedenceOverCibaGrant() {

        FederatedTokenResponseHandler handler = new FederatedTokenResponseHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO reqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(reqDTO);
        // When both authorization code and CIBA grant type are present, auth code path should be used.
        when(reqDTO.getAuthorizationCode()).thenReturn(TEST_AUTH_CODE);

        List<FederatedTokenDO> federatedTokens = new ArrayList<>();
        federatedTokens.add(new FederatedTokenDO("authCodeIdp", "auth-code-token"));

        AuthorizationGrantCacheEntry cacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(cacheEntry.getFederatedTokens()).thenReturn(federatedTokens);

        try (MockedStatic<AuthorizationGrantCache> cacheMockedStatic = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache cache = mock(AuthorizationGrantCache.class);
            cacheMockedStatic.when(AuthorizationGrantCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Map<String, Object> result = handler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);

            Assert.assertNotNull(result);
            List<FederatedTokenDO> returnedTokens =
                    (List<FederatedTokenDO>) result.get(FrameworkConstants.FEDERATED_TOKENS);
            Assert.assertEquals(returnedTokens.get(0).getIdp(), "authCodeIdp");
        }
    }
}
