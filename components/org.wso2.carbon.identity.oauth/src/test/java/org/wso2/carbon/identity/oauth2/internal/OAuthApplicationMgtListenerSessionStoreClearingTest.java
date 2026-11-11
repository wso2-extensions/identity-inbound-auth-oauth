/*
 * Copyright (c) 2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.internal;

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests that {@link OAuthApplicationMgtListener} clears the session store entries of the tokens and authorization
 * codes of an application in a single batch instead of one operation per entry.
 */
public class OAuthApplicationMgtListenerSessionStoreClearingTest {

    @Test
    public void testTokenSessionStoreEntriesClearedInBatch() throws Exception {

        AccessTokenDO token1 = new AccessTokenDO();
        token1.setAccessToken("token1");
        token1.setTokenId("tokenId1");
        AccessTokenDO token2 = new AccessTokenDO();
        token2.setAccessToken("token2");
        token2.setTokenId("tokenId2");
        AccessTokenDO tokenWithoutId = new AccessTokenDO();
        tokenWithoutId.setAccessToken("token3");

        AuthorizationGrantCache grantCache = invoke("clearCacheEntriesAgainstToken",
                new HashSet<>(Arrays.asList(token1, token2, tokenWithoutId)));

        verifyBatch(grantCache, "tokenId1", "tokenId2");
        verify(grantCache, never()).clearCacheEntryByTokenId(any(), anyString());
    }

    @Test
    public void testAuthzCodeSessionStoreEntriesClearedInBatch() throws Exception {

        AuthzCodeDO code1 = new AuthzCodeDO();
        code1.setAuthorizationCode("code1");
        code1.setAuthzCodeId("codeId1");
        AuthzCodeDO code2 = new AuthzCodeDO();
        code2.setAuthorizationCode("code2");
        code2.setAuthzCodeId("codeId2");

        AuthorizationGrantCache grantCache = invoke("clearCacheEntriesAgainstAuthzCode",
                new HashSet<>(Arrays.asList(code1, code2)));

        verifyBatch(grantCache, "codeId1", "codeId2");
        verify(grantCache, never()).clearCacheEntryByCodeId(any(), anyString());
    }

    private AuthorizationGrantCache invoke(String methodName, Set<?> entries) throws Exception {

        Method method = OAuthApplicationMgtListener.class.getDeclaredMethod(methodName, Set.class);
        method.setAccessible(true);
        AuthorizationGrantCache grantCache = mock(AuthorizationGrantCache.class);
        OAuthCache oAuthCache = mock(OAuthCache.class);
        try (MockedStatic<AuthorizationGrantCache> grantCacheStatic = mockStatic(AuthorizationGrantCache.class);
             MockedStatic<OAuthCache> oAuthCacheStatic = mockStatic(OAuthCache.class)) {
            grantCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(grantCache);
            oAuthCacheStatic.when(OAuthCache::getInstance).thenReturn(oAuthCache);
            method.invoke(new OAuthApplicationMgtListener(), entries);
        }
        return grantCache;
    }

    @SuppressWarnings("unchecked")
    private void verifyBatch(AuthorizationGrantCache grantCache, String... expectedIds) {

        org.mockito.ArgumentCaptor<List<String>> captor = org.mockito.ArgumentCaptor.forClass(List.class);
        verify(grantCache, times(1)).clearFromSessionStoreBatch(captor.capture());
        // The session store must be cleared before the cache, so a cache miss cannot reload a stale entry.
        org.mockito.InOrder inOrder = org.mockito.Mockito.inOrder(grantCache);
        inOrder.verify(grantCache).clearFromSessionStoreBatch(any());
        inOrder.verify(grantCache, org.mockito.Mockito.atLeastOnce()).clearCacheEntry(any());
        List<String> ids = captor.getValue();
        org.testng.Assert.assertEquals(new HashSet<>(ids), new HashSet<>(Arrays.asList(expectedIds)));
        org.testng.Assert.assertEquals(ids.size(), expectedIds.length);
    }
}
