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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for DefaultRefreshTokenGrantProcessor.
 */
@PrepareForTest({AuthorizationGrantCache.class, OAuth2Util.class, OAuthServerConfiguration.class})
public class DefaultRefreshTokenGrantProcessorTest extends PowerMockTestCase {

    private static final String OLD_ACCESS_TOKEN = "old-access-token";
    private static final String OLD_TOKEN_ID = "old-token-id";
    private static final String NEW_ACCESS_TOKEN = "new-access-token";
    private static final String NEW_TOKEN_ID = "new-token-id";
    private static final String JWT_TOKEN_TYPE = "JWT";
    private static final String DEFAULT_TOKEN_TYPE = "Default";
    private static final long REFRESH_TOKEN_VALIDITY_MILLIS = 86400000L;

    private final AuthorizationGrantCacheKey oldKey = new AuthorizationGrantCacheKey(OLD_ACCESS_TOKEN);
    private final AuthorizationGrantCacheKey newKey = new AuthorizationGrantCacheKey(NEW_ACCESS_TOKEN);

    private AuthorizationGrantCache mockAuthorizationGrantCache;
    private DefaultRefreshTokenGrantProcessor processor;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {

        mockStatic(AuthorizationGrantCache.class);
        mockAuthorizationGrantCache = mock(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(mockAuthorizationGrantCache);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mock(OAuthServerConfiguration.class));
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isNonPersistentTokenEnabled(anyString())).thenReturn(false);
        processor = new DefaultRefreshTokenGrantProcessor();
    }

    @Test
    public void testEntryRecoveredFromStoreOperationForFederatedUserWithJwtApp() {

        AuthorizationGrantCacheEntry storedEntry = new AuthorizationGrantCacheEntry(new HashMap<>());
        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID))).thenReturn(null);
        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID),
                eq(OAuth2Constants.STORE_OPERATION))).thenReturn(storedEntry);

        processor.addUserAttributesToCache(buildNewAccessToken(), buildMessageContext(true, JWT_TOKEN_TYPE));

        verify(mockAuthorizationGrantCache).getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID),
                eq(OAuth2Constants.STORE_OPERATION));
        verify(mockAuthorizationGrantCache).clearCacheEntryByTokenId(eq(oldKey), eq(OLD_TOKEN_ID));
        verify(mockAuthorizationGrantCache).addToCacheByToken(eq(newKey), eq(storedEntry));
        assertEquals(storedEntry.getTokenId(), NEW_TOKEN_ID);
        assertEquals(storedEntry.getValidityPeriod(), TimeUnit.MILLISECONDS.toNanos(REFRESH_TOKEN_VALIDITY_MILLIS));
    }

    @Test
    public void testRecoveredEntryKeepsAttributesForFederatedUserWithNonPersistentTokens() {

        Map<org.wso2.carbon.identity.application.common.model.ClaimMapping, String> attributes = new HashMap<>();
        attributes.put(org.wso2.carbon.identity.application.common.model.ClaimMapping.build("given_name",
                "given_name", null, false), "Fed");
        AuthorizationGrantCacheEntry storedEntry = new AuthorizationGrantCacheEntry(attributes);
        when(OAuth2Util.isNonPersistentTokenEnabled(anyString())).thenReturn(true);
        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID))).thenReturn(null);
        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID),
                eq(OAuth2Constants.STORE_OPERATION))).thenReturn(storedEntry);

        processor.addUserAttributesToCache(buildNewAccessToken(), buildMessageContext(true, JWT_TOKEN_TYPE));

        verify(mockAuthorizationGrantCache).addToCacheByToken(eq(newKey), eq(storedEntry));
        assertNotNull(storedEntry.getUserAttributes());
        assertEquals(storedEntry.getUserAttributes().size(), 1);
    }

    @Test
    public void testFallbackNotUsedWhenEntryFoundByNormalLookup() {

        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry(new HashMap<>());
        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID))).thenReturn(entry);

        processor.addUserAttributesToCache(buildNewAccessToken(), buildMessageContext(true, JWT_TOKEN_TYPE));

        verify(mockAuthorizationGrantCache, never()).getValueFromCacheByTokenId(any(AuthorizationGrantCacheKey.class),
                anyString(), anyString());
        verify(mockAuthorizationGrantCache).addToCacheByToken(eq(newKey), eq(entry));
        assertEquals(entry.getTokenId(), NEW_TOKEN_ID);
    }

    @DataProvider
    public Object[][] fallbackNotApplicableData() {

        return new Object[][]{
                {false, JWT_TOKEN_TYPE, true},
                {true, DEFAULT_TOKEN_TYPE, true},
                {true, null, true},
                {false, JWT_TOKEN_TYPE, false},
        };
    }

    @Test(dataProvider = "fallbackNotApplicableData")
    public void testFallbackNotUsedWhenNotApplicable(boolean federatedUser, String tokenType,
                                                     boolean hasAuthorizedUser) {

        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID))).thenReturn(null);
        OAuthTokenReqMessageContext msgCtx = buildMessageContext(federatedUser, tokenType);
        if (!hasAuthorizedUser) {
            msgCtx.setAuthorizedUser(null);
        }

        processor.addUserAttributesToCache(buildNewAccessToken(), msgCtx);

        verify(mockAuthorizationGrantCache, never()).getValueFromCacheByTokenId(any(AuthorizationGrantCacheKey.class),
                anyString(), anyString());
        verify(mockAuthorizationGrantCache, never()).addToCacheByToken(any(AuthorizationGrantCacheKey.class),
                any(AuthorizationGrantCacheEntry.class));
    }

    @Test
    public void testNoEntryWrittenWhenBothLookupsMiss() {

        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID))).thenReturn(null);
        when(mockAuthorizationGrantCache.getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID),
                eq(OAuth2Constants.STORE_OPERATION))).thenReturn(null);

        processor.addUserAttributesToCache(buildNewAccessToken(), buildMessageContext(true, JWT_TOKEN_TYPE));

        verify(mockAuthorizationGrantCache).getValueFromCacheByTokenId(eq(oldKey), eq(OLD_TOKEN_ID),
                eq(OAuth2Constants.STORE_OPERATION));
        verify(mockAuthorizationGrantCache, never()).clearCacheEntryByTokenId(any(AuthorizationGrantCacheKey.class),
                anyString());
        verify(mockAuthorizationGrantCache, never()).addToCacheByToken(any(AuthorizationGrantCacheKey.class),
                any(AuthorizationGrantCacheEntry.class));
    }

    @Test
    public void testNoCacheInteractionWhenPreviousAccessTokenIsNull() {

        OAuthTokenReqMessageContext msgCtx = buildMessageContext(true, JWT_TOKEN_TYPE);
        ((RefreshTokenValidationDataDO) msgCtx.getProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN))
                .setAccessToken(null);

        processor.addUserAttributesToCache(buildNewAccessToken(), msgCtx);

        verifyZeroInteractions(mockAuthorizationGrantCache);
    }

    private AccessTokenDO buildNewAccessToken() {

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken(NEW_ACCESS_TOKEN);
        accessTokenDO.setTokenId(NEW_TOKEN_ID);
        accessTokenDO.setRefreshTokenValidityPeriodInMillis(REFRESH_TOKEN_VALIDITY_MILLIS);
        accessTokenDO.setConsumerKey("test-client-id");
        AuthenticatedUser authzUser = new AuthenticatedUser();
        authzUser.setUserName("testUser");
        authzUser.setFederatedUser(true);
        accessTokenDO.setAuthzUser(authzUser);
        return accessTokenDO;
    }

    private OAuthTokenReqMessageContext buildMessageContext(boolean federatedUser, String tokenType) {

        OAuthTokenReqMessageContext msgCtx = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        RefreshTokenValidationDataDO previousToken = new RefreshTokenValidationDataDO();
        previousToken.setAccessToken(OLD_ACCESS_TOKEN);
        previousToken.setTokenId(OLD_TOKEN_ID);
        msgCtx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, previousToken);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        user.setFederatedUser(federatedUser);
        msgCtx.setAuthorizedUser(user);

        if (tokenType != null) {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setTokenType(tokenType);
            msgCtx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, oAuthAppDO);
        }
        return msgCtx;
    }
}
