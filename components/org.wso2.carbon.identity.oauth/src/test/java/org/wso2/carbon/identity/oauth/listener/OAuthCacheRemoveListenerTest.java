/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.listener;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import javax.cache.Cache;
import javax.cache.event.CacheEntryEvent;
import java.sql.Timestamp;
import java.util.Calendar;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({IdentityUtil.class, OAuthServerConfiguration.class, OAuthCache.class})
public class OAuthCacheRemoveListenerTest extends PowerMockTestCase {

    @Mock
    private OAuthServerConfiguration oauthServerConfigurationMock;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        mockStatic(IdentityUtil.class);
        mockStatic(OAuthServerConfiguration.class);
        mockStatic(OAuthCache.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(3600L);
    }

    @DataProvider(name = "provideParams")
    public Object[][] providePostParams() {
        Cache cache = mock(Cache.class);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("USER_NAME");
        String[] scope = {"PROFILE", "OPEN_ID"};
        Timestamp issuedTime = new Timestamp(Calendar.getInstance().getTimeInMillis());
        Timestamp refreshTime = new Timestamp(3600);
        long validity = 10000;
        long refreshTokenVaidity = 10500;
        final AccessTokenDO tokenDO = new AccessTokenDO("CONSUMER_KEY", authenticatedUser, scope,
                issuedTime, refreshTime, validity, refreshTokenVaidity, "CODE");

        CacheEntryEvent<? extends OAuthCacheKey, ? extends CacheEntry> cacheEntryEventQualified =
                new CacheEntryEvent<OAuthCacheKey, CacheEntry>(cache) {
                    OAuthCacheKey cacheKey = new OAuthCacheKey("CACHE_KEY");

                    CacheEntry cacheEntry = tokenDO;

                    @Override
                    public OAuthCacheKey getKey() {
                        return cacheKey;
                    }

                    @Override
                    public CacheEntry getValue() {
                        return cacheEntry;
                    }
                };

        CacheEntryEvent<? extends OAuthCacheKey, ? extends CacheEntry> cacheEntryEventNullInstance =
                new CacheEntryEvent<OAuthCacheKey, CacheEntry>(cache) {
                    OAuthCacheKey cacheKey = new OAuthCacheKey("CACHE_KEY");

                    @Override
                    public OAuthCacheKey getKey() {
                        return cacheKey;
                    }

                    @Override
                    public CacheEntry getValue() {
                        return null;
                    }
                };

        return new Object[][]{
                {cacheEntryEventNullInstance, false},
                {cacheEntryEventQualified, true},
                {cacheEntryEventQualified, false}
        };
    }

    @Test(dataProvider = "provideParams")
    public void testEntryRemoved(Object cacheEntryObject, Boolean sensitivity) throws Exception {
        OAuthCache mockedOAuthCache = mock(OAuthCache.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(sensitivity);
        when(OAuthCache.getInstance()).thenReturn(mockedOAuthCache);

        OAuthCacheRemoveListener listener = new OAuthCacheRemoveListener();
        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        listener.entryRemoved((CacheEntryEvent<? extends OAuthCacheKey, ? extends CacheEntry>) cacheEntryObject);

        if (((CacheEntryEvent<? extends OAuthCacheKey, ? extends CacheEntry>) cacheEntryObject).getValue() != null) {
            PowerMockito.verifyStatic();
            IdentityUtil.isUserStoreInUsernameCaseSensitive(argumentCaptor.capture());
            assertEquals(argumentCaptor.getValue(), "USER_NAME");
        }
    }

}
