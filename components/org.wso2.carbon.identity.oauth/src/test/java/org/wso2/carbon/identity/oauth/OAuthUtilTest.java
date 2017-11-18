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

package org.wso2.carbon.identity.oauth;

import org.apache.commons.lang.StringUtils;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;

import java.nio.file.Paths;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for OAuthUtil class.
 */
@WithCarbonHome
@WithRealmService
public class OAuthUtilTest {

    @DataProvider(name = "testGetAuthenticatedUser")
    public Object[][] fullQualifiedUserName() {
        return new Object[][] { { "JDBC/siripala@is.com", "siripala" }, { "JDBC/siripala", "siripala" },
                { "siripala@is.com", "siripala" }, { "siripala", "siripala" } };
    }

    @DataProvider(name = "testClearOAuthCache")
    public Object[][] isUserStoreCaseSensitive() {
        return new Object[][] { { true }, { false } };
    }

    @Test
    public void testGetRandomNumber() throws Exception {
        assertTrue(StringUtils.isNotBlank(OAuthUtil.getRandomNumber()), "Generated random string should not be blank.");
    }

    @Test
    public void testClearOAuthCache() throws Exception {

        String cacheKey = "some-cache-key";
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(cacheKey);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(cacheKey);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear();
    }

    @Test(dataProvider = "testClearOAuthCache")
    public void testClearOAuthCacheKeyUser(boolean isUserStoreCaseSensitive) throws Exception {

        String consumerKey = "consumer-key";
        String authorizedUser = "authorized-user";
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(consumerKey + ":" + authorizedUser);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(consumerKey, authorizedUser);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear();
    }

    @Test
    public void testClearOAuthCacheKeyUserclass() throws Exception {

        String consumerKey = "consumer-key";
        User authorizedUser = new User();
        authorizedUser.setUserName("siripala");
        authorizedUser.setTenantDomain("is.com");
        authorizedUser.setUserStoreDomain("JDBC");

        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(consumerKey + ":" + authorizedUser.toString());
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(consumerKey, authorizedUser);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear();
    }

    @Test(dataProvider = "testClearOAuthCache")
    public void testClearOAuthCacheKeyUserScope(boolean isUserStoreCaseSensitive) throws Exception {

        String consumerKey = "consumer-key";
        String authorizedUser = "authorized-user";
        String scope = "scope";
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(consumerKey + ":" + authorizedUser + ":" + scope);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(consumerKey, authorizedUser, scope);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear();
    }

    @Test
    public void testClearOAuthCacheKeyUserclassScope() throws Exception {

        String consumerKey = "consumer-key";
        User authorizedUser = new User();
        authorizedUser.setUserName("siripala");
        authorizedUser.setTenantDomain("is.com");
        authorizedUser.setUserStoreDomain("JDBC");
        String scope = "scope";
        OAuthCacheKey oAuthCacheKey = new OAuthCacheKey(consumerKey + ":" + authorizedUser.toString() + ":" + scope);
        OAuthCache oAuthCache = getOAuthCache(oAuthCacheKey);

        assertNotNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should give the cached value before cleaning it.");
        OAuthUtil.clearOAuthCache(consumerKey, authorizedUser, scope);
        assertNull(oAuthCache.getValueFromCache(oAuthCacheKey), "Should clear the cached value against the cache key.");

        // Clear all the cached values to make sure no side effect on other tests.
        oAuthCache.clear();
    }

    @Test(dataProvider = "testGetAuthenticatedUser")
    public void testGetAuthenticatedUser(String fullQualifiedName, String username) throws Exception {
        assertEquals(OAuthUtil.getAuthenticatedUser(fullQualifiedName).getUserName(), username,
                "Should set the " + "cleared username from fullyQualifiedName.");
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGetAuthenticatedUserException() throws Exception {
        OAuthUtil.getAuthenticatedUser("");
    }

    private OAuthCache getOAuthCache(OAuthCacheKey oAuthCacheKey) {

        // Set carbon home.
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);

        // Add some value to OAuthCache.
        DummyOAuthCacheEntry dummyOAuthCacheEntry = new DummyOAuthCacheEntry("identifier");
        OAuthCache oAuthCache = OAuthCache.getInstance();
        oAuthCache.addToCache(oAuthCacheKey, dummyOAuthCacheEntry);
        return oAuthCache;
    }

    private static class DummyOAuthCacheEntry extends CacheEntry {

        private String identifier;

        DummyOAuthCacheEntry(String identifier) {
            this.identifier = identifier;
        }

        public String getIdentifier() {
            return identifier;
        }
    }
}
