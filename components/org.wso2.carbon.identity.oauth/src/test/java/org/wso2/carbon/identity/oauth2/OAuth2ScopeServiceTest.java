/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.powermock.reflect.Whitebox;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCacheKey;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.HashMap;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithH2Database(files = { "dbScripts/scope.sql" })
public class OAuth2ScopeServiceTest extends PowerMockIdentityBaseTest {

    private OAuth2ScopeService oAuth2ScopeService;
    private static final String SCOPE_NAME = "dummyScopeName";
    private static final String SCOPE_DESCRIPTION = "dummyScopeDescription";

    @DataProvider(name = "indexAndCountProvider")
    public static Object[][] indexAndCountProvider() {
        return new Object[][]{
                {null, 1},
                {1, null},
                {1, 2}};
    }

    @BeforeMethod
    public void setUp() throws Exception {
        oAuth2ScopeService = new OAuth2ScopeService();
        IdentityUtil.populateProperties();
    }

    @AfterMethod
    public void tearDown() throws Exception {
        Whitebox.setInternalState(IdentityUtil.class, "configuration", new HashMap<>());
        Whitebox.setInternalState(IdentityUtil.class, "eventListenerConfiguration", new HashMap<>());
        Whitebox.setInternalState(IdentityUtil.class, "identityCacheConfigurationHolder", new HashMap<>());
        Whitebox.setInternalState(IdentityUtil.class, "identityCookiesConfigurationHolder", new HashMap<>());
    }

    @Test
    public void testRegisterScope() throws Exception {

        Scope dummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, SCOPE_DESCRIPTION);
        Scope scope = oAuth2ScopeService.registerScope(dummyScope);
        assertEquals(scope.getName(), SCOPE_NAME, "Expected name did not received");
        assertEquals(scope.getDescription(), SCOPE_DESCRIPTION, "Expected description did not received");
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testRegisterScopeWithNoScopeName() throws Exception {
        String name = "";
        String description = "dummyScopeDescription";
        Scope scope = new Scope(name, name, description);
        oAuth2ScopeService.registerScope(scope);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testRegisterScopeWithNoDisplayName() throws Exception {
        String name = "dummyScopeName";
        String displayName = "";
        String description = "";
        Scope scope = new Scope(name, displayName, description);
        oAuth2ScopeService.registerScope(scope);
    }

    @Test
    public void testGetScopes() throws Exception {
        assertNotNull(oAuth2ScopeService.getScopes(null, null), "Expected a not null object");
    }

    @Test(dataProvider = "indexAndCountProvider")
    public void testGetScopesWithStartAndCount(Integer startIndex, Integer count) throws Exception {
        assertNotNull(oAuth2ScopeService.getScopes(startIndex, count), "Expected a not null object");
    }

    @DataProvider(name = "ProvideCacheConfigurations")
    public static Object[][] provideCacheConfigurations() {
        return new Object[][]{
                {false},
                {true}
        };
    }

    @Test(dataProvider = "ProvideCacheConfigurations")
    public void testGetScope(boolean existWithinCache) throws Exception {
        Scope dummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, SCOPE_DESCRIPTION);
        oAuth2ScopeService.registerScope(dummyScope);
        if (!existWithinCache) {
            OAuthScopeCache.getInstance().clearCacheEntry(new OAuthScopeCacheKey(SCOPE_NAME, Integer.toString(
                    Oauth2ScopeUtils.getTenantID())));
        }
        assertEquals(oAuth2ScopeService.getScope(SCOPE_NAME).getName(), SCOPE_NAME, "Retrieving registered scope is " +
                "failed");
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
    }

    @Test
    public void testUpdateScope() throws Exception {
        Scope dummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, SCOPE_DESCRIPTION);
        oAuth2ScopeService.registerScope(dummyScope);
        Scope updatedDummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, StringUtils.EMPTY);
        assertEquals(oAuth2ScopeService.updateScope(updatedDummyScope).getDescription(), StringUtils.EMPTY);
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeException.class)
    public void testUpdateScopeWithExceptions() throws Exception {
        Scope updatedDummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, StringUtils.EMPTY);
        oAuth2ScopeService.updateScope(updatedDummyScope);
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeException.class)
    public void testDeleteScope() throws Exception {
        Scope dummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, SCOPE_DESCRIPTION);
        oAuth2ScopeService.registerScope(dummyScope);
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
        oAuth2ScopeService.getScope(SCOPE_NAME);
    }
}
