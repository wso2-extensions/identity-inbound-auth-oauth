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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.IdentityCacheConfig;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCacheKey;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.ScopeMgtDAO;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Field;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({IdentityUtil.class, IdentityDatabaseUtil.class, OAuth2ScopeService.class, ScopeMgtDAO.class,
        OAuthScopeCache.class})
public class OAuth2ScopeServiceTest extends PowerMockIdentityBaseTest {

    @Mock
    private Scope mockedScope;

    @Mock
    private IdentityCacheConfig mockedIdentityCacheConfig;

    @Mock
    private ScopeMgtDAO mockedScopeMgtDAO;

    @Mock
    private Set<Scope> mockedScopeSet;

    @Mock
    private OAuthScopeCache mockedOAuthScopeCache;

    @InjectMocks
    private OAuth2ScopeService oAuth2ScopeService;

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
        CommonTestUtils.initPrivilegedCarbonContext();

        Field field = OAuth2ScopeService.class.getDeclaredField("scopeMgtDAO");
        field.setAccessible(true);
        field.set(oAuth2ScopeService, mockedScopeMgtDAO);
        field.setAccessible(false);
    }

    @Test
    public void testRegisterScope() throws Exception {
        String name = "dummyScopeName";
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(mockedIdentityCacheConfig);
        when(mockedScopeMgtDAO.isScopeExists(anyString(), anyInt())).thenReturn(false);

        Scope scope = oAuth2ScopeService.registerScope(mockedScope);
        assertEquals(scope.getName(), "dummyScopeName", "Expected name did not received");
        assertEquals(scope.getDescription(), "dummyScopeDescription", "Expected description did not received");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testRegisterScopeWithNoScopeName() throws Exception {
        String name = "";
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        oAuth2ScopeService.registerScope(mockedScope);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testRegisterScopeWithNoScopeDescription() throws Exception {
        String name = "dummyScopeName";
        String description = "";
        mockedScope = new Scope(name, description);

        oAuth2ScopeService.registerScope(mockedScope);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testRegisterScopeWithScopeExists() throws Exception {
        String name = "dummyScopeName";
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(mockedIdentityCacheConfig);
        when(mockedScopeMgtDAO.isScopeExists(anyString(), anyInt())).thenReturn(true);

        oAuth2ScopeService.registerScope(mockedScope);
    }

    @Test
    public void testGetScopes() throws Exception {
        when(mockedScopeMgtDAO.getAllScopes(anyInt())).thenReturn(mockedScopeSet);

        assertNotNull(oAuth2ScopeService.getScopes(null, null), "Expected a not null object");
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testGetScopesWithIdentityException() throws Exception {
        when(mockedScopeMgtDAO.getAllScopes(anyInt())).thenThrow(new IdentityOAuth2ScopeServerException(anyString()));

        oAuth2ScopeService.getScopes(null, null);
    }

    @Test(dataProvider = "indexAndCountProvider")
    public void testGetScopesWithStartAndCount(Integer startIndex, Integer count) throws Exception {
        assertNotNull(oAuth2ScopeService.getScopes(startIndex, count), "Expected a not null object");
    }

    @Test(dataProvider = "indexAndCountProvider", expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testGetScopesWithScopeServerException(Integer startIndex, Integer count) throws Exception {
        when(mockedScopeMgtDAO.getScopesWithPagination(anyInt(), anyInt(), anyInt())).thenThrow(new
                IdentityOAuth2ScopeServerException("dummyIdentityOAuth2ScopeServerException"));

        oAuth2ScopeService.getScopes(startIndex, count);
    }

    @Test(dataProvider = "indexAndCountProvider", expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testGetScopesWithScopeServerExceptionConstruct2(Integer startIndex, Integer count) throws Exception {
        when(mockedScopeMgtDAO.getScopesWithPagination(anyInt(), anyInt(), anyInt())).thenThrow(new
                IdentityOAuth2ScopeServerException("dummyIdentityOAuth2ScopeServerException", "Generated for testing " +
                "purpose"));

        oAuth2ScopeService.getScopes(startIndex, count);
    }

    @Test(dataProvider = "indexAndCountProvider", expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testGetScopesWithScopeServerExceptionConstruct3(Integer startIndex, Integer count) throws Exception {
        Throwable throwable = new Throwable();
        when(mockedScopeMgtDAO.getScopesWithPagination(anyInt(), anyInt(), anyInt())).thenThrow(new
                IdentityOAuth2ScopeServerException("dummyIdentityOAuth2ScopeServerException", throwable));

        oAuth2ScopeService.getScopes(startIndex, count);
    }

    @Test
    public void testGetScope() throws Exception {
        String name = "dummyName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(mockedScope);

        assertNotNull(oAuth2ScopeService.getScope(name), "Expected a not null object");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testGetScopeWithNoName() throws Exception {
        oAuth2ScopeService.getScope("");
    }

    @Test
    public void testGetScopeWithNullScope() throws Exception {
        String name = "dummyName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(null);
        when(mockedScopeMgtDAO.getScopeByName(anyString(), anyInt())).thenReturn(mockedScope);
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);

        assertNotNull(oAuth2ScopeService.getScope(name), "Expected a not null object");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testGetScopeWithNullScope2() throws Exception {
        String name = "dummyName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(null);
        when(mockedScopeMgtDAO.getScopeByName(anyString(), anyInt())).thenReturn(null);

        oAuth2ScopeService.getScope(name);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testGetScopeWithIdentityOAuth2ScopeServerException() throws Exception {
        String name = "dummyName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(null);
        when(mockedScopeMgtDAO.getScopeByName(anyString(), anyInt())).thenThrow(new IdentityOAuth2ScopeServerException
                ("dummyIdentityOAuth2ScopeServerException"));

        oAuth2ScopeService.getScope(name);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testIsScopeExistsWithIdentityException() throws Exception {
        oAuth2ScopeService.isScopeExists(null);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testIsScopeExistsWithIdentityExceptionAndNullScope() throws Exception {
        String name = "dummyName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(null);
        when(mockedScopeMgtDAO.isScopeExists(anyString(), anyInt())).thenThrow(new IdentityOAuth2ScopeServerException
                ("dummyIdentityOAuth2ScopeServerException"));

        oAuth2ScopeService.isScopeExists(name);
    }

    @Test
    public void testDeleteScope() throws Exception {
        String name = "dummyScopeName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(mockedScope);
        doNothing().when(mockedScopeMgtDAO).deleteScopeByName(anyString(), anyInt());

        oAuth2ScopeService.deleteScope(name);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testDeleteScopeWithNullName() throws Exception {
        oAuth2ScopeService.deleteScope(null);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testDeleteScopeWithWrongName() throws Exception {
        String name = "dumName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(null);
        when(mockedScopeMgtDAO.isScopeExists(anyString(), anyInt())).thenReturn(false);

        oAuth2ScopeService.deleteScope(name);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testDeleteScopeWithIdentityOAuth2ScopeServerException() throws Exception {
        String name = "dummyScopeName";
        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(mockedScope);
        doThrow(new IdentityOAuth2ScopeServerException("dummyException")).when(mockedScopeMgtDAO).deleteScopeByName
                (anyString(), anyInt());

        oAuth2ScopeService.deleteScope(name);
    }

    @Test
    public void testUpdateScope() throws Exception {
        String name = "dummyScopeName";
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(mockedScope);

        assertNotNull(oAuth2ScopeService.updateScope(mockedScope), "Expected a not null object");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUpdateScopeWithNullName() throws Exception {
        String name = null;
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        oAuth2ScopeService.updateScope(mockedScope);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUpdateScopeWithScopeNotExists() throws Exception {
        String name = "dummyScopeName";
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(null);
        when(mockedScopeMgtDAO.isScopeExists(anyString(), anyInt())).thenReturn(false);

        oAuth2ScopeService.updateScope(mockedScope);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeServerException.class)
    public void testUpdateScopeWithIdentityOAuth2ScopeServerException() throws Exception {
        String name = "dummyScopeName";
        String description = "dummyScopeDescription";
        mockedScope = new Scope(name, description);

        mockStatic(OAuthScopeCache.class);
        when(OAuthScopeCache.getInstance()).thenReturn(mockedOAuthScopeCache);
        when(mockedOAuthScopeCache.getValueFromCache(any(OAuthScopeCacheKey.class))).thenReturn(mockedScope);
        doThrow(new IdentityOAuth2ScopeServerException("dummyException")).when(mockedScopeMgtDAO).updateScopeByName
                (any(Scope.class), anyInt());

        oAuth2ScopeService.updateScope(mockedScope);
    }
}
