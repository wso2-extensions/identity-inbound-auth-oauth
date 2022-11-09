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
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.caching.impl.DataHolder;
import org.wso2.carbon.caching.impl.TenantCacheManager;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCacheKey;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.model.OAuth2ScopeConsentResponse;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

@WithCarbonHome
@WithRealmService
@WithH2Database(files = {"dbScripts/scope.sql", "dbScripts/h2.sql"})
public class OAuth2ScopeServiceTest extends PowerMockTestCase {

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

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);

        // Removing the cache manager for tenant to reset the caches added by other tenants.
        ((TenantCacheManager) DataHolder.getInstance().getCachingProvider().getCacheManagerFactory())
                .removeCacheManagerMap("carbon.super");
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

        String scopeName = "dummyScope1";
        Scope dummyScope = new Scope(scopeName, SCOPE_NAME, SCOPE_DESCRIPTION);
        Scope scope = oAuth2ScopeService.registerScope(dummyScope);
        assertEquals(scope.getName(), scopeName, "Expected name did not received");
        assertEquals(scope.getDescription(), SCOPE_DESCRIPTION, "Expected description did not received");
        oAuth2ScopeService.deleteScope(scopeName);
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

    @DataProvider(name = "invalidScopeNameProvider")
    public static Object[][] provideInvalidScopeName() {

        return new Object[][]{
                {"invalid Scope Name", Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_CONTAINS_WHITESPACES.getMessage()},
                {"invalid?scopeName", Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SATIFIED_THE_REGEX.getMessage()}
        };
    }

    @Test(dataProvider = "invalidScopeNameProvider")
    public void testRegisterWithInvalidScopeName(String scopeName, String expected) {

        try {
            Scope scope = new Scope(scopeName, "displayName", "description");
            oAuth2ScopeService.registerScope(scope);
        } catch (IdentityOAuth2ScopeException ex) {
            assertEquals(ex.getMessage(), String.format(expected, scopeName));
            return;
        }
        fail("Expected IdentityOAuth2ScopeClientException was not thrown by registerScope method");
    }

    @Test
    public void testGetScopes() throws Exception {

        assertNotNull(oAuth2ScopeService.getScopes(null, null), "Expected a not null object");
    }

    @Test(dataProvider = "indexAndCountProvider")
    public void testGetScopesWithStartAndCount(Integer startIndex, Integer count) throws Exception {

        assertNotNull(oAuth2ScopeService.getScopes(startIndex, count), "Expected a not null object");
    }

    @Test
    public void testGetScopesWithStartAndCountAndRequestedScopes() throws Exception {

        assertNotNull(oAuth2ScopeService.getScopes(1, 2, false, "read"), "Expected a not null object");
    }

    @Test
    public void testIsScopeExistsWithNullName() throws IdentityOAuth2ScopeException {

        try {
            oAuth2ScopeService.isScopeExists(null);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED.getMessage());
            return;
        }
        fail("Expected IdentityException was not thrown by isScopeExists method");
    }

    @Test
    public void testIsScopeExistsIncludeOIDCScopesWithNullName() throws IdentityOAuth2ScopeException {

        try {
            oAuth2ScopeService.isScopeExists(null, true);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED.getMessage());
            return;
        }
        fail("Expected IdentityException was not thrown by isScopeExists method");
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

        String scopeName = "dummyName2";
        Scope dummyScope = new Scope(scopeName, SCOPE_DESCRIPTION, SCOPE_NAME);
        oAuth2ScopeService.registerScope(dummyScope);
        if (!existWithinCache) {
            OAuthScopeCache.getInstance().clearCacheEntry(new OAuthScopeCacheKey(scopeName), Integer.toString(
                    Oauth2ScopeUtils.getTenantID()));
        }
        assertEquals(oAuth2ScopeService.getScope(scopeName).getName(), scopeName, "Retrieving registered scope is " +
                "failed");
        oAuth2ScopeService.deleteScope(scopeName);
    }

    @Test
    public void testUpdateScope() throws Exception {

        String scopeName = "DummyName";
        Scope dummyScope = new Scope(scopeName, SCOPE_NAME, SCOPE_DESCRIPTION);
        oAuth2ScopeService.registerScope(dummyScope);
        Scope updatedDummyScope = new Scope(scopeName, SCOPE_NAME, StringUtils.EMPTY);
        assertEquals(oAuth2ScopeService.updateScope(updatedDummyScope).getDescription(), StringUtils.EMPTY);
        oAuth2ScopeService.deleteScope(scopeName);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeException.class)
    public void testUpdateScopeWithExceptions() throws Exception {

        String scopeName = "dummyName1";
        Scope updatedDummyScope = new Scope(scopeName, SCOPE_NAME, StringUtils.EMPTY);
        oAuth2ScopeService.updateScope(updatedDummyScope);
        oAuth2ScopeService.deleteScope(scopeName);
    }

    @Test(expectedExceptions = IdentityOAuth2ScopeException.class)
    public void testDeleteScope() throws Exception {

        Scope dummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, SCOPE_DESCRIPTION);
        oAuth2ScopeService.registerScope(dummyScope);
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
        oAuth2ScopeService.getScope(SCOPE_NAME);
    }

    @Test
    public void testAddUserConsentForApplication() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        oAuth2ScopeService.addUserConsentForApplication("user_id", appId, 1, approvedScopes, deniedScopes);

        OAuth2ScopeConsentResponse oAuth2ScopeConsentResponse = oAuth2ScopeService.getUserConsentForApp("user_id",
                appId, 1);
        assertEquals(oAuth2ScopeConsentResponse.getApprovedScopes().get(0), approvedScopes.get(0));
        assertEquals(oAuth2ScopeConsentResponse.getDeniedScopes().get(0), deniedScopes.get(0));
    }

    private void insertAppId(String uuid) throws Exception {

        String sql = "INSERT INTO SP_APP (TENANT_ID, APP_NAME, UUID) VALUES (?,?,?)";
        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, 1);
            ps.setString(2, "dummyAppName");
            ps.setString(3, uuid);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when inserting codeID", e);
        }
    }

    @DataProvider(name = "invalidNameDataProvider")
    public static Object[][] invalidNameData() {

        return new Object[][]{
                {null},
                {""}
        };
    }

    @Test(dataProvider = "invalidNameDataProvider")
    public void testAddUserConsentForApplicationWithInvalidUserID(String invalidName) throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        try {
            oAuth2ScopeService.addUserConsentForApplication(invalidName, appId, 1, approvedScopes, deniedScopes);
        } catch (IdentityOAuth2ScopeClientException ex) {
            assertEquals(ex.getMessage(), "User ID can't be null/empty.");
            return;
        }
        fail("Expected IdentityOAuth2ScopeClientException was not thrown by addUserConsentForApplication method");
    }

    @Test(dataProvider = "invalidNameDataProvider")
    public void testAddUserConsentForApplicationWithInvalidAppID(String invalidAppId) throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        try {
            oAuth2ScopeService.addUserConsentForApplication("userId", invalidAppId, 1, approvedScopes, deniedScopes);
        } catch (IdentityOAuth2ScopeClientException ex) {
            assertEquals(ex.getMessage(), "Application ID can't be null/empty.");
            return;
        }
        fail("Expected IdentityOAuth2ScopeClientException was not thrown by addUserConsentForApplication method");
    }

    @Test
    public void testAddUserConsentForApplicationWithException() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String invalidAppId = UUID.randomUUID().toString();
        int tenantId = 1;
        String userId = "dummyUserId";
        try {
            oAuth2ScopeService.addUserConsentForApplication(userId, invalidAppId, tenantId, approvedScopes,
                    deniedScopes);
        } catch (IdentityOAuth2ScopeServerException e) {
            String expected = String.format(Oauth2ScopeConstants.ErrorMessages.
                            ERROR_CODE_FAILED_TO_ADD_USER_CONSENT_FOR_APP.getMessage(), userId, invalidAppId,
                    tenantId);
            assertEquals(e.getMessage(), expected);
            return;
        }
        fail("Expected IdentityOAuth2ScopeServerException was not thrown by addUserConsentForApplication method");
    }

    @DataProvider(name = "userConsentScopesForApplicationProvider")
    public static Object[][] provideUserConsentScopesForApplication() {

        return new Object[][]{
                {new ArrayList<>(Arrays.asList("create")),
                        new ArrayList<>(Arrays.asList("update")), 2, 2},
                {new ArrayList<>(Arrays.asList("write", "create")), new ArrayList<>(Arrays.asList("delete")), 3, 1}
        };
    }

    @Test(dataProvider = "userConsentScopesForApplicationProvider")
    public void testUpdateUserConsentForApplication(List<String> newApprovedScopes, List<String> newDeniedScopes,
                                                    int approvedScopeSize, int deniedScopeSize) throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("write"));
        String uuid = UUID.randomUUID().toString();
        insertAppId(uuid);
        oAuth2ScopeService.addUserConsentForApplication("user_id", uuid, 1, approvedScopes, deniedScopes);

        oAuth2ScopeService.updateUserConsentForApplication("user_id", uuid, 1, newApprovedScopes, newDeniedScopes);

        OAuth2ScopeConsentResponse oAuth2ScopeConsentResponse = oAuth2ScopeService
                .getUserConsentForApp("user_id", uuid, 1);
        assertEquals(oAuth2ScopeConsentResponse.getApprovedScopes().size(), approvedScopeSize);
        assertEquals(oAuth2ScopeConsentResponse.getDeniedScopes().size(), deniedScopeSize);
    }

    @Test
    public void testUpdateUserConsentForApplicationWithException() throws Exception {

        List<String> newApprovedScopes = new ArrayList<>(Arrays.asList("read", "create"));
        List<String> newDeniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        int tenantId = 1;
        String userId = "dummyUserId";
        try {
            oAuth2ScopeService.updateUserConsentForApplication(userId, appId, tenantId, newApprovedScopes,
                    newDeniedScopes);
        } catch (IdentityOAuth2ScopeServerException e) {
            String expected = String.format(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_UPDATE_USER_CONSENT_FOR_APP.getMessage(), userId, appId, tenantId);
            assertEquals(e.getMessage(), expected);
            return;
        }
        fail("Expected IdentityOAuth2ScopeServerException was not thrown by updateUserConsentForApplication method");
    }

    @Test
    public void testRevokeUserConsentForApplication() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String uuid = UUID.randomUUID().toString();
        insertAppId(uuid);
        oAuth2ScopeService.addUserConsentForApplication("user_id", uuid, 1, approvedScopes, deniedScopes);

        oAuth2ScopeService.revokeUserConsentForApplication("user_id", uuid, 1);

        OAuth2ScopeConsentResponse oAuth2ScopeConsentResponse = oAuth2ScopeService
                .getUserConsentForApp("user_id", uuid, 1);
        assertEquals(oAuth2ScopeConsentResponse.getApprovedScopes().size(), 0);
    }

    @Test
    public void testGetUserConsentForApp() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1;
        String userId = "dummyUserId";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        OAuth2ScopeConsentResponse oAuth2ScopeConsentResponse = oAuth2ScopeService.getUserConsentForApp(userId, appId,
                tenantId);
        assertEquals(oAuth2ScopeConsentResponse.getAppId(), appId);
        assertEquals(oAuth2ScopeConsentResponse.getUserId(), userId);
        assertEquals(oAuth2ScopeConsentResponse.getApprovedScopes().size(), approvedScopes.size());
        assertEquals(oAuth2ScopeConsentResponse.getDeniedScopes().size(), deniedScopes.size());
    }

    @DataProvider(name = "userConsentDataProvider")
    public static Object[][] provideUserConsentData() {

        return new Object[][]{
                {new ArrayList<>(Arrays.asList("read", "write", "delete")), true},
                {new ArrayList<>(Arrays.asList("read", "write", "delete", "create")), false},
                {new ArrayList<>(), true}
        };
    }

    @Test(dataProvider = "userConsentDataProvider")
    public void testHasUserProvidedConsentForAllRequestedScopes(List<String> consentRequiredScopes, boolean expected)
            throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1;
        String userId = "dummyUserId1";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        assertEquals(oAuth2ScopeService.hasUserProvidedConsentForAllRequestedScopes(userId, appId, tenantId,
                consentRequiredScopes), expected);
    }

    @DataProvider(name = "userConsentScopesProvider")
    public static Object[][] provideUserConsentScopes() {

        return new Object[][]{
                {new ArrayList<>(Arrays.asList("read", "write")),
                        new ArrayList<>(Arrays.asList("delete")), true},
                {new ArrayList<>(Arrays.asList("read", "write")), new ArrayList<>(), true},
                {new ArrayList<>(), new ArrayList<>(), false}
        };
    }

    @Test(dataProvider = "userConsentScopesProvider")
    public void testUserHasAnExistingConsentForApp(List<String> approvedScopes,
                                                   List<String> deniedScopes, boolean expected)
            throws Exception {

        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1;
        String userId = "dummyUserId1";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        assertEquals(oAuth2ScopeService.isUserHasAnExistingConsentForApp(userId, appId, tenantId), expected);
    }

    @Test
    public void testGetUserConsents() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1;
        String userId = "dummyUserId";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        List<OAuth2ScopeConsentResponse> response = oAuth2ScopeService.getUserConsents(userId,
                tenantId);
        assertEquals(response.get(0).getAppId(), appId);
        assertEquals(response.get(0).getUserId(), userId);
        assertEquals(response.get(0).getApprovedScopes().size(), approvedScopes.size());
        assertEquals(response.get(0).getDeniedScopes().size(), deniedScopes.size());
    }

    @Test
    public void testRevokeUserConsents() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Arrays.asList("read", "write"));
        List<String> deniedScopes = new ArrayList<>(Arrays.asList("delete"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1;
        String userId = "dummyUserId";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        oAuth2ScopeService.revokeUserConsents(userId, tenantId);

        List<OAuth2ScopeConsentResponse> response = oAuth2ScopeService.getUserConsents(userId,
                tenantId);
        assertEquals(response.size(), 0);
    }
}
