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
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCacheKey;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.model.OAuth2ScopeConsentResponse;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
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
    public void testRegisterScopeWithExistingScopeName() throws Exception {

        Scope dummyScope = new Scope(SCOPE_NAME, SCOPE_NAME, SCOPE_DESCRIPTION);
        oAuth2ScopeService.registerScope(dummyScope);
        try {
            oAuth2ScopeService.registerScope(dummyScope);
        } catch (IdentityOAuth2ScopeClientException e) {
            assertEquals(e.getMessage(), "Scope with the name dummyScopeName already exists in the system."
                    + " Please use a different scope name.");
        }
        oAuth2ScopeService.deleteScope(SCOPE_NAME);
    }

    @DataProvider(name = "invalidScopeNameProvider")
    public static Object[][] provideInvalidScopeName() {

        return new Object[][]{
                {"invalid Scope Name", "Scope name: %s contains white spaces."},
                {"invalid?scopeName", "Invalid scope name. Scope name %s cannot " +
                        "contain special characters ?,#,/,( or )"}
        };
    }

    @Test(dataProvider = "invalidScopeNameProvider")
    public void testRegisterWithInvalidScopeName(String scopeName, String expected) {

        try {
            Scope scope = new Scope(scopeName, "displayName", "description");
            oAuth2ScopeService.registerScope(scope);
        } catch (IdentityOAuth2ScopeException ex) {
            assertEquals(ex.getMessage(), String.format(expected, scopeName));
        }
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

        assertNotNull(oAuth2ScopeService.getScopes(1, 2, false, "true"), "Expected a not null object");
    }

    @Test()
    public void testIsScopeExistsWithNullName() throws IdentityOAuth2ScopeException {

        try {
            oAuth2ScopeService.isScopeExists(null);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Scope Name is not specified.");
        }
    }

    @Test()
    public void testIsScopeExistsIncludeOIDCScopesWithNullName() throws IdentityOAuth2ScopeException {

        try {
            oAuth2ScopeService.isScopeExists(null, true);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Scope Name is not specified.");
        }
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
            OAuthScopeCache.getInstance().clearCacheEntry(new OAuthScopeCacheKey(SCOPE_NAME), Integer.toString(
                    Oauth2ScopeUtils.getTenantID()));
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

    @Test
    public void testAddUserConsentForApplication() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String uuid = UUID.randomUUID().toString();
        insertAppId(uuid);
        oAuth2ScopeService.addUserConsentForApplication("user_id", uuid, 1, approvedScopes, deniedScopes);

        assertEquals(oAuth2ScopeService.getUserConsentForApp("user_id", uuid, 1).getApprovedScopes().get(0),
                approvedScopes.get(0));
    }

    private void insertAppId(String uuid) throws Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = "INSERT INTO SP_APP (TENANT_ID, APP_NAME, UUID) VALUES (?,?,?)";
            PreparedStatement ps = connection.prepareStatement(sql);
            ps.setInt(1, 1234);
            ps.setString(2, "dummyAppName");
            ps.setString(3, uuid);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when inserting codeID", e);
        }
    }

    @Test
    public void testAddUserConsentForApplicationWithInvalidUserID() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String appId = UUID.randomUUID().toString();
        try {
            oAuth2ScopeService.addUserConsentForApplication(null, appId, 1, approvedScopes, deniedScopes);
        } catch (IdentityOAuth2ScopeClientException ex) {
            assertEquals(ex.getMessage(), "User ID can't be null/empty.");
        }
    }

    @Test
    public void testAddUserConsentForApplicationWithInvalidAppID() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        try {
            oAuth2ScopeService.addUserConsentForApplication("userId", null, 1, approvedScopes, deniedScopes);
        } catch (IdentityOAuth2ScopeClientException ex) {
            assertEquals(ex.getMessage(), "Application ID can't be null/empty.");
        }
    }

    @Test
    public void testAddUserConsentForApplicationWithException() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String appId = UUID.randomUUID().toString();
        int tenantId = 1234;
        String userId = "dummyUserId";
        try {
            oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);
        } catch (IdentityOAuth2ScopeServerException e) {
            String expected = String.format("Error occurred while adding user consent for "
                    + "OAuth scopes for user : %s, application : %s and tenant Id : %d.", userId, appId, tenantId);
            assertEquals(e.getMessage(), expected);
        }
    }

    @Test
    public void testUpdateUserConsentForApplication() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String uuid = UUID.randomUUID().toString();
        insertAppId(uuid);
        oAuth2ScopeService.addUserConsentForApplication("user_id", uuid, 1234, approvedScopes, deniedScopes);

        List<String> newApprovedScopes = new ArrayList<>(Collections.singletonList("newApprovedScopes"));
        List<String> newDeniedScopes = new ArrayList<>(Collections.singletonList("newDeniedScopes"));
        oAuth2ScopeService.updateUserConsentForApplication("user_id", uuid, 1234, newApprovedScopes, newDeniedScopes);

        assertEquals(oAuth2ScopeService.getUserConsentForApp("user_id", uuid, 1234).getApprovedScopes().size(),
                2);
    }

    @Test
    public void testUpdateUserConsentForApplicationWithException() throws Exception {

        List<String> newApprovedScopes = new ArrayList<>(Collections.singletonList("newApprovedScopes"));
        List<String> newDeniedScopes = new ArrayList<>(Collections.singletonList("newDeniedScopes"));
        String appId = UUID.randomUUID().toString();
        int tenantId = 1234;
        String userId = "dummyUserId";
        try {
            oAuth2ScopeService.updateUserConsentForApplication(userId, appId, tenantId, newApprovedScopes,
                    newDeniedScopes);
        } catch (IdentityOAuth2ScopeServerException e) {
            String expected = String.format("Error occurred while updating user consent for OAuth scopes for user"
                    + " : %s, application : %s and tenant Id : %d.", userId, appId, tenantId);
            assertEquals(e.getMessage(), expected);
        }
    }

    @Test
    public void testRevokeUserConsentForApplication() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String uuid = UUID.randomUUID().toString();
        insertAppId(uuid);
        oAuth2ScopeService.addUserConsentForApplication("user_id", uuid, 1234, approvedScopes, deniedScopes);

        oAuth2ScopeService.revokeUserConsentForApplication("user_id", uuid, 1234);

        assertEquals(oAuth2ScopeService.getUserConsentForApp("user_id", uuid, 1234).getApprovedScopes().size(), 0);
    }

    @Test
    public void testGetUserConsentForApp() throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1234;
        String userId = "dummyUserId";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        OAuth2ScopeConsentResponse oAuth2ScopeConsentResponse = oAuth2ScopeService.getUserConsentForApp(userId, appId,
                tenantId);
        assertEquals(oAuth2ScopeConsentResponse.getAppId(), appId);
        assertEquals(oAuth2ScopeConsentResponse.getUserId(), userId);
    }

    @DataProvider(name = "userConsentDataProvider")
    public static Object[][] provideUserConsentData() {

        return new Object[][]{
                {new ArrayList<>(Arrays.asList("approvedScopes", "deniedScopes")), true},
                {new ArrayList<>(Arrays.asList("approvedScopes", "deniedScopes", "newScope")), false},
                {new ArrayList<>(), true}
        };
    }

    @Test(dataProvider = "userConsentDataProvider")
    public void testHasUserProvidedConsentForAllRequestedScopes(List<String> consentRequiredScopes, boolean expected)
            throws Exception {

        List<String> approvedScopes = new ArrayList<>(Collections.singletonList("approvedScopes"));
        List<String> deniedScopes = new ArrayList<>(Collections.singletonList("deniedScopes"));
        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1234;
        String userId = "dummyUserId1";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        assertEquals(oAuth2ScopeService.hasUserProvidedConsentForAllRequestedScopes(userId, appId, tenantId,
                consentRequiredScopes), expected);
        oAuth2ScopeService.revokeUserConsentForApplication(userId, appId, tenantId);
    }

    @DataProvider(name = "userConsentScopesProvider")
    public static Object[][] provideUserConsentScopes() {

        return new Object[][]{
                {new ArrayList<>(Collections.singletonList("approvedScopes")),
                        new ArrayList<>(Collections.singletonList("deniedScopes")), true},
                {new ArrayList<>(Collections.singletonList("approvedScopes")), new ArrayList<>(), true},
                {new ArrayList<>(), new ArrayList<>(), false}
        };
    }

    @Test(dataProvider = "userConsentScopesProvider")
    public void testsUserHasAnExistingConsentForApp(List<String> approvedScopes,
                                                    List<String> deniedScopes, boolean expected)
            throws Exception {

        String appId = UUID.randomUUID().toString();
        insertAppId(appId);
        int tenantId = 1234;
        String userId = "dummyUserId1";
        oAuth2ScopeService.addUserConsentForApplication(userId, appId, tenantId, approvedScopes, deniedScopes);

        assertEquals(oAuth2ScopeService.isUserHasAnExistingConsentForApp(userId, appId, tenantId), expected);
        oAuth2ScopeService.revokeUserConsentForApplication(userId, appId, tenantId);
    }
}
