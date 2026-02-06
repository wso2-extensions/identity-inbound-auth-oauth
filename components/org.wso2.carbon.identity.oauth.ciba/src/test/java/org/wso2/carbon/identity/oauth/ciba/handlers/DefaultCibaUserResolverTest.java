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

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver.ResolvedUser;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class DefaultCibaUserResolverTest {

    private DefaultCibaUserResolver defaultCibaUserResolver;

    @Mock
    private RealmService realmService;

    @Mock
    private UserRealm userRealm;

    @Mock
    private AbstractUserStoreManager userStoreManager;

    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    private static final String LOGIN_HINT = "testUser";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        defaultCibaUserResolver = DefaultCibaUserResolver.getInstance();
        CibaServiceComponentHolder.getInstance().setRealmService(realmService);

        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(TENANT_ID);

        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
    }

    @AfterMethod
    public void tearDown() {
        identityTenantUtil.close();
    }

    @Test(expectedExceptions = CibaCoreException.class)
    public void testResolveUserWithBlankLoginHint() throws Exception {
        defaultCibaUserResolver.resolveUser("", TENANT_DOMAIN);
    }

    @Test
    public void testResolveUserByUsername() throws Exception {

        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        Map<String, String> claims = new HashMap<>();
        claims.put("http://wso2.org/claims/emailaddress", "test@wso2.com");
        claims.put("http://wso2.org/claims/userid", "uid-123");
        when(userStoreManager.getUserClaimValues(anyString(), any(), any())).thenReturn(claims);

        ResolvedUser resolvedUser = defaultCibaUserResolver.resolveUser(LOGIN_HINT, TENANT_DOMAIN);
        Assert.assertNotNull(resolvedUser);
        Assert.assertEquals(resolvedUser.getUsername(), "testUser"); // Tenant aware username
        Assert.assertEquals(resolvedUser.getUserId(), "uid-123");
        Assert.assertEquals(resolvedUser.getEmail(), "test@wso2.com");
    }

    @Test
    public void testResolveUserByUserId() throws Exception {

        when(userStoreManager.isExistingUser(anyString())).thenReturn(false);
        when(userStoreManager.isExistingUserWithID(anyString())).thenReturn(true);
        when(userStoreManager.getUserNameFromUserID(anyString())).thenReturn(LOGIN_HINT);

        Map<String, String> claims = new HashMap<>();
        claims.put("http://wso2.org/claims/emailaddress", "test@wso2.com");
        when(userStoreManager.getUserClaimValuesWithID(anyString(), any(), any())).thenReturn(claims);

        ResolvedUser resolvedUser = defaultCibaUserResolver.resolveUser("uid-123", TENANT_DOMAIN);
        Assert.assertNotNull(resolvedUser);
        Assert.assertEquals(resolvedUser.getUserId(), "uid-123");
        Assert.assertEquals(resolvedUser.getUsername(), LOGIN_HINT);
    }

    @Test(expectedExceptions = CibaClientException.class)
    public void testResolveUserNotFound() throws Exception {
        when(userStoreManager.isExistingUser(anyString())).thenReturn(false);
        when(userStoreManager.isExistingUserWithID(anyString())).thenReturn(false);
        defaultCibaUserResolver.resolveUser(LOGIN_HINT, TENANT_DOMAIN);
    }

    @Test
    public void testResolveUserTenantResolution() throws Exception {
        // Test when tenant domain is null/blank, it resolves from login hint
        String loginHintWithTenant = "testUser@wso2.com";
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        Map<String, String> claims = new HashMap<>();
        when(userStoreManager.getUserClaimValues(anyString(), any(), any())).thenReturn(claims);

        // Mock static behavior of MultitenantUtils by implicit assumption or explicit
        // mock if needed.
        // But here we rely on actual util as we are not mocking it.
        // MultitenantUtils.getTenantDomain("testUser@wso2.com") -> "wso2.com"
        // But IdentityTenantUtil.getTenantId("wso2.com") is mocked to return TENANT_ID
        // so it should proceed.

        ResolvedUser resolvedUser = defaultCibaUserResolver.resolveUser(loginHintWithTenant, null);
        Assert.assertNotNull(resolvedUser);
    }
}
