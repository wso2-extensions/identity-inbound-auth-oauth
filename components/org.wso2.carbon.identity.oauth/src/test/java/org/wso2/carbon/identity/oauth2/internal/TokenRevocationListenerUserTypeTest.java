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

package org.wso2.carbon.identity.oauth2.internal;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.listener.TenantCreationEventListener;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Tests that the listeners revoking the tokens of a user store or a tenant revoke the latest token of each user
 * type (APPLICATION and APPLICATION_USER), as a user can hold a token of each user type for the same client and
 * scope.
 */
@WithCarbonHome
public class TokenRevocationListenerUserTypeTest {

    private static final int TENANT_ID = 1;
    private static final String TENANT_DOMAIN = "wso2.com";
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String CONSUMER_KEY = "consumerKey";
    private static final String OLDER_APPLICATION_USER_TOKEN = "olderApplicationUserToken";
    private static final String APPLICATION_TOKEN = "applicationToken";
    private static final String APPLICATION_USER_TOKEN = "applicationUserToken";

    private MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactory;
    private MockedStatic<OAuthUtil> oAuthUtil;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<AccessTokenEventUtil> accessTokenEventUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private AccessTokenDAO accessTokenDAO;
    private OrganizationManager organizationManager;

    private interface Revocation {

        void revoke() throws Exception;
    }

    @BeforeMethod
    public void setUp() throws Exception {

        accessTokenDAO = mock(AccessTokenDAO.class);
        OAuthTokenPersistenceFactory persistenceFactory = mock(OAuthTokenPersistenceFactory.class);
        when(persistenceFactory.getAccessTokenDAO()).thenReturn(accessTokenDAO);
        when(persistenceFactory.getAuthorizationCodeDAO()).thenReturn(mock(AuthorizationCodeDAO.class));
        oAuthTokenPersistenceFactory = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(persistenceFactory);

        // The cache clearing and the revocation events are not part of these tests.
        oAuthUtil = mockStatic(OAuthUtil.class);
        accessTokenEventUtil = mockStatic(AccessTokenEventUtil.class);

        oAuth2Util = mockStatic(OAuth2Util.class);
        oAuth2Util.when(() -> OAuth2Util.buildScopeString(any(String[].class))).thenCallRealMethod();
        oAuth2Util.when(OAuth2Util::isHashEnabled).thenReturn(false);

        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(TENANT_DOMAIN);

        organizationManager = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager();
        OrganizationManager mockOrganizationManager = mock(OrganizationManager.class);
        when(mockOrganizationManager.resolveOrganizationId(anyString())).thenReturn("organizationId");
        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(mockOrganizationManager);

        Set<AccessTokenDO> tokens = buildTokensOfBothUserTypes();
        when(accessTokenDAO.getAccessTokensOfUserStore(TENANT_ID, USER_STORE_DOMAIN)).thenReturn(tokens);
        when(accessTokenDAO.getAccessTokensByTenant(TENANT_ID)).thenReturn(new HashSet<>(tokens));
        when(accessTokenDAO.getAccessTokensByAuthorizedOrg(anyString())).thenReturn(new HashSet<>());
    }

    @AfterMethod(alwaysRun = true)
    public void tearDown() {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManager);
        oAuthTokenPersistenceFactory.close();
        oAuthUtil.close();
        oAuth2Util.close();
        accessTokenEventUtil.close();
        identityTenantUtil.close();
    }

    @DataProvider(name = "listenerData")
    public Object[][] listenerData() {

        Revocation userStoreDeletion = () ->
                new OAuthUserStoreConfigListenerImpl().onUserStorePreDelete(TENANT_ID, USER_STORE_DOMAIN);
        Revocation tenantDeactivation = () -> new OAuthTenantMgtListenerImpl().onTenantDeactivation(TENANT_ID);
        Revocation tenantCreationListenerDeactivation = () ->
                new TenantCreationEventListener().onTenantDeactivation(TENANT_ID);
        return new Object[][]{{userStoreDeletion}, {tenantDeactivation}, {tenantCreationListenerDeactivation}};
    }

    @Test(dataProvider = "listenerData")
    public void testLatestTokenOfEachUserTypeIsRevoked(Revocation revocation) throws Exception {

        revocation.revoke();

        ArgumentCaptor<String[]> revokedTokens = ArgumentCaptor.forClass(String[].class);
        verify(accessTokenDAO).revokeAccessTokens(revokedTokens.capture(), anyBoolean());
        String[] revoked = revokedTokens.getValue();
        Arrays.sort(revoked);
        assertEquals(revoked, new String[]{APPLICATION_TOKEN, APPLICATION_USER_TOKEN},
                "The latest token of each user type, and only that, should be revoked.");
    }

    private Set<AccessTokenDO> buildTokensOfBothUserTypes() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("user");
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserId("userId");
        long now = System.currentTimeMillis();
        // An older token of the same user type, which is not the latest of its user type.
        return new HashSet<>(Arrays.asList(
                buildToken(OLDER_APPLICATION_USER_TOKEN, user, OAuthConstants.UserType.APPLICATION_USER, now - 20000),
                buildToken(APPLICATION_TOKEN, user, OAuthConstants.UserType.APPLICATION, now - 10000),
                buildToken(APPLICATION_USER_TOKEN, user, OAuthConstants.UserType.APPLICATION_USER, now)));
    }

    private AccessTokenDO buildToken(String accessToken, AuthenticatedUser user, String userType, long issuedTime) {

        AccessTokenDO accessTokenDO = new AccessTokenDO(CONSUMER_KEY, user, new String[]{"scope1"},
                new Timestamp(issuedTime), new Timestamp(issuedTime), 3600000L, 3600000L, userType);
        accessTokenDO.setAccessToken(accessToken);
        accessTokenDO.setTokenId(accessToken + "Id");
        return accessTokenDO;
    }
}
