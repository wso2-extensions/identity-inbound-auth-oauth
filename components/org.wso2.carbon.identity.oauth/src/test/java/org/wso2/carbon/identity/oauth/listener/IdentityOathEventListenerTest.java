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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;


public class IdentityOathEventListenerTest extends IdentityBaseTest {

    private final String credentialUpdateUsername = "testUsername";
    private final String newCredential = "newPassword1$";
    @Mock
    OAuth2ServiceComponentHolder oAuth2ServiceComponentHolder;
    private IdentityOathEventListener identityOathEventListener;
    @Mock
    private AbstractUserStoreManager abstractUserStoreManager;
    @Mock
    private OAuth2RevocationProcessor oAuth2RevocationProcessor;
    @Mock
    private OrganizationManager organizationManager;
    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic;

    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;

    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;

    @Mock
    private OrganizationUserSharingService organizationUserSharingService;

    @Mock
    private RealmService realmService;

    @Mock
    private UserRealm userRealm;

    @BeforeMethod
    public void setUp() {

        openMocks(this);
        identityOathEventListener = new IdentityOathEventListener();

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);

        oAuth2ServiceComponentHolderMockedStatic = mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(oAuth2ServiceComponentHolder);

        oAuthComponentServiceHolderMockedStatic = mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);

    }

    @AfterMethod
    public void clear() {

        identityTenantUtilMockedStatic.close();
        oAuth2ServiceComponentHolderMockedStatic.close();
        oAuthComponentServiceHolderMockedStatic.close();
    }

    private void prepareForCredentialUpdate() throws UserStoreException, OrganizationManagementException {

        String userID = "testId";
        int tenantId = 1234;
        String tenant = "testTenant";
        String orgId = "testOrg";
        String orgIdUserAssociation = "TestAssociateOrg";
        String tenantUserAssociation = "TestAssociateTenant";
        int userAssociationTenantId = 3245;
        User user = new User(userID);
        List<UserAssociation> userAssociationList = new ArrayList<>();
        UserAssociation userAssociation = new UserAssociation();
        userAssociation.setOrganizationId(orgIdUserAssociation);
        userAssociationList.add(userAssociation);

        when(oAuth2ServiceComponentHolder.getRevocationProcessor()).thenReturn(oAuth2RevocationProcessor);
        when(oAuth2RevocationProcessor.revokeTokens(credentialUpdateUsername, abstractUserStoreManager)).thenReturn(
                false);
        when(abstractUserStoreManager.getUser(null, credentialUpdateUsername)).thenReturn(user);
        when(abstractUserStoreManager.getTenantId()).thenReturn(tenantId);
        when(IdentityTenantUtil.getTenantDomain(tenantId)).thenReturn(tenant);
        when(organizationManager.resolveOrganizationId(tenant)).thenReturn(orgId);
        when(oAuthComponentServiceHolder.getOrganizationUserSharingService()).thenReturn(
                organizationUserSharingService);
        when(organizationUserSharingService.getUserAssociationsOfGivenUser(userID, orgId)).thenReturn(
                userAssociationList);
        when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(organizationManager.resolveTenantDomain(orgIdUserAssociation)).thenReturn(tenantUserAssociation);
        when(oAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);
        when(IdentityTenantUtil.getTenantId(tenantUserAssociation)).thenReturn(userAssociationTenantId);
        when(realmService.getTenantUserRealm(userAssociationTenantId)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(abstractUserStoreManager);
    }

    @Test
    public void testDoPostUpdateCredential() throws UserStoreException, OrganizationManagementException {

        prepareForCredentialUpdate();
        identityOathEventListener.doPostUpdateCredential(credentialUpdateUsername, newCredential,
                abstractUserStoreManager);
    }

    @Test
    public void testDoPostUpdateCredentialByAdmin() throws UserStoreException, OrganizationManagementException {

        prepareForCredentialUpdate();
        identityOathEventListener.doPostUpdateCredentialByAdmin(credentialUpdateUsername, newCredential,
                abstractUserStoreManager);

    }

//
//    @DataProvider(name = "testGetExecutionOrderIdData")
//    public Object[][] testGetExecutionOrderIdData() {
//        return new Object[][]{
//                {10, 10},
//                {IdentityCoreConstants.EVENT_LISTENER_ORDER_ID, 100}
//        };
//    }
//
//    @Test(dataProvider = "testGetExecutionOrderIdData")
//    public void testGetExecutionOrderId(int orderId, int expected) throws Exception {
//        IdentityEventListenerConfig identityEventListenerConfig = mock(IdentityEventListenerConfig.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(identityEventListenerConfig);
//        when(identityOathEventListener.getOrderId()).thenReturn(orderId);
//        assertEquals(identityOathEventListener.getExecutionOrderId(), expected, "asserting exec. order id");
//    }
//
//    @Test
//    public void testDoPreDeleteUser() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPreDeleteUser(username, userStoreManager));
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//        when(ClaimMetaDataCache.getInstance()).thenReturn(claimMetaDataCache);
//        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
//
//        IdentityOathEventListener listener2 = new IdentityOathEventListener();
//        assertTrue(listener2.doPreDeleteUser(username, userStoreManager));
//    }
//
//    @Test
//    public void testDoPreSetUserClaimValue() throws Exception {
//        Set<String> accessToken = new HashSet<>();
//        accessToken.add("kljdslfjljdsfjldsflkdsjkfjdsjlkj");
//        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);
//
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
//        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
//        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
//
//        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
//        assertTrue(identityOathEventListener.doPreSetUserClaimValue(username, claimUri, claimValue, profileName,
//                userStoreManager));
//    }
//
//    @Test
//    public void testDoPreSetUserClaimValueWithAuthorizationCode() throws Exception {
//        Set<String> accessToken = new HashSet<>();
//        accessToken.add("kljdslfjljdsfjldsflkdsjkfjdsjlkj");
//
//        Set<String> authorizationCodes = new HashSet<String>();
//        authorizationCodes.add("AUTHORIZATION_CODE");
//        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);
//
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
//        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
//
//        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
//
//        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
//        assertTrue(identityOathEventListener.doPreSetUserClaimValue(username, claimUri, claimValue, profileName,
//                userStoreManager));
//    }
//
//    @Test
//    public void testRemoveTokensFromCacheExceptionalFlow() throws Exception {
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
//        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
//
//        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
//        assertTrue(identityOathEventListener.doPreSetUserClaimValue(username, claimUri, claimValue, profileName,
//                userStoreManager));
//    }
//
//    @Test
//    public void testDoPreSetUserClaimValues() throws Exception {
//        Set<String> accessToken = new HashSet<>();
//        accessToken.add("kljdslfjljdsfjldsflkdsjkfjdsjlkj");
//        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);
//
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
//        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
//        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
//
//        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
//        assertTrue(identityOathEventListener.doPreSetUserClaimValues(username, mockedMapClaims, profileName,
//                userStoreManager));
//    }
//
//    @Test
//    public void testDoPostSetUserClaimValue() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        assertTrue(identityOathEventListener.doPostSetUserClaimValue(username, userStoreManager));
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostSetUserClaimValue(username, userStoreManager));
//    }
//
//    @Test
//    public void testDoPostSetUserClaimValues() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        assertTrue(identityOathEventListener.doPostSetUserClaimValues(username, mockedMapClaims, profileName,
//                userStoreManager));
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostSetUserClaimValues(username, mockedMapClaims, profileName, userStoreManager));
//    }
//
//    @Test
//    public void testDoPostAuthenticate() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        assertTrue(identityOathEventListener.doPostAuthenticate(username, true, userStoreManager));
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostAuthenticate(username, true, userStoreManager));
//    }
//
//    @Test
//    public void testDoPostUpdateCredential() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        IdentityOathEventListener ioeListener = new IdentityOathEventListener();
//        assertTrue(ioeListener.doPostUpdateCredential(username, new Object(), userStoreManager));
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//
//        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredential(username, new Object(), userStoreManager));
//    }
//
//    @Test
//    public void testDoPostUpdateCredentialByAdmin() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        IdentityOathEventListener ioeListener = new IdentityOathEventListener();
//        assertTrue(ioeListener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//
//        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//    }
//
//    @Test
//    public void testForTokenRevocationUnmetPaths() throws Exception {
//        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//        ClaimCache claimCache = mock(ClaimCache.class);
//        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
//        when(StringUtils.isNotBlank(anyString())).thenReturn(true);
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//        when(claimCache.isEnabled()).thenReturn(false);
//
//        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
//
//        Set<String> clientIds = new HashSet<String>();
//        clientIds.add("CLIENT_ID_ONE");
//
//        AccessTokenDO accessTokenDO = new AccessTokenDO();
//        accessTokenDO.setConsumerKey("CONSUMER_KEY");
//        accessTokenDO.setAuthzUser(authenticatedUser);
//        accessTokenDO.setScope(new String[]{"OPEN_ID", "PROFILE"});
//        accessTokenDO.setAccessToken("ACCESS_TOKEN  ");
//
//        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//    }
//
//    @Test
//    public void testForExceptionsInTokenRevocationPath1() throws Exception {
//        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(true);
//        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(true);
//        when(OAuth2Util.getUserStoreForFederatedUser(any(AuthenticatedUser.class))).
//                thenThrow(new IdentityOAuth2Exception("message"));
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//    }
//
//    @Test
//    public void testForExceptionInTokenRevocationPath2() throws Exception {
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//    }
//
//    @Test
//    public void testForExceptionInTokenRevocationPath3() throws Exception {
//        Set<String> clientIds = new HashSet<String>();
//        clientIds.add("CLIENT_ID_ONE");
//
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//    }
//
//    @Test
//    public void testForExceptionInTokenRevocationPath4() throws Exception {
//        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
//
//        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
//        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
//        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
//
//        Set<String> clientIds = new HashSet<String>();
//        clientIds.add("CLIENT_ID_ONE");
//
//        AccessTokenDO accessTokenDO = new AccessTokenDO();
//        accessTokenDO.setConsumerKey("CONSUMER_KEY");
//        accessTokenDO.setAuthzUser(authenticatedUser);
//        accessTokenDO.setScope(new String[]{"OPEN_ID", "PROFILE"});
//        accessTokenDO.setAccessToken("ACCESS_TOKEN  ");
//
//        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
//
//        IdentityOathEventListener listener = new IdentityOathEventListener();
//        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
//    }
}
