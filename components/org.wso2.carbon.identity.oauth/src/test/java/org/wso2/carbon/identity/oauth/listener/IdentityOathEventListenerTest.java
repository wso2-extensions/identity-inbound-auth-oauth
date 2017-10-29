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

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.model.IdentityCacheConfig;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

@PrepareForTest({UserCoreUtil.class, IdentityTenantUtil.class, OAuthServerConfiguration.class,
        IdentityOathEventListener.class, AuthorizationGrantCache.class, IdentityUtil.class,
        StringUtils.class, ClaimMetaDataCache.class,OAuth2Util.class})
public class IdentityOathEventListenerTest extends IdentityBaseTest {

    private IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
    private String username = "USER_NAME";
    private String claimUri = "CLAIM_URI";
    private String claimValue = "CLAIM_VALUE";
    private String profileName = "PROFILE_NAME";

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private TokenMgtDAO tokenMgtDAO;

    @Mock
    private AuthenticatedUser authenticatedUser;

    @Mock
    private Map<String, String> mockedMapClaims;

    @Mock
    private ClaimMetaDataCache claimMetaDataCache;

    @Mock
    private OAuthServerConfiguration oauthServerConfigurationMock;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(UserCoreUtil.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(AuthorizationGrantCache.class);
        mockStatic(IdentityUtil.class);
        mockStatic(StringUtils.class);
        mockStatic(ClaimMetaDataCache.class);
        mockStatic(OAuth2Util.class);

    }

    @DataProvider(name = "testGetExecutionOrderIdData")
    public Object[][] testGetExecutionOrderIdData() {
        return new Object[][]{
                {10, 10},
                {IdentityCoreConstants.EVENT_LISTENER_ORDER_ID, 100}
        };
    }

    @Test(dataProvider = "testGetExecutionOrderIdData")
    public void testGetExecutionOrderId(int orderId, int expected) throws Exception {
        IdentityEventListenerConfig identityEventListenerConfig = mock(IdentityEventListenerConfig.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(identityEventListenerConfig);
        when(identityOathEventListener.getOrderId()).thenReturn(orderId);
        assertEquals(identityOathEventListener.getExecutionOrderId(), expected, "asserting exec. order id");
    }

    @Test
    public void testDoPreDeleteUser() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPreDeleteUser(username, userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);
        when(ClaimMetaDataCache.getInstance()).thenReturn(claimMetaDataCache);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);

        IdentityOathEventListener listener2 = new IdentityOathEventListener();
        assertTrue(listener2.doPreDeleteUser(username, userStoreManager));
    }

    @Test
    public void testDoPreSetUserClaimValue() throws Exception {
        Set<String> accessToken = new HashSet<>();
        accessToken.add("kljdslfjljdsfjldsflkdsjkfjdsjlkj");
        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);

        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
        when(tokenMgtDAO.getAccessTokensForUser(authenticatedUser)).thenReturn(accessToken);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);

        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
        assertTrue(identityOathEventListener.doPreSetUserClaimValue(username, claimUri, claimValue, profileName,
                userStoreManager));
    }

    @Test
    public void testDoPreSetUserClaimValueWithAuthorizationCode() throws Exception {
        Set<String> accessToken = new HashSet<>();
        accessToken.add("kljdslfjljdsfjldsflkdsjkfjdsjlkj");

        Set<String> authorizationCodes = new HashSet<String>();
        authorizationCodes.add("AUTHORIZATION_CODE");
        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);

        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
        when(tokenMgtDAO.getAccessTokensForUser(authenticatedUser)).thenReturn(accessToken);
        when(tokenMgtDAO.getAuthorizationCodesForUser(any(AuthenticatedUser.class))).thenReturn(authorizationCodes);

        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);

        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
        assertTrue(identityOathEventListener.doPreSetUserClaimValue(username, claimUri, claimValue, profileName,
                userStoreManager));
    }

    @Test
    public void testRemoveTokensFromCacheExceptionalFlow() throws Exception {
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
        when(tokenMgtDAO.getAccessTokensForUser(authenticatedUser)).
                thenThrow(new IdentityOAuth2Exception("Error occrued"));

        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
        assertTrue(identityOathEventListener.doPreSetUserClaimValue(username, claimUri, claimValue, profileName,
                userStoreManager));
    }

    @Test
    public void testDoPreSetUserClaimValues() throws Exception {
        Set<String> accessToken = new HashSet<>();
        accessToken.add("kljdslfjljdsfjldsflkdsjkfjdsjlkj");
        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);

        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn("TENANT_DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(authenticatedUser);
        when(tokenMgtDAO.getAccessTokensForUser(authenticatedUser)).thenReturn(accessToken);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);

        IdentityOathEventListener identityOathEventListener = new IdentityOathEventListener();
        assertTrue(identityOathEventListener.doPreSetUserClaimValues(username, mockedMapClaims, profileName,
                userStoreManager));
    }

    @Test
    public void testDoPostSetUserClaimValue() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        assertTrue(identityOathEventListener.doPostSetUserClaimValue(username, userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostSetUserClaimValue(username, userStoreManager));
    }

    @Test
    public void testDoPostSetUserClaimValues() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        assertTrue(identityOathEventListener.doPostSetUserClaimValues(username, mockedMapClaims, profileName,
                userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostSetUserClaimValues(username, mockedMapClaims, profileName, userStoreManager));
    }

    @Test
    public void testDoPostAuthenticate() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        assertTrue(identityOathEventListener.doPostAuthenticate(username, true, userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostAuthenticate(username, true, userStoreManager));
    }

    @Test
    public void testDoPostUpdateCredential() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        IdentityOathEventListener ioeListener = new IdentityOathEventListener();
        assertTrue(ioeListener.doPostUpdateCredential(username, new Object(), userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredential(username, new Object(), userStoreManager));
    }

    @Test
    public void testDoPostUpdateCredentialByAdmin() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        IdentityOathEventListener ioeListener = new IdentityOathEventListener();
        assertTrue(ioeListener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
    }

    @Test
    public void testForTokenRevocationUnmetPaths() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        OAuthServerConfiguration mockedServerConfig = mock(OAuthServerConfiguration.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);

        Set<String> clientIds = new HashSet<String>();
        clientIds.add("CLIENT_ID_ONE");

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("CONSUMER_KEY");
        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokenDO.setScope(new String[]{"OPEN_ID", "PROFILE"});
        accessTokenDO.setAccessToken("ACCESS_TOKEN  ");

        Set<AccessTokenDO> accessTokens = new HashSet<AccessTokenDO>();
        accessTokens.add(accessTokenDO);

        when(tokenMgtDAO.getAllTimeAuthorizedClientIds(any(AuthenticatedUser.class))).thenReturn(clientIds);
        when(tokenMgtDAO.retrieveAccessTokens(anyString(), any(AuthenticatedUser.class), anyString(),
                anyBoolean())).thenReturn(accessTokens);

        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
    }

    @Test
    public void testForExceptionsInTokenRevocationPath1() throws Exception {
        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(true);
        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(true);
        when(OAuth2Util.getUserStoreForFederatedUser(any(AuthenticatedUser.class))).
                thenThrow(new IdentityOAuth2Exception("message"));
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
    }

    @Test
    public void testForExceptionInTokenRevocationPath2() throws Exception {
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        when(tokenMgtDAO.getAllTimeAuthorizedClientIds(any(AuthenticatedUser.class))).thenThrow(new IdentityOAuth2Exception("message"));

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
    }

    @Test
    public void testForExceptionInTokenRevocationPath3() throws Exception {
        Set<String> clientIds = new HashSet<String>();
        clientIds.add("CLIENT_ID_ONE");

        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);
        when(tokenMgtDAO.getAllTimeAuthorizedClientIds(any(AuthenticatedUser.class))).thenReturn(clientIds);
        when(tokenMgtDAO.retrieveAccessTokens(anyString(), any(AuthenticatedUser.class), anyString(), anyBoolean())).
                thenThrow(new IdentityOAuth2Exception("message"));

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
    }

    @Test
    public void testForExceptionInTokenRevocationPath4() throws Exception {
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(tokenMgtDAO);

        Set<String> clientIds = new HashSet<String>();
        clientIds.add("CLIENT_ID_ONE");

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("CONSUMER_KEY");
        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokenDO.setScope(new String[]{"OPEN_ID", "PROFILE"});
        accessTokenDO.setAccessToken("ACCESS_TOKEN  ");
        Set<AccessTokenDO> accessTokens = new HashSet<AccessTokenDO>();
        accessTokens.add(accessTokenDO);

        when(tokenMgtDAO.getAllTimeAuthorizedClientIds(any(AuthenticatedUser.class))).thenReturn(clientIds);
        when(tokenMgtDAO.retrieveAccessTokens(anyString(), any(AuthenticatedUser.class), anyString(),
                anyBoolean())).thenReturn(accessTokens);
        when(tokenMgtDAO.retrieveLatestAccessToken(anyString(), any(AuthenticatedUser.class), anyString(), anyString()
                , anyBoolean())).thenThrow(new IdentityOAuth2Exception("Error Occured"));
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostUpdateCredentialByAdmin(username, new Object(), userStoreManager));
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}
