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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.dto.TokenBindingMetaDataDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.NetworkUtils;

import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuthError.AuthorizationResponsei18nKey.APPLICATION_NOT_FOUND;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getIdTokenIssuer;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;

@WithCarbonHome
@PrepareForTest({OAuthServerConfiguration.class, OAuthCache.class, IdentityUtil.class, OAuthConsumerDAO.class,
        OAuth2Util.class, OAuthComponentServiceHolder.class, AppInfoCache.class, IdentityConfigParser.class,
        PrivilegedCarbonContext.class, IdentityTenantUtil.class, CarbonUtils.class,
        IdentityCoreServiceComponent.class, NetworkUtils.class, IdentityApplicationManagementUtil.class,
        IdentityProviderManager.class, FederatedAuthenticatorConfig.class, FrameworkUtils.class, LoggerUtils.class,
        OAuth2ServiceComponentHolder.class, OAuthAdminServiceImpl.class, Base64Utils.class, OAuthUtils.class})
public class OAuth2UtilTest extends PowerMockIdentityBaseTest {

    private String[] scopeArraySorted = new String[]{"scope1", "scope2", "scope3"};
    private String[] scopeArrayUnSorted = new String[]{"scope2", "scope3", "scope1"};
    private String[] scopeArray = new String[]{"openid", "scope1", "scope2"};
    private String[] oidcScopes = new String[]{"address", "phone", "openid", "profile", "groups", "email"};
    private String scopeString = "scope1 scope2 scope3";
    private final String clientId = "dummyClientId";
    private final String clientSecret = "dummyClientSecret";
    private final String base64EncodedClientIdSecret = "ZHVtbXlDbGllbnRJZDpkdW1teUNsaWVudFNlY3JldA==";
    private final String base64EncodedClientIdInvalid = "ZHVtbXlDbGllbnRJZA==";
    private String authorizationCode = "testAuthorizationCode";
    private String tokenType = "testTokenType";
    private AuthenticatedUser authzUser;
    private final Integer clientTenantId = 1;
    private final String clientTenantDomain = "clientTenant";
    private Timestamp issuedTime;
    private Timestamp refreshTokenIssuedTime;
    private long validityPeriodInMillis;
    private long refreshTokenValidityPeriodInMillis;

    @Mock
    private OAuthServerConfiguration oauthServerConfigurationMock;

    @Mock
    private OAuthAuthzReqMessageContext authAuthzReqMessageContextMock;

    @Mock
    private OAuthTokenReqMessageContext oAuthTokenReqMessageContextMock;

    @Mock
    private OAuthCache oAuthCacheMock;

    @Mock
    private AppInfoCache appInfoCacheMock;

    @Mock
    private CacheEntry cacheEntryMock;

    @Mock
    private TokenPersistenceProcessor tokenPersistenceProcessorMock;

    @Mock
    private HashingPersistenceProcessor tokenHashPersistenceProcessorMock;

    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolderMock;

    @Mock
    private RealmService realmServiceMock;

    @Mock
    private TenantManager tenantManagerMock;

    @Mock
    private AuthorizationGrantHandler authorizationGrantHandlerMock;

    @Mock
    private ConfigurationContextService mockConfigurationContextService;

    @Mock
    private ConfigurationContext mockConfigurationContext;

    @Mock
    private AxisConfiguration mockAxisConfiguration;

    @Mock
    private FederatedAuthenticatorConfig mockFederatedAuthenticatorConfig = new FederatedAuthenticatorConfig();

    @Mock
    private IdentityProviderManager mockIdentityProviderManager;

    @Mock
    private IdentityProvider mockIdentityProvider;

    @Mock
    private AccessTokenDAO accessTokenDAO;

    @Mock
    OAuth2ServiceComponentHolder oAuth2ServiceComponentHolder;

    @Mock
    OAuthAdminServiceImpl oAuthAdminService;

    private KeyStore wso2KeyStore;

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        authzUser = new AuthenticatedUser();
        issuedTime = new Timestamp(System.currentTimeMillis());
        refreshTokenIssuedTime = new Timestamp(System.currentTimeMillis());
        validityPeriodInMillis = 3600000L;
        refreshTokenValidityPeriodInMillis = 3600000L;
        long timestampSkew = 3600L;
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(timestampSkew);
        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolderMock);
        mockStatic(PrivilegedCarbonContext.class);
        mockStatic(IdentityTenantUtil.class);
        PrivilegedCarbonContext privilegedCarbonContext = Mockito.mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);

        mockStatic(CarbonUtils.class);
        mockStatic(IdentityCoreServiceComponent.class);
        mockStatic(NetworkUtils.class);

        when(IdentityCoreServiceComponent.getConfigurationContextService()).thenReturn(mockConfigurationContextService);
        when(mockConfigurationContextService.getServerConfigContext()).thenReturn(mockConfigurationContext);
        when(mockConfigurationContext.getAxisConfiguration()).thenReturn(mockAxisConfiguration);
        when(CarbonUtils.getTransportPort(any(AxisConfiguration.class), anyString())).thenReturn(9443);
        when(CarbonUtils.getTransportProxyPort(any(AxisConfiguration.class), anyString())).thenReturn(9443);
        when(CarbonUtils.getManagementTransport()).thenReturn("https");

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(mockIdentityProviderManager);
        when(mockIdentityProviderManager.getResidentIdP(anyString())).thenReturn(mockIdentityProvider);
        try {
            when(NetworkUtils.getLocalHostname()).thenReturn("localhost");
        } catch (SocketException e) {
            // Mock behaviour, hence ignored
        }
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        when(IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
        when(IdentityTenantUtil.getLoginTenantId()).thenReturn(-1234);
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testAuthenticateClientCacheHit() throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(appDO);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        assertTrue(OAuth2Util.authenticateClient(clientId, clientSecret));
    }

    @Test
    public void testGetAuthzRequestContext() throws Exception {
        OAuth2Util.setAuthzRequestContext(authAuthzReqMessageContextMock);
        assertEquals(OAuth2Util.getAuthzRequestContext(), authAuthzReqMessageContextMock);
    }

    @Test
    public void testSetAuthzRequestContext() throws Exception {
        OAuth2Util.setAuthzRequestContext(authAuthzReqMessageContextMock);
        assertEquals(OAuth2Util.getAuthzRequestContext(), authAuthzReqMessageContextMock);
    }

    @Test
    public void testClearAuthzRequestContext() throws Exception {
        OAuth2Util.setAuthzRequestContext(authAuthzReqMessageContextMock);
        assertEquals(OAuth2Util.getAuthzRequestContext(), authAuthzReqMessageContextMock);
        OAuth2Util.clearAuthzRequestContext();
        assertNull(OAuth2Util.getAuthzRequestContext());
    }

    @Test
    public void testGetTokenRequestContext() throws Exception {
        OAuth2Util.setTokenRequestContext(oAuthTokenReqMessageContextMock);
        assertEquals(OAuth2Util.getTokenRequestContext(), oAuthTokenReqMessageContextMock);
    }

    @Test
    public void testSetTokenRequestContext() throws Exception {
        OAuth2Util.setTokenRequestContext(oAuthTokenReqMessageContextMock);
        assertEquals(OAuth2Util.getTokenRequestContext(), oAuthTokenReqMessageContextMock);
    }

    @Test
    public void testClearTokenRequestContext() throws Exception {

        OAuth2Util.setTokenRequestContext(oAuthTokenReqMessageContextMock);
        assertEquals(OAuth2Util.getTokenRequestContext(), oAuthTokenReqMessageContextMock);
        OAuth2Util.clearTokenRequestContext();
        assertNull(OAuth2Util.getTokenRequestContext());
    }

    @Test
    public void testGetClientTenatId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenantId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenantId.intValue());
    }

    @Test
    public void testSetClientTenatId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenantId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenantId.intValue());
    }

    @Test
    public void testClearClientTenantId() throws Exception {
        OAuth2Util.setClientTenatId(clientTenantId);
        assertEquals(OAuth2Util.getClientTenatId(), clientTenantId.intValue());
        OAuth2Util.clearClientTenantId();
        assertEquals(OAuth2Util.getClientTenatId(), -1);
    }

    @DataProvider(name = "BuildScopeString")
    public Object[][] buildScopeString() {
        return new Object[][]{
                // scope array
                // scope string
                {scopeArraySorted, scopeString},
                {scopeArrayUnSorted, scopeString},
                {null, null},
                {new String[0], ""}
        };
    }

    @Test(dataProvider = "BuildScopeString")
    public void testBuildScopeString(String[] scopeArray, String scopeString) throws Exception {
        assertEquals(OAuth2Util.buildScopeString(scopeArray), scopeString);
    }

    @DataProvider(name = "BuildScopeArray")
    public Object[][] buildScopeArray() {
        return new Object[][]{
                // scopes
                // response
                {scopeString, scopeArraySorted},
                {null, new String[0]}
        };
    }

    @Test(dataProvider = "BuildScopeArray")
    public void testBuildScopeArray(String scopes, String[] response) throws Exception {
        assertEquals(OAuth2Util.buildScopeArray(scopes), response);
    }

    @DataProvider(name = "AuthenticateClient")
    public Object[][] authenticateClient() {

        OAuthAppDO cachedOAuthappDO = new OAuthAppDO();
        cachedOAuthappDO.setOauthConsumerKey(clientId);
        cachedOAuthappDO.setOauthConsumerSecret(clientSecret);

        final String secretToFail = "4_EedLmABh_cPdmmYxCTwRdyDG5b";
        OAuthAppDO oauthAppToFailAuthentication = new OAuthAppDO();
        oauthAppToFailAuthentication.setOauthConsumerKey(clientId);
        oauthAppToFailAuthentication.setOauthConsumerSecret(secretToFail);

        // cacheResult
        // dummyClientSecret
        // expectedResult
        return new Object[][]{
                {null, null, false},
                {null, clientSecret, true},
                {cachedOAuthappDO, clientSecret, true},
                {null, secretToFail, false},
                {oauthAppToFailAuthentication, secretToFail, false},
        };
    }

    @Test(dataProvider = "AuthenticateClient")
    public void testAuthenticateClient(Object cacheResult, String clientSecretInDB, boolean expectedResult)
            throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecretInDB);

        // Mock the cache result
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn((OAuthAppDO) cacheResult);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        // Mock the DB result
        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, -1234)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        assertEquals(OAuth2Util.authenticateClient(clientId, clientSecret), expectedResult);
    }

    @Test(dataProvider = "AuthenticateClient")
    public void testAuthenticateClientWithHashPersistenceProcessor(Object cacheResult,
                                                                   String clientSecretInDB,
                                                                   boolean expectedResult) throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecretInDB);

        // Mock the cache result
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn((OAuthAppDO) cacheResult);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        // Mock the DB result
        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, -1234)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        TokenPersistenceProcessor hashingProcessor = mock(HashingPersistenceProcessor.class);
        when(hashingProcessor.getProcessedClientSecret(clientSecret)).thenReturn(clientSecret);

        when(oauthServerConfigurationMock.isClientSecretHashEnabled()).thenReturn(true);

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(hashingProcessor);
        assertEquals(OAuth2Util.authenticateClient(clientId, clientSecret), expectedResult);
    }

    @Test
    public void testAuthenticateClientWithAppTenant() throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);

        // Mock the cache result.
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        // Mock the DB result.
        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, clientTenantId)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(IdentityTenantUtil.getTenantId(clientTenantDomain)).thenReturn(clientTenantId);

        // Mock realm and tenant manager.
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(clientTenantDomain)).thenReturn(clientTenantId);
        when(tenantManagerMock.isTenantActive(clientTenantId)).thenReturn(true);

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        assertTrue(OAuth2Util.authenticateClient(clientId, clientSecret, clientTenantDomain));
    }

    @Test
    public void testIsHashDisabled() {
        when(OAuthServerConfiguration.getInstance().isClientSecretHashEnabled()).thenReturn(true);

        assertEquals(OAuth2Util.isHashDisabled(), false);
    }

    @Test
    public void testIsHashEnabled() {

        when(OAuthServerConfiguration.getInstance().isClientSecretHashEnabled()).thenReturn(true);
        assertTrue(OAuth2Util.isHashEnabled());
    }

    @DataProvider(name = "AuthenticateUsername")
    public Object[][] authenticateUsername() {

        CacheEntry cacheResult2 = cacheEntryMock;
        ClientCredentialDO cacheResult3 = new ClientCredentialDO("testUser");

        // isUsernameCaseSensitive
        // cacheResult
        // dummyClientSecret
        // dummyUserName
        // expectedResult
        return new Object[][]{
                {false, null, "4_EedLmABh_cPdmmYxCTwRdyDG5b", "testUser", null},
                {false, null, clientSecret, "testUser", "testUser"},
                {false, null, "4_EedLmABh_cPdmmYxCTwRdyDG5b", null, null},
                {false, null, clientSecret, null, null},
                {true, cacheResult2, "4_EedLmABh_cPdmmYxCTwRdyDG5b", "testUser", null},
                {true, cacheResult2, clientSecret, "testUser", "testUser"},
                {true, cacheResult2, "4_EedLmABh_cPdmmYxCTwRdyDG5b", null, null},
                {true, cacheResult2, clientSecret, null, null},
                {true, cacheResult3, clientSecret, "testUser", "testUser"}
        };
    }

    @Test(dataProvider = "AuthenticateUsername")
    public void testGetAuthenticatedUsername(boolean isUsernameCaseSensitive,
                                             Object cacheResult,
                                             String clientSecretInDB,
                                             String dummyUserName,
                                             String expectedResult) throws Exception {


        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(isUsernameCaseSensitive);

        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCacheMock);
        when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class))).thenReturn((CacheEntry) cacheResult);
        OAuthConsumerDAO oAuthConsumerDAO = mock(OAuthConsumerDAO.class);
        whenNew(OAuthConsumerDAO.class).withNoArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getAuthenticatedUsername(anyString(), anyString())).thenReturn(dummyUserName);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecretInDB);

        // Mock the cache result
        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        // Mock the DB result
        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, -1234)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());

        assertEquals(OAuth2Util.getAuthenticatedUsername(clientId, clientSecret), expectedResult);
    }

    @Test
    public void testGetPersistenceProcessorWithIdentityOAuth2Exception() throws IdentityOAuth2Exception {

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenThrow(IdentityOAuth2Exception.class);
        assertNotNull(OAuth2Util.getPersistenceProcessor());
    }

    @Test
    public void testBuildCacheKeyStringForAuthzCode() throws Exception {

        String authzCode = "testAuthzCode";
        String testAuthzCode = clientId + ":" + authzCode;
        assertEquals(OAuth2Util.buildCacheKeyStringForAuthzCode(clientId, authzCode), testAuthzCode);
    }

    @Test
    public void testBuildCacheKeyStringForToken() throws Exception {

        String authorizedUser = "testAuthzUser";
        String scope = "testScope";
        String userId = "4d458e40-afa4-466f-b668-b01cfbfba827";
        mockStatic(IdentityUtil.class);
        mockStatic(FrameworkUtils.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        when(FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString())).thenReturn(userId);
        String expected = clientId + ":" + userId + ":" + scope;
        assertEquals(OAuth2Util.buildCacheKeyStringForToken(clientId, scope, authorizedUser), expected);
    }

    @Test
    public void testBuildCacheKeyStringForTokenWithAuthenticatedIDP() throws Exception {

        String authorizedUser = "testAuthzUser";
        String scope = "testScope";
        String authenticatedIDP = "testAuthenticatedIDP";
        String userId = "4d458e40-afa4-466f-b668-b01cfbfba827";
        mockStatic(IdentityUtil.class);
        mockStatic(FrameworkUtils.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        when(FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString())).thenReturn(userId);
        String expected = clientId + ":" + userId + ":" + scope + ":" + authenticatedIDP;

        assertEquals(OAuth2Util.buildCacheKeyStringForToken(clientId, scope, authorizedUser, authenticatedIDP),
                expected);
    }

    @Test
    public void testBuildCacheKeyStringForTokenWithTokenBindingReference() throws Exception {

        String authorizedUser = "testAuthzUser";
        String scope = "testScope";
        String authenticatedIDP = "testAuthenticatedIDP";
        String tokenBindingReference = "testTokenBindingReference";
        String expected = clientId + ":" + authorizedUser + ":" + scope + ":" + authenticatedIDP + ":"
                + tokenBindingReference;

        assertEquals(OAuth2Util.buildCacheKeyStringForTokenWithUserId(clientId, scope, authorizedUser,
                authenticatedIDP, tokenBindingReference), expected);
    }

    @Test
    public void testValidateAccessTokenDO() throws Exception {

        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertEquals(OAuth2Util.validateAccessTokenDO(accessTokenDO), accessTokenDO);
    }

    @DataProvider(name = "booleanData")
    public Object[][] booleanData() {
        return new Object[][]{
                {false, false},
                {true, true}
        };
    }

    @Test(dataProvider = "booleanData")
    public void testCheckAccessTokenPartitioningEnabled(boolean value, boolean expectedResult) throws Exception {
        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled()).thenReturn(value);
        assertEquals(OAuth2Util.checkAccessTokenPartitioningEnabled(), expectedResult);
    }

    @Test(dataProvider = "booleanData")
    public void testCheckUserNameAssertionEnabled(boolean value, boolean expectedResult) throws Exception {
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(value);
        assertEquals(OAuth2Util.checkUserNameAssertionEnabled(), expectedResult);
    }

    @Test
    public void testGetAccessTokenPartitioningDomains() throws Exception {
        String accessTokenPartitioningDomains = "A:foo.com , B:bar.com";
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains())
                .thenReturn(accessTokenPartitioningDomains);
        assertEquals(OAuth2Util.getAccessTokenPartitioningDomains(), accessTokenPartitioningDomains);
    }

    @DataProvider(name = "accessTokenPartitioningDomainsData")
    public Object[][] accessTokenPartitioningDomainsData() {
        return new Object[][]{
                // accessTokenPartitioningDomains
                // expectedResult
                {"A:foo.com , B:bar.com", 2},
                {null, 0}
        };
    }

    @Test(dataProvider = "accessTokenPartitioningDomainsData")
    public void testGetAvailableUserStoreDomainMappings(String accessTokenPartitioningDomains, int expectedResult)
            throws Exception {

        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains())
                .thenReturn(accessTokenPartitioningDomains);
        Map<String, String> userStoreDomainMap = OAuth2Util.getAvailableUserStoreDomainMappings();
        assertEquals(userStoreDomainMap.size(), expectedResult);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAvailableUserStoreDomainMappings1() throws Exception {
        String accessTokenPartitioningDomains = "A: , B:bar.com";
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains())
                .thenReturn(accessTokenPartitioningDomains);
        OAuth2Util.getAvailableUserStoreDomainMappings();
    }

    @DataProvider(name = "accessMappedUserStoreDomainData")
    public Object[][] accessMappedUserStoreDomainData() {
        return new Object[][]{
                // accessTokenPartitioningDomains
                // userStoreDomain
                // expectedResult
                {"A:foo.com, B:bar.com", "foo.com", "A"},
                {"A:foo.com , B:bar.com", "bar.com", "B"},
                {"A:foo.com , B:bar.com", null, null},
                {"A:foo.com , B:bar.com", "test.com", "test.com"}
        };
    }

    @Test(dataProvider = "accessMappedUserStoreDomainData")
    public void testGetMappedUserStoreDomain(String accessTokenPartitioningDomains, String userStoreDomain,
                                             String expectedResult) throws Exception {

        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains())
                .thenReturn(accessTokenPartitioningDomains);
        assertEquals(OAuth2Util.getMappedUserStoreDomain(userStoreDomain), expectedResult);
    }

    @DataProvider(name = "TestGetPartitionedTableByUserStoreDataProvider")
    public Object[][] getPartitionedTableByUserStoreData() {
        return new Object[][]{
                // tableName
                // userstoreDomain
                // partionedTableName
                {"IDN_OAUTH2_ACCESS_TOKEN", "H2", "IDN_OAUTH2_ACCESS_TOKEN_A"},
                {"IDN_OAUTH2_ACCESS_TOKEN", "AD", "IDN_OAUTH2_ACCESS_TOKEN_B"},
                {"IDN_OAUTH2_ACCESS_TOKEN", "PRIMARY", "IDN_OAUTH2_ACCESS_TOKEN"},
                {"IDN_OAUTH2_ACCESS_TOKEN", "LDAP", "IDN_OAUTH2_ACCESS_TOKEN_LDAP"},
                {"IDN_OAUTH2_ACCESS_TOKEN_SCOPE", "H2", "IDN_OAUTH2_ACCESS_TOKEN_SCOPE_A"},
                {null, "H2", null},
                {"IDN_OAUTH2_ACCESS_TOKEN", null, "IDN_OAUTH2_ACCESS_TOKEN"}
        };
    }

    @Test(dataProvider = "TestGetPartitionedTableByUserStoreDataProvider")
    public void testGetPartitionedTableByUserStore(String tableName, String userstoreDomain, String partionedTableName)
            throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        assertEquals(OAuth2Util.getPartitionedTableByUserStore(tableName, userstoreDomain), partionedTableName);
    }

    @DataProvider(name = "TokenPartitionedSqlByUserStoreData")
    public Object[][] tokenPartitionedSqlByUserStoreData() {
        String sql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE ACCESS_TOKEN = ?";
        String partitionedSql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN_A WHERE ACCESS_TOKEN = ?";
        return new Object[][]{
                // accessTokenPartitioningEnabled
                // assertionsUserNameEnabled
                // sql
                // partitionedSql
                {false, false, sql, sql},
                {true, false, sql, sql},
                {false, true, sql, sql},
                {true, true, sql, partitionedSql}
        };
    }

    @Test(dataProvider = "TokenPartitionedSqlByUserStoreData")
    public void testGetTokenPartitionedSqlByUserStore(boolean accessTokenPartitioningEnabled,
                                                      boolean assertionsUserNameEnabled, String sql,
                                                      String partitionedSql) throws Exception {

        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled())
                .thenReturn(accessTokenPartitioningEnabled);
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(assertionsUserNameEnabled);
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        assertEquals(OAuth2Util.getTokenPartitionedSqlByUserStore(sql, "H2"), partitionedSql);
    }

    @DataProvider(name = "TokenPartitionedSqlByUserIdData")
    public Object[][] tokenPartitionedSqlByUserIdData() {
        String sql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE ACCESS_TOKEN = ?";
        String partitionedSql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN_A WHERE ACCESS_TOKEN = ?";
        return new Object[][]{
                // accessTokenPartitioningEnabled
                // assertionsUserNameEnabled
                // sql
                // username
                // partitionedSql
                {false, false, sql, null, sql},
                {true, false, sql, "H2/testUser", sql},
                {false, true, sql, null, sql},
                {true, true, sql, "H2/testUser", partitionedSql},
                {true, true, sql, null, sql},

        };
    }

    @Test(dataProvider = "TokenPartitionedSqlByUserIdData")
    public void testGetTokenPartitionedSqlByUserId(boolean accessTokenPartitioningEnabled,
                                                   boolean assertionsUserNameEnabled, String sql,
                                                   String username, String partitionedSql) throws Exception {

        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled())
                .thenReturn(accessTokenPartitioningEnabled);
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(assertionsUserNameEnabled);
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        assertEquals(OAuth2Util.getTokenPartitionedSqlByUserId(sql, username), partitionedSql);
    }

    @DataProvider(name = "TokenPartitionedSqlByTokenData")
    public Object[][] tokenPartitionedSqlByTokenData() {
        String sql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE ACCESS_TOKEN = ?";
        String partitionedSql = "SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN_A WHERE ACCESS_TOKEN = ?";
        String apiKey = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OkgyL2FkbWlu";

        return new Object[][]{
                // accessTokenPartitioningEnabled
                // assertionsUserNameEnabled
                // isTokenLoggable
                // sql
                // apiKey
                // partitionedSql
                {false, false, true, sql, null, sql},
                {true, false, false, sql, apiKey, sql},
                {false, true, true, sql, null, sql},
                {true, true, false, sql, apiKey, partitionedSql},
                {true, true, true, sql, apiKey, partitionedSql},
        };
    }

    @Test(dataProvider = "TokenPartitionedSqlByTokenData")
    public void testGetTokenPartitionedSqlByToken(boolean accessTokenPartitioningEnabled,
                                                  boolean assertionsUserNameEnabled, boolean isTokenLoggable, String
                                                          sql,
                                                  String apiKey, String partitionedSql) throws Exception {

        when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled())
                .thenReturn(accessTokenPartitioningEnabled);
        when(oauthServerConfigurationMock.isUserNameAssertionEnabled()).thenReturn(assertionsUserNameEnabled);
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        when(IdentityUtil.isTokenLoggable(anyString())).thenReturn(isTokenLoggable);
        assertEquals(OAuth2Util.getTokenPartitionedSqlByToken(sql, apiKey), partitionedSql);
    }

    @DataProvider(name = "UserStoreDomainFromUserIdData")
    public Object[][] userStoreDomainFromUserIdData() {
        return new Object[][]{
                // userId
                // userStoreDomain
                {"H2/admin", "A"},
                {"admin", null}
        };
    }

    @Test(dataProvider = "UserStoreDomainFromUserIdData")
    public void testGetUserStoreDomainFromUserId(String userId, String userStoreDomain) throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        assertEquals(OAuth2Util.getUserStoreDomainFromUserId(userId), userStoreDomain);
    }

    @DataProvider(name = "UserStoreDomainFromAccessTokenData")
    public Object[][] userStoreDomainFromAccessTokenData() {
        String apiKey1 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OkgyL2FkbWlu";
        String apiKey2 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OmFkbWlu";

        return new Object[][]{
                // apiKey
                // userStoreDomain
                {apiKey1, "H2"},
                {apiKey2, null}
        };
    }

    @Test(dataProvider = "UserStoreDomainFromAccessTokenData")
    public void testGetUserStoreDomainFromAccessToken(String apiKey, String userStoreDomain) throws Exception {
        assertEquals(OAuth2Util.getUserStoreDomainFromAccessToken(apiKey), userStoreDomain);
    }

    @DataProvider(name = "AccessTokenStoreTableFromUserIdData")
    public Object[][] accessTokenStoreTableFromUserIdData() {
        return new Object[][]{
                // userId
                // accessTokenStoreTable
                {"H2/admin", "IDN_OAUTH2_ACCESS_TOKEN_A"},
                {"admin", "IDN_OAUTH2_ACCESS_TOKEN"},
                {null, "IDN_OAUTH2_ACCESS_TOKEN"}
        };
    }

    @Test(dataProvider = "AccessTokenStoreTableFromUserIdData")
    public void testGetAccessTokenStoreTableFromUserId(String userId, String accessTokenStoreTable) throws Exception {
        when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        assertEquals(OAuth2Util.getAccessTokenStoreTableFromUserId(userId), accessTokenStoreTable);
    }

    @Test
    public void testGetAccessTokenStoreTableFromAccessToken() throws Exception {
        String apiKey = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OmFkbWlu";
        String accessTokenStoreTable = "IDN_OAUTH2_ACCESS_TOKEN";
        assertEquals(OAuth2Util.getAccessTokenStoreTableFromAccessToken(apiKey), accessTokenStoreTable);
    }

    @DataProvider(name = "UserIdFromAccessTokenData")
    public Object[][] userIdFromAccessTokenData() {
        String apiKey1 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2OmFkbWlu";
        String apiKey2 = "NDk1MmI0NjctODZiMi0zMWRmLWI2M2MtMGJmMjVjZWM0Zjg2";

        return new Object[][]{
                // apiKey
                // userId
                {apiKey1, "admin"},
                {apiKey2, null}
        };
    }

    @Test(dataProvider = "UserIdFromAccessTokenData")
    public void testGetUserIdFromAccessToken(String apiKey, String userId) throws Exception {
        assertEquals(OAuth2Util.getUserIdFromAccessToken(apiKey), userId);
    }

    @DataProvider(name = "TestGetTokenExpireTimeMillisDataProvider")
    public Object[][] getTokenExpireTimeMillisData() {
        return new Object[][] {
                {issuedTime, refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis},
                // Refresh token validity period is infinite
                {issuedTime, refreshTokenIssuedTime, validityPeriodInMillis, -1000L}
        };
    }

    @Test(dataProvider = "TestGetTokenExpireTimeMillisDataProvider")
    public void testGetTokenExpireTimeMillis(Timestamp issuedTime, Timestamp refreshTokenIssuedTime, long
            validityPeriodInMillis, long refreshTokenValidityPeriodInMillis) throws Exception {

        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertTrue(OAuth2Util.getTokenExpireTimeMillis(accessTokenDO) > 1000);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetTokenExpireTimeMillis2() throws Exception {
        OAuth2Util.getTokenExpireTimeMillis(null);
    }

    @Test
    public void testGetRefreshTokenExpireTimeMillis() throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertTrue(OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO) > 1000);
    }

    @Test
    public void testGetRefreshTokenExpireTimeMillis2() throws Exception {
        refreshTokenValidityPeriodInMillis = -100;
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertEquals(OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO), -1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetRefreshTokenExpireTimeMillis3() throws Exception {
        OAuth2Util.getRefreshTokenExpireTimeMillis(null);
    }

    @Test
    public void testGetAccessTokenExpireMillis() throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        assertTrue(OAuth2Util.getAccessTokenExpireMillis(accessTokenDO) > 1000);
    }

    @DataProvider(name = "BooleanData2")
    public Object[][] booleanData2() {
        return new Object[][]{
                // isTokenLoggable
                {true},
                {false}
        };
    }

    @Test(dataProvider = "BooleanData2")
    public void testGetAccessTokenExpireMillis2(boolean isTokenLoggable) throws Exception {
        validityPeriodInMillis = -100;
        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        String accessToken = "dummyAccessToken";
        accessTokenDO.setAccessToken(accessToken);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
        when(IdentityUtil.isTokenLoggable(anyString())).thenReturn(isTokenLoggable);
        assertEquals(OAuth2Util.getAccessTokenExpireMillis(accessTokenDO), -1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetAccessTokenExpireMillis3() throws Exception {
        OAuth2Util.getAccessTokenExpireMillis(null);
    }

    @Test
    public void testCalculateValidityInMillis() throws Exception {

        long issuedTimeInMillis = System.currentTimeMillis() - 5000;
        long validityPeriodMillis = 100000;
        assertTrue(OAuth2Util.calculateValidityInMillis(issuedTimeInMillis, validityPeriodMillis) > 0);
    }

    @Test
    public void testGetTenantId() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        assertEquals(OAuth2Util.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME),
                MultitenantConstants.SUPER_TENANT_ID);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTenantId1() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenThrow(new UserStoreException());

        OAuth2Util.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Test
    public void testGetTenantDomain() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        assertEquals(OAuth2Util.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID),
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTenantDomain1() throws Exception {
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getDomain(anyInt())).thenThrow(new UserStoreException());

        OAuth2Util.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID);
    }

    @Test
    public void testGetTenantIdFromUserName() throws Exception {

        String userName = "admin" + CarbonConstants.ROLE_TENANT_DOMAIN_SEPARATOR + MultitenantConstants
                .SUPER_TENANT_DOMAIN_NAME;
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        assertEquals(OAuth2Util.getTenantIdFromUserName(userName), MultitenantConstants.SUPER_TENANT_ID);
    }

    @Test
    public void testHashScopes() throws Exception {
        String hashScopes = DigestUtils.md5Hex(scopeString);
        assertEquals(OAuth2Util.hashScopes(scopeArraySorted), hashScopes);
    }

    @DataProvider(name = "ScopesData")
    public Object[][] scopesData() {
        String scope = "testScope";
        String hashScope = DigestUtils.md5Hex(scope);

        return new Object[][]{
                // scope
                // hashScope
                {scope, hashScope},
                {null, null}
        };
    }

    @Test(dataProvider = "ScopesData")
    public void testHashScopes1(String scope, String hashScope) throws Exception {
        assertEquals(OAuth2Util.hashScopes(scope), hashScope);
    }

    @Test
    public void testGetUserFromUserName() throws Exception {
        AuthenticatedUser user = OAuth2Util.getUserFromUserName("H2/testUser");
        assertNotNull(user, "User should be not null.");
        assertEquals(user.getUserName(), "testUser");
        assertEquals(user.getTenantDomain(), MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(user.getUserStoreDomain(), "H2");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetUserFromUserName1() throws Exception {
        OAuth2Util.getUserFromUserName("");
    }

    @DataProvider(name = "IDTokenIssuerData")
    public Object[][] idTokenIssuerData() {
        return new Object[][]{
                // oidcIDTokenIssuer
                // oauth2TokenEPUrl
                // issuer
                {"https://localhost:9443/testIssuer", "", "https://localhost:9443/testIssuer"},
                {"", "https://localhost:9443/testIssuer", "https://localhost:9443/oauth2/token"},
                {"", "", "https://localhost:9443/oauth2/token"}
        };
    }

    @Test(dataProvider = "IDTokenIssuerData")
    public void testGetIDTokenIssuer(String oidcIDTokenIssuer, String oauth2TokenEPUrl, String issuer) {

        String serverUrl = "https://localhost:9443/oauth2/token";
        when(oauthServerConfigurationMock.getOpenIDConnectIDTokenIssuerIdentifier()).thenReturn(oidcIDTokenIssuer);
        when(oauthServerConfigurationMock.getOAuth2TokenEPUrl()).thenReturn(oauth2TokenEPUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2TokenEPUrl).get())
                .thenReturn(serverUrl);

        assertEquals(OAuth2Util.getIDTokenIssuer(), issuer);
    }

    @DataProvider(name = "TenantQualifiedURLsIDTokenIssuerData")
    public Object[][] tenantQualifiedURLsIdTokenIssuerData() {

        return new Object[][]{
                // tenant-qualified URL support
                // OIDC Config url
                // tenant domain
                // expected
                {false, "https://localhost:9443/testIssuer", "wso2.com", "https://localhost:9443/testIssuer"},
                {false, "https://localhost:9443/testIssuer", "", "https://localhost:9443/testIssuer"},
                {true, "https://localhost:9443/testIssuer", "", "https://localhost:9443/oauth2/token"},
                {true, "https://localhost:9443/testIssuer", "wso2.com", "https://localhost:9443/t/wso2" +
                        ".com/oauth2/token"}
        };
    }

    @Test(dataProvider = "TenantQualifiedURLsIDTokenIssuerData")
    public void testGetTenantQualifiedIDTokenIssuer(boolean enableTenantURLSupport, String oidcConfigUrl,
                                                    String tenantDomain, String expected) throws Exception {

        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");

        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[0];
        when(mockIdentityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);

        mockStatic(IdentityApplicationManagementUtil.class);
        mockStatic(FederatedAuthenticatorConfig.class);
        Property property = mock(Property.class);
        Property[] properties = new Property[0];
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs,
                "openidconnect")).thenReturn(mockFederatedAuthenticatorConfig);
        when(mockFederatedAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(IdentityApplicationManagementUtil.getProperty(properties, "IdPEntityId")).thenReturn(property);
        when(property.getValue()).thenReturn(oidcConfigUrl);
        assertEquals(getIdTokenIssuer(tenantDomain), expected);

    }

    @DataProvider(name = "OAuthURLData")
    public Object[][] oauthURLData() {

        return new Object[][]{
                // configUrl
                // serverUrl
                // oauthUrl
                {"https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "https://localhost:9443/testUrl"},
                {"", "https://localhost:9443/testUrl", "https://localhost:9443/testUrl"}
        };
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1RequestTokenUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth1RequestTokenUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth1RequestTokenUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1AuthorizeUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth1AuthorizeUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth1AuthorizeUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1AccessTokenUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth1AccessTokenUrl()).thenReturn(configUrl);
        getOAuthURL(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth1AccessTokenUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2AuthzEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth2AuthzEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2AuthzEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2AuthzEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2ParEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth2ParEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2ParEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2ParEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2TokenEPUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        when(oauthServerConfigurationMock.getOAuth2TokenEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2TokenEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2TokenEPUrl(), oauthUrl);
    }

    @DataProvider(name = "OAuthURLData2")
    public Object[][] oauthURLData2() {
        return new Object[][]{
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {"https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain", "https://localhost" +
                        ":9443/t/testDomain/testUrl"},
                {"", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
                {"", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/testUrl"}
        };
    }

    @DataProvider(name = "OAuthJWKSPageUrlData")
    public Object[][] oAuthJWKSPageUrlData() {

        return new Object[][]{
                // enableTenantURLSupport
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {true, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/jwks"},
                {true, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/oauth2/jwks"},
                {false, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
        };
    }

    @Test(dataProvider = "OAuthJWKSPageUrlData")
    public void testGetOAuth2JWKSPageUrl(Boolean enableTenantURLSupport, String configUrl, String serverUrl,
                                         String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOAuth2JWKSPageUrl()).thenReturn(configUrl);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2JWKSPageUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(tenantDomain), oauthUrl);
    }

    @DataProvider(name = "OAuthDCREPData")
    public Object[][] oAuthDCREPData() {

        return new Object[][]{
                // enableTenantURLSupport
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {true, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/api/identity/oauth2/dcr/v1.1/register"},
                {true, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/api/identity/oauth2/dcr/v1.1/register"},
                {true, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/api/identity/oauth2/dcr/v1.1/register"},
                {false, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
        };
    }

    @Test(dataProvider = "OAuthDCREPData")
    public void testGetOAuth2DCREPUrl(Boolean enableTenantURLSupport, String configUrl, String serverUrl,
                                      String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOAuth2DCREPUrl()).thenReturn(configUrl);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2DCREPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2DCREPUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOAuth2JWKSPageUrlLegacy(String configUrl, String serverUrl,
                                               String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOAuth2JWKSPageUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2JWKSPageUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOAuth2DCREPUrlLegacy(String configUrl, String serverUrl,
                                            String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOAuth2DCREPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2DCREPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2DCREPUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOidcWebFingerEPUrlLegacy(String configUrl, String serverUrl, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOidcWebFingerEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOidcWebFingerEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOidcWebFingerEPUrl(), oauthUrl);
    }

    @DataProvider(name = "OAuthWebFingerEPData")
    public Object[][] oAuthWebFingerEPData() {

        return new Object[][]{
                // enableTenantURLSupport
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {true, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/.well-known/webfinger"},
                {true, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/.well-known/webfinger"},
                {true, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/.well-known/webfinger"},
                {false, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
        };
    }

    @Test(dataProvider = "OAuthWebFingerEPData")
    public void testGetOidcWebFingerEPUrl(boolean enableTenantURLSupport, String configUrl, String serverUrl,
                                          String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOidcWebFingerEPUrl()).thenReturn(configUrl);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOidcWebFingerEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOidcWebFingerEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOidcDiscoveryEPUrl(String configUrl, String serverUrl,
                                          String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOidcDiscoveryUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOidcDiscoveryUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOidcDiscoveryEPUrl(tenantDomain), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2UserInfoEPUrlLegacy(String configUrl, String serverUrl, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOauth2UserInfoEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOauth2UserInfoEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2UserInfoEPUrl(), oauthUrl);
    }

    @DataProvider(name = "OAuthUserInfoEPData")
    public Object[][] oAuthUserInfoEPData() {

        return new Object[][]{
                // enableTenantURLSupport
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {true, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/userinfo"},
                {true, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/oauth2/userinfo"},
                {true, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/userinfo"},
                {false, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
        };
    }

    @Test(dataProvider = "OAuthUserInfoEPData")
    public void testGetOAuth2UserInfoEPUrl(boolean enableTenantURLSupport, String configUrl, String serverUrl,
                                           String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOauth2UserInfoEPUrl()).thenReturn(configUrl);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOauth2UserInfoEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2UserInfoEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth2RevocationEPUrlLegacy(String configUrl, String serverUrl, String oauthUrl)
            throws Exception {

        when(oauthServerConfigurationMock.getOauth2RevocationEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOauth2RevocationEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2RevocationEPUrl(), oauthUrl);
    }

    @DataProvider(name = "OAuthRevocationEPData")
    public Object[][] oAuthRevocationEPData() {

        return new Object[][]{
                // enableTenantURLSupport
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {true, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/revoke"},
                {true, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/oauth2/revoke"},
                {true, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/revoke"},
                {false, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
        };
    }

    @Test(dataProvider = "OAuthRevocationEPData")
    public void testGetOAuth2RevocationEPUrl(boolean enableTenantURLSupport, String configUrl, String serverUrl,
                                             String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOauth2RevocationEPUrl()).thenReturn(configUrl);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOauth2RevocationEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2RevocationEPUrl(), oauthUrl);
    }

    @Test(dataProvider = "OAuthURLData2")
    public void testGetOAuth2IntrospectionEPUrlLegacy(String configUrl, String serverUrl,
                                                      String tenantDomain, String oauthUrl)
            throws Exception {

        when(oauthServerConfigurationMock.getOauth2IntrospectionEPUrl()).thenReturn(configUrl);
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOauth2IntrospectionEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2IntrospectionEPUrl(tenantDomain), oauthUrl);
    }

    @DataProvider(name = "OAuthIntrospectionEPData")
    public Object[][] oAuthIntrospectionEPData() {

        return new Object[][]{
                // enableTenantURLSupport
                // configUrl
                // serverUrl
                // tenantDomain
                // oauthUrl
                {true, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/introspect"},
                {true, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/oauth2/introspect"},
                {true, "", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/oauth2/introspect"},
                {false, "https://localhost:9443/testUrl", "https://localhost:9443/testUrl", "testDomain",
                        "https://localhost:9443/t/testDomain/testUrl"},
                {false, "", "https://localhost:9443/testUrl", "",
                        "https://localhost:9443/testUrl"},
        };
    }

    @Test(dataProvider = "OAuthIntrospectionEPData")
    public void testGetOAuth2IntrospectionEPUrl(boolean enableTenantURLSupport, String configUrl, String serverUrl,
                                                String tenantDomain, String oauthUrl) throws Exception {

        when(oauthServerConfigurationMock.getOauth2IntrospectionEPUrl()).thenReturn(configUrl);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(enableTenantURLSupport);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
        when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOauth2IntrospectionEPUrl).get())
                .thenReturn(serverUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2IntrospectionEPUrl(tenantDomain), oauthUrl);
    }

    @DataProvider(name = "OIDCConsentPageURLData")
    public Object[][] getOIDCConsentUrlData() {

        return new Object[][]{
                // URL from file based config , Expected error page URL
                {"https://localhost:9443/authenticationendpoint/custom_oidc_consent.do",
                        "https://localhost:9443/authenticationendpoint/custom_oidc_consent.do"},
                {"", "https://localhost:9443/authenticationendpoint/oauth2_consent.do"}
        };
    }

    @Test(dataProvider = "OIDCConsentPageURLData")
    public void testGetOIDCConsentPageUrl(String configUrl, String expectedUrl) throws Exception {

        when(oauthServerConfigurationMock.getOIDCConsentPageUrl()).thenReturn(configUrl);
        assertEquals(OAuth2Util.OAuthURL.getOIDCConsentPageUrl(), expectedUrl);
    }

    @DataProvider(name = "OAuthConsentPageURLData")
    public Object[][] getOAuthConsentUrlData() {

        return new Object[][]{
                // URL from file based config , Expected error page URL
                {"https://localhost:9443/authenticationendpoint/custom_consent.do",
                        "https://localhost:9443/authenticationendpoint/custom_consent.do"},
                {"", "https://localhost:9443/authenticationendpoint/oauth2_authz.do"}
        };
    }

    @Test(dataProvider = "OAuthConsentPageURLData")
    public void testGetOAuth2ConsentPageUrl(String configUrl, String expectedUrl) throws Exception {

        when(oauthServerConfigurationMock.getOauth2ConsentPageUrl()).thenReturn(configUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2ConsentPageUrl(), expectedUrl);
    }

    @DataProvider(name = "OAuthErrorPageData")
    public Object[][] getOAuthErrorPageUrlData() {

        return new Object[][]{
                // URL from file based config , Expected error page URL
                {"https://localhost:9443/authenticationendpoint/custom_oauth_error.do",
                        "https://localhost:9443/authenticationendpoint/custom_oauth_error.do"},
                {"", "https://localhost:9443/authenticationendpoint/oauth2_error.do"}
        };
    }

    @Test(dataProvider = "OAuthErrorPageData")
    public void testGetOAuth2ErrorPageUrl(String configUrl, String expectedUrl) throws Exception {

        when(OAuthServerConfiguration.getInstance().getOauth2ErrorPageUrl()).thenReturn(configUrl);
        assertEquals(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl(), expectedUrl);
    }

    private void getOAuthURL(String serverUrl) {
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(serverUrl);
    }

    @DataProvider(name = "ScopesSet")
    public Object[][] scopesSet() {
        Set<String> scopesSet1 = new HashSet<>((Arrays.asList(scopeArray)));
        Set<String> scopesSet2 = new HashSet<>((Arrays.asList(scopeArraySorted)));

        return new Object[][]{
                // scopes
                // expected result
                {scopesSet1, true},
                {scopesSet2, false}
        };
    }

    @Test(dataProvider = "ScopesSet")
    public void testIsOIDCAuthzRequest(Set<String> scopes, boolean expectedResult) throws Exception {
        assertEquals(OAuth2Util.isOIDCAuthzRequest(scopes), expectedResult);
    }

    @DataProvider(name = "ScopesArray")
    public Object[][] scopesArray() {
        return new Object[][]{
                // scopes
                // expected result
                {scopeArray, true},
                {scopeArraySorted, false}
        };
    }

    @Test(dataProvider = "ScopesArray")
    public void testIsOIDCAuthzRequest1(String[] scopes, boolean expectedResult) throws Exception {
        assertEquals(OAuth2Util.isOIDCAuthzRequest(scopes), expectedResult);
    }

    @DataProvider(name = "PKCEData")
    public Object[][] pkceData() {
        return new Object[][]{
                // codeVerifierLength
                // expected result
                {42, false},
                {129, false},
                {77, true}
        };
    }

    @Test(dataProvider = "PKCEData")
    public void testValidatePKCECodeVerifier(int codeVerifierLength, boolean expectedResult) throws Exception {
        String codeVerifier = generateCodeVerifier(codeVerifierLength);
        assertEquals(OAuth2Util.validatePKCECodeVerifier(codeVerifier), expectedResult);
    }

    @DataProvider(name = "PKCECodeChallengeData")
    public Object[][] pkceCodeChallengeData() {
        return new Object[][]{
                // codeVerifierLength
                // codeChallengeMethod
                // expected result
                {42, null, false},
                {129, null, false},
                {77, null, true},
                {42, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false},
                {129, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false},
                {77, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, true},
                {77, "testCodeChallengeMethod", false},
                {43, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, true},
                {40, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, false}
        };
    }

    @Test(dataProvider = "PKCECodeChallengeData")
    public void testValidatePKCECodeChallenge(int codeVerifierLength, String codeChallengeMethod,
                                              boolean expectedResult) throws Exception {
        String codeChallenge = generateCodeVerifier(codeVerifierLength);
        assertEquals(OAuth2Util.validatePKCECodeChallenge(codeChallenge, codeChallengeMethod), expectedResult);
    }

    @Test
    public void testIsPKCESupportEnabled() throws Exception {
        assertFalse(OAuth2Util.isPKCESupportEnabled());
    }

    @DataProvider(name = "pkceData")
    public Object[][] createPKCEData() {

        String verificationCode = generateCodeVerifier(77);
        return new Object[][]{
                {verificationCode, verificationCode, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, true},
                {"dummyReferenceCodeChallenge", verificationCode, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false},
                {"dummyReferenceCodeChallenge", verificationCode, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, false},
                {verificationCode, verificationCode, null, true},
                {"", null, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, true},
        };
    }

    @Test(dataProvider = "pkceData")
    public void doPKCEValidation(String referenceCodeChallenge, String verificationCode,
                                 String challengeMethod, boolean expected) throws Exception {

        OAuthAppDO oAuthApp = new OAuthAppDO();
        oAuthApp.setPkceSupportPlain(true);
        assertEquals(OAuth2Util.doPKCEValidation(referenceCodeChallenge, verificationCode,
                challengeMethod, oAuthApp), expected);
    }

    @DataProvider(name = "invalidPKCEData")
    public Object[][] createPKCEInvalidData() {

        String verificationCode = generateCodeVerifier(77);
        String invalidVerificationCode = generateCodeVerifier(42);
        String invalidChallengeMethod = "dummyChallengeMethod";
        return new Object[][]{
                {verificationCode, null, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, true, false,
                        "No PKCE code verifier found.PKCE is mandatory for this oAuth 2.0 application."},
                {verificationCode, null, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false, false,
                        "Empty PKCE code_verifier sent. This authorization code " +
                                "requires a PKCE verification to obtain an access token."},
                {verificationCode, null, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false, true,
                        "Empty PKCE code_verifier sent. This authorization code " +
                                "requires a PKCE verification to obtain an access token."},
                {verificationCode, verificationCode, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, true, false,
                        "This application does not allow 'plain' transformation algorithm."},
                {verificationCode, invalidVerificationCode, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, false, false,
                        "Code verifier used is not up to RFC 7636 specifications."},
                {"dummyReferenceCodeChallenge", verificationCode, invalidChallengeMethod, false, false,
                        "Invalid OAuth2 Token Response. Invalid PKCE Code Challenge Method '" +
                                invalidChallengeMethod + "'"}
        };
    }

    @Test(dataProvider = "invalidPKCEData")
    public void testValidatePKCEWithException(String referenceCodeChallenge, String verificationCode,
                                              String challengeMethod, boolean isPickleMandatory,
                                              boolean isPkceSupportPlain, String expected) {

        OAuthAppDO oAuthApp = new OAuthAppDO();
        oAuthApp.setPkceMandatory(isPickleMandatory);
        oAuthApp.setPkceSupportPlain(isPkceSupportPlain);

        try {
            OAuth2Util.validatePKCE(referenceCodeChallenge, verificationCode, challengeMethod, oAuthApp);
        } catch (IdentityOAuth2Exception ex) {
            assertEquals(ex.getMessage(), expected);
            return;
        }
        fail("Expected IdentityOAuth2Exception was not thrown by validatePKCE method");
    }

    @DataProvider(name = "ImplicitResponseTypeData")
    public Object[][] implicitResponseTypeData() {

        return new Object[][]{
                // responseType
                // expected result
                {"", false},
                {"testResponseType", false},
                {"token", true},
                {"id_token", true}
        };
    }

    @Test(dataProvider = "ImplicitResponseTypeData")
    public void testIsImplicitResponseType(String responseType, boolean expectedResult) {
        assertEquals(OAuth2Util.isImplicitResponseType(responseType), expectedResult);
    }

    private String generateCodeVerifier(int codeVerifierLength) {
        StringBuilder codeVerifier = new StringBuilder();
        Random r = new Random();
        String subset = "0123456789abcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < codeVerifierLength; i++) {
            int index = r.nextInt(subset.length());
            char c = subset.charAt(index);
            codeVerifier.append(c);
        }

        return codeVerifier.toString();
    }

    @DataProvider(name = "authzUserProvider")
    public Object[][] providerAuthzUser() {
        AuthenticatedUser federatedDomainUser = new AuthenticatedUser();
        federatedDomainUser.setUserStoreDomain("FEDERATED");

        AuthenticatedUser localUser = new AuthenticatedUser();
        localUser.setFederatedUser(false);

        return new Object[][]{
                // Authenticated User, isMapFederatedUserToLocal, expectedIsFederatedValue
                {AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier("DUMMY"), false, true},
                {AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier("DUMMY"), true, false},
                {federatedDomainUser, false, true},
                {federatedDomainUser, true, false},
                {localUser, false, false},
                {localUser, true, false}
        };
    }

    @Test(dataProvider = "authzUserProvider")
    public void testGetAuthenticatedUser(Object authenticatedUser,
                                         boolean mapFederatedUserToLocal,
                                         boolean expectedIsFederatedValue) throws Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAuthzUser((AuthenticatedUser) authenticatedUser);

        when(oauthServerConfigurationMock.isMapFederatedUsersToLocal()).thenReturn(mapFederatedUserToLocal);

        AuthenticatedUser authzUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);
        assertEquals(authzUser.isFederatedUser(), expectedIsFederatedValue);
    }

    @DataProvider(name = "supportedGrantTypes")
    public Object[][] supportedGrantTypes() {
        Map<String, AuthorizationGrantHandler> supportedGrantTypesMap = new HashMap<>();
        supportedGrantTypesMap.put("testGrantType1", authorizationGrantHandlerMock);
        supportedGrantTypesMap.put("testGrantType2", authorizationGrantHandlerMock);

        List<String> supportedGrantTypes = new ArrayList<>();
        supportedGrantTypes.add("testGrantType1");
        supportedGrantTypes.add("testGrantType2");

        return new Object[][]{
                // supportedGrantTypesMap
                // supportedGrantTypes
                {supportedGrantTypesMap, supportedGrantTypes},
                {new HashMap<>(), new ArrayList<>()},
                {null, new ArrayList<>()}
        };
    }

    @Test(dataProvider = "supportedGrantTypes")
    public void testGetSuportedGrantTypes(Map<String, AuthorizationGrantHandler> supportedGrantTypesMap,
                                          List<String> supportedGrantTypes) throws Exception {

        when(oauthServerConfigurationMock.getSupportedGrantTypes()).thenReturn(supportedGrantTypesMap);
        assertEquals(OAuth2Util.getSupportedGrantTypes(), supportedGrantTypes);
    }

    @Test
    public void testGetSupportedClientAuthenticationMethods() throws Exception {
        List<String> clientAuthenticationMethods = new ArrayList<>();
        clientAuthenticationMethods.add("client_secret_basic");
        clientAuthenticationMethods.add("client_secret_post");

        assertEquals(OAuth2Util.getSupportedClientAuthenticationMethods(), clientAuthenticationMethods);
    }

    @Test
    public void testGetSupportedCodeChallengeMethods() {

        List<String> codeChallengeMethods = new ArrayList<>();
        codeChallengeMethods.add(OAuthConstants.OAUTH_PKCE_S256_CHALLENGE);
        codeChallengeMethods.add(OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE);

        assertEquals(OAuth2Util.getSupportedCodeChallengeMethods(), codeChallengeMethods);
    }

    @DataProvider(name = "supportedResponseModes")
    public Object[][] supportedResponseModes() {

        List<String> supportedResponseModes = new ArrayList<>();
        supportedResponseModes.add(OAuthConstants.ResponseModes.QUERY);
        supportedResponseModes.add(OAuthConstants.ResponseModes.FRAGMENT);
        supportedResponseModes.add(OAuthConstants.ResponseModes.FORM_POST);

        return new Object[][] {
                {supportedResponseModes}
        };
    }

    @Test(dataProvider = "supportedResponseModes")
    public void testGetSupportedResponseModes(List<String> supportedResponseModes) {

        when(oauthServerConfigurationMock.getSupportedResponseModeNames()).thenReturn(supportedResponseModes);
        assertEquals(OAuth2Util.getSupportedResponseModes(), supportedResponseModes);
    }

    @Test
    public void testGetRequestObjectSigningAlgValuesSupported() throws Exception {
        List<String> requestObjectSigningAlgValues = new ArrayList<>();
        requestObjectSigningAlgValues.add(JWSAlgorithm.RS256.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.RS384.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.RS512.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.PS256.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.NONE.getName());

        assertEquals(OAuth2Util.getRequestObjectSigningAlgValuesSupported(), requestObjectSigningAlgValues);
    }

    @Test
    public void testIsRequestParameterSupported() throws Exception {
        assertTrue(OAuth2Util.isRequestParameterSupported());
    }

    @Test
    public void testIsClaimsParameterSupported() throws Exception {
        assertTrue(OAuth2Util.isClaimsParameterSupported());
    }

    @DataProvider(name = "getFederatedUserStoreDomainsWithNoIdP")
    public Object[][] getFederatedUserStoreDomainsWithNoIdP() {

        return new Object[][]{
                {OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX},
                {"federated"},
                {null},
                {""}
        };
    }

    @Test(dataProvider = "getFederatedUserStoreDomainsWithNoIdP")
    public void testGetFederatedIdPFromDomainForDomainsWithNoIdP(String userStoreDomain) throws Exception {

        assertNull(OAuth2Util.getFederatedIdPFromDomain(userStoreDomain));
    }

    @Test
    public void testGetFederatedIdPFromDomainForDomainWithIdP() throws Exception {

        String federatedIdP = "facebook";
        String userStoreDomain = String.join(OAuthConstants.UserType.FEDERATED_USER_DOMAIN_SEPARATOR, OAuthConstants
                .UserType.FEDERATED_USER_DOMAIN_PREFIX, federatedIdP);

        assertEquals(OAuth2Util.getFederatedIdPFromDomain(userStoreDomain), federatedIdP);
    }

    @Test
    public void testCreateLocalAuthenticatedUser() throws Exception {

        String username = "testuser1";
        String userStoreDomain = "PRIMARY";
        String tenantDomain = "carbon.super";

        AuthenticatedUser authenticatedUser = OAuth2Util.createAuthenticatedUser(username, userStoreDomain,
                tenantDomain);
        Assert.assertEquals(authenticatedUser.getUserName(), username);
        Assert.assertEquals(authenticatedUser.getUserStoreDomain(), userStoreDomain);
        Assert.assertEquals(authenticatedUser.getTenantDomain(), tenantDomain);
        Assert.assertEquals(authenticatedUser.toString(), UserCoreUtil.addTenantDomainToEntry(UserCoreUtil
                .addDomainToName(username, userStoreDomain), tenantDomain), "When user store domain is not " +
                "'FEDERATED' full qualified username of the user should be in " +
                "{user-store-domain}/{username}@{tenant-domain} format.");
    }

    @Test
    public void testCreateFederatedAuthenticatedUserWithoutAuthenticatedIdP() throws Exception {

        String username = "testuser1";
        String userStoreDomain = "FEDERATED";
        String tenantDomain = "carbon.super";

        AuthenticatedUser authenticatedUser = OAuth2Util.createAuthenticatedUser(username, userStoreDomain,
                tenantDomain);
        Assert.assertEquals(authenticatedUser.getUserName(), username);
        Assert.assertEquals(authenticatedUser.getTenantDomain(), tenantDomain);
        Assert.assertTrue(authenticatedUser.isFederatedUser(), "When user store domain is 'FEDERATED' user should be " +
                "flagged as a federated user.");
        Assert.assertEquals(authenticatedUser.toString(), UserCoreUtil.addTenantDomainToEntry(username, tenantDomain)
                , "When user store domain is 'FEDERATED' full qualified username " +
                        "of the user should be in {username}@{tenant-domain} format.");
    }

    @Test
    public void testCreateFederatedAuthenticatedUserWithAuthenticatedIdP() throws Exception {

        String username = "testuser1";
        String federatedIdP = "facebook";
        String userStoreDomain = String.join(OAuthConstants.UserType.FEDERATED_USER_DOMAIN_SEPARATOR, OAuthConstants
                .UserType.FEDERATED_USER_DOMAIN_PREFIX, federatedIdP);
        String tenantDomain = "carbon.super";

        AuthenticatedUser authenticatedUser = OAuth2Util.createAuthenticatedUser(username, userStoreDomain,
                tenantDomain);
        Assert.assertEquals(authenticatedUser.getUserName(), username);
        Assert.assertEquals(authenticatedUser.getTenantDomain(), tenantDomain);
        Assert.assertEquals(authenticatedUser.getFederatedIdPName(), federatedIdP, "When user store domain is of " +
                "format 'FEDERATED:{idp-name}' federatedIdPName of the user should match {idp-name}.");
        Assert.assertTrue(authenticatedUser.isFederatedUser(), "When user store domain is 'FEDERATED' user should be " +
                "flagged as a federated user.");
        Assert.assertEquals(authenticatedUser.toString(), UserCoreUtil.addTenantDomainToEntry(username, tenantDomain)
                , "When user store domain is 'FEDERATED' full qualified username " +
                        "of the user should be in {username}@{tenant-domain} format.");
    }

    @DataProvider(name = "oidcAudienceDataProvider")
    public Object[][] getOIDCAudience() {

        return new Object[][]{
                {null, 1},
                {new String[0], 1},
                {new String[]{"custom_audience"}, 2},
                {new String[]{"custom_audience", clientId}, 2},
                {new String[]{"custom_audience1", "custom_audience2", clientId}, 3}
        };
    }

    @Test(dataProvider = "oidcAudienceDataProvider")
    public void testGetAudienceForSpDefinedAudiences(Object oidcAudienceConfiguredInApp,
                                                     int expectedAudiencesInTheList) throws Exception {

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        String[] configuredAudiences = (String[]) oidcAudienceConfiguredInApp;
        oAuthAppDO.setAudiences(configuredAudiences);

        OAuth2ServiceComponentHolder.setAudienceEnabled(true);

        IdentityConfigParser mockConfigParser = mock(IdentityConfigParser.class);
        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(mockConfigParser);
        OMElement mockOAuthConfigElement = mock(OMElement.class);
        when(mockConfigParser.getConfigElement(OAuth2Util.CONFIG_ELEM_OAUTH)).thenReturn(mockOAuthConfigElement);

        List<String> oidcAudience = OAuth2Util.getOIDCAudience(clientId, oAuthAppDO);
        assertNotNull(oidcAudience);
        assertEquals(oidcAudience.size(), expectedAudiencesInTheList);
        // We except the client_id to be the first value in the audience list.
        assertEquals(oidcAudience.get(0), clientId);
        if (configuredAudiences != null) {
            // Check whether all configued audience values are available.
            for (String configuredAudience : configuredAudiences) {
                assertTrue(oidcAudience.contains(configuredAudience));
            }
        }
    }

    @DataProvider(name = "tenantDomainProvider")
    public Object[][] getTenantDomains() {

        return new Object[][]{
                // Tenant qualified URLs disable, we do not do any validation.
                { false, null, "wso2.com", false},
                { false, "carbon.super", "wso2.com", false},
                { false, "carbon.super", "carbon.super", false},

                // Tenant qualified URLs enabled but tenant domains do not match.
                { true, null, "wso2.com", true},
                { true, "carbon.super", "wso2.com", true},

                // Tenant qualified URLs enabled and tenant domains match.
                { true, "wso2.com", "wso2.com", false},
        };
    }

    @Test (dataProvider = "tenantDomainProvider")
    public void testValidateRequestTenantDomain(boolean isTenantQualifiedURLsEnabled, String requestTenantDomain,
                                                String appTenantDomain, boolean isExceptionExpected) {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedURLsEnabled);
        when(IdentityTenantUtil.resolveTenantDomain()).thenReturn(requestTenantDomain);

        boolean isInvalidClientExceptionThrown = false;
        try {
            OAuth2Util.validateRequestTenantDomain(appTenantDomain);
        } catch (InvalidOAuthClientException e) {
            isInvalidClientExceptionThrown = true;
        }

        assertEquals(isInvalidClientExceptionThrown, isExceptionExpected);
    }

    @DataProvider(name = "createResponseType")
    public Object[][] createResponseType() {

        return new Object[][]{
                {"", false},
                {null, false},
                {OAuthConstants.CODE_TOKEN, true},
                {OAuthConstants.CODE_IDTOKEN, true},
                {OAuthConstants.CODE_IDTOKEN_TOKEN, true}
        };
    }

    @Test(dataProvider = "createResponseType")
    public void testIsHybridResponseType(String responseType, boolean expected) {

        assertEquals(OAuth2Util.isHybridResponseType(responseType), expected);
    }

    @Test
    public void testGetOIDCScopes() throws UserStoreException, IdentityOAuth2Exception {

        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        ScopeClaimMappingDAO scopeClaimMappingDAOMock = mock(ScopeClaimMappingDAO.class);
        WhiteboxImpl.setInternalState(OAuthTokenPersistenceFactory.getInstance(), "scopeClaimMappingDAO",
                scopeClaimMappingDAOMock);
        List<ScopeDTO> scopes = new ArrayList<>(Arrays.asList(new ScopeDTO("dummyName", "displayName",
                "description", null)));
        when(scopeClaimMappingDAOMock.getScopes(anyInt())).thenReturn(scopes);
        List<String> result = OAuth2Util.getOIDCScopes(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(result.get(0), scopes.get(0).getName());
    }

    @Test
    public void testGetOIDCScopesWithException() throws UserStoreException, IdentityOAuth2Exception {

        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        ScopeClaimMappingDAO scopeClaimMappingDAOMock = mock(ScopeClaimMappingDAO.class);
        WhiteboxImpl.setInternalState(OAuthTokenPersistenceFactory.getInstance(), "scopeClaimMappingDAO",
                scopeClaimMappingDAOMock);

        when(scopeClaimMappingDAOMock.getScopes(anyInt())).thenThrow(IdentityOAuth2Exception.class);
        List<String> result = OAuth2Util.getOIDCScopes(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(result.size(), 0);
    }

    @DataProvider(name = "tokenTypeProvider")
    public static Object[][] tokenTypeProvider() {

        return new Object[][]{
                {"dummyTokenType"},
                {""},
                {null}};
    }

    @Test(dataProvider = "tokenTypeProvider")
    public void testGetOAuthTokenIssuerForOAuthApp(String tokenType) throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setTokenType(tokenType);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(appDO);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuer.class);
        when(oauthServerConfigurationMock.getIdentityOauthTokenIssuer()).thenReturn(oauthTokenIssuer);
        assertEquals(OAuth2Util.getOAuthTokenIssuerForOAuthApp(clientId), oauthTokenIssuer);
    }

    @Test
    public void testGetOAuthTokenIssuerForOAuthAppWithException() {

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).
                thenAnswer (i -> {
                    throw new IdentityOAuth2Exception("IdentityOAuth2Exception");
                });
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        try {
            OAuth2Util.getOAuthTokenIssuerForOAuthApp(clientId);
        } catch (IdentityOAuth2Exception ex) {
            assertEquals(ex.getMessage(), "Error while retrieving app information for clientId: " + clientId);
            return;
        } catch (InvalidOAuthClientException e) {
            throw new RuntimeException(e);
        }
        fail("Expected IdentityOAuth2Exception was not thrown by getOAuthTokenIssuerForOAuthApp method");
    }

    @Test
    public void testGetAppInformationByClientIdWithTenant() throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, clientTenantId)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(IdentityTenantUtil.getTenantId(clientTenantDomain)).thenReturn(clientTenantId);

        assertEquals(OAuth2Util.getAppInformationByClientId(clientId, clientTenantDomain), appDO);
    }

    @Test
    public void testGetAppInformationByClientIdOnly() throws Exception {

        OAuthAppDO[] appDOs = new OAuthAppDO[1];
        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);
        appDOs[0] = appDO;

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppsForConsumerKey(clientId)).thenReturn(appDOs);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        assertEquals(OAuth2Util.getAppInformationByClientIdOnly(clientId), appDO);
    }

    @Test
    public void testGetAppInformationByClientIdOnlyWithException() throws Exception {

        OAuthAppDO[] appDOs = new OAuthAppDO[2];
        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);
        appDOs[0] = appDO;
        appDOs[1] = appDO;

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppsForConsumerKey(clientId)).thenReturn(appDOs);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        try {
            OAuth2Util.getAppInformationByClientIdOnly(clientId);
        } catch (InvalidOAuthClientException ex) {
            assertEquals(ex.getMessage(), APPLICATION_NOT_FOUND);
            return;
        }
        fail("Expected InvalidOAuthClientException was not thrown.");
    }

    @Test
    public void testGetAppInformationByAccessTokenDO() throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(clientId);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, accessTokenDO)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        assertEquals(OAuth2Util.getAppInformationByAccessTokenDO(accessTokenDO), appDO);
    }

    @Test
    public void testGetAllAppInformationByClientId() throws Exception {

        OAuthAppDO[] appDOs = new OAuthAppDO[2];
        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);
        appDOs[0] = appDO;
        appDOs[1] = appDO;

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppsForConsumerKey(clientId)).thenReturn(appDOs);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        OAuthAppDO[] result = OAuth2Util.getAppsForClientId(clientId);
        assertEquals(result.length, appDOs.length);
        assertNotNull(result[0]);
        assertNotNull(result[1]);
    }

    @Test
    public void testGetClientSecret() throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(appDO);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        assertEquals(OAuth2Util.getClientSecret(clientId), appDO.getOauthConsumerSecret());
    }

    @Test
    public void testGetClientSecretWithException() throws Exception {

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);

        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(anyString())).thenReturn(null);

        try {
            OAuth2Util.getClientSecret(clientId);
        } catch (InvalidOAuthClientException ex) {
            assertEquals(ex.getMessage(), "Unable to retrieve app information for consumer key: "
                    + clientId);
            return;
        }
        fail("Expected InvalidOAuthClientException was not thrown by getClientSecret method");
    }

    @Test
    public void testGetClientSecretWithTenant() throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(null);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
        when(oAuthAppDAO.getAppInformation(clientId, clientTenantId)).thenReturn(appDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(IdentityTenantUtil.getTenantId(clientTenantDomain)).thenReturn(clientTenantId);

        assertEquals(OAuth2Util.getClientSecret(clientId, clientTenantDomain), clientSecret);
    }

    @DataProvider(name = "authenticatedIDPProvider")
    public static Object[][] authenticatedIDPProvider() {

        String authenticatedIDP = "dummyAuthenticatedIDP";
        return new Object[][]{
                {authenticatedIDP, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX +
                        OAuthConstants.UserType.FEDERATED_USER_DOMAIN_SEPARATOR + authenticatedIDP},
                {null, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX},
                {"", OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX}};
    }

    @Test(dataProvider = "authenticatedIDPProvider")
    public void testGetFederatedUserDomain(String authenticatedIDP, String expected) {

        assertEquals(OAuth2Util.getFederatedUserDomain(authenticatedIDP), expected);
    }

    @Test
    public void testGetTokenBindingReference() {

        assertNotNull(OAuth2Util.getTokenBindingReference("dummyReference"));
    }

    @Test
    public void testGetTokenBindingReferenceWithInvalidBindingValue() {

        assertNull(OAuth2Util.getTokenBindingReference(null));
        assertNull(OAuth2Util.getTokenBindingReference(""));
    }

    @DataProvider(name = "accessTokenData")
    public static Object[][] accessTokenDataProvider() {

        return new Object[][]{
                {true},
                {false}};
    }

    @Test(dataProvider = "accessTokenData")
    public void testGetAccessTokenDOFromTokenIdentifier(boolean isCacheAvailable) throws Exception {

        getAccessTokenDOFromTokenIdentifier(isCacheAvailable);
        assertNotNull(OAuth2Util.getAccessTokenDOfromTokenIdentifier("dummyIdentifier"));
    }

    @Test
    public void testGetAccessTokenDOFromTokenIdentifierWithException() throws Exception {

        getAccessTokenDOFromTokenIdentifier(false);
        when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(null);
        when(accessTokenDAO.getAccessToken(anyString(), anyBoolean())).thenReturn(null);

        try {
            OAuth2Util.getAccessTokenDOfromTokenIdentifier("dummyIdentifier");
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid Access Token. Access token is not ACTIVE.");
            return;
        }
        fail("Expected IllegalArgumentException was not thrown by getAccessTokenDOfromTokenIdentifier method");
    }

    @Test(dataProvider = "accessTokenData")
    public void testGetClientIdForAccessToken(boolean isCacheAvailable) throws Exception {

        AccessTokenDO accessTokenDO = getAccessTokenDOFromTokenIdentifier(isCacheAvailable);
        assertEquals(OAuth2Util.getClientIdForAccessToken("dummyIdentifier"), accessTokenDO.getConsumerKey());
    }

    private AccessTokenDO getAccessTokenDOFromTokenIdentifier(boolean isCacheAvailable) throws Exception {

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("dummyConsumerKey");

        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(oAuthCacheMock);
        if (isCacheAvailable) {
            when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);
        } else {
            WhiteboxImpl.setInternalState(OAuthTokenPersistenceFactory.getInstance(), "tokenDAO", accessTokenDAO);
            when(accessTokenDAO.getAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);
        }
        when(oauthServerConfigurationMock.isClientSecretHashEnabled()).thenReturn(false);
        return accessTokenDO;
    }

    @Test
    public void testGetServiceProvider() throws Exception {

        setCache();
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        assertNotNull(OAuth2Util.getServiceProvider(clientId));
    }

    @Test
    public void testGetServiceProviderWithIdentityApplicationManagementException() throws Exception {

        setCache();
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenThrow(IdentityApplicationManagementException.class);

        try {
            OAuth2Util.getServiceProvider(clientId);
        } catch (IdentityOAuth2Exception ex) {
            assertEquals(ex.getMessage(), "Error while obtaining the service provider for client_id: " +
                    clientId + " of tenantDomain: " + MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            return;
        }
        fail("Expected IdentityOAuth2Exception was not thrown by getServiceProvider method");
    }

    private void setCache() {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        appDO.setUser(user);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).thenReturn(appDO);
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);
    }

    @Test
    public void testGetServiceProviderWithIdentityInvalidOAuthClientException() {

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        when(appInfoCache.getValueFromCache(clientId)).
                thenAnswer (i -> {
                     throw new InvalidOAuthClientException("InvalidOAuthClientException");
                 });
        mockStatic(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);

        try {
            OAuth2Util.getServiceProvider(clientId);
        } catch (IdentityOAuth2Exception ex) {
            assertEquals(ex.getMessage(), "Could not find an existing app for clientId: " + clientId);
            return;
        }
        fail("Expected IdentityOAuth2Exception was not thrown by getServiceProvider method");
    }

    @Test
    public void testGetServiceProviderWithGivenTenantDomain() throws Exception {

        setCache();
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        assertNotNull(OAuth2Util.getServiceProvider(clientId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
    }

    @Test
    public void testGetServiceProviderWithGivenTenantDomainWithException() throws Exception {

        setCache();
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenThrow(IdentityApplicationManagementException.class);

        try {
            OAuth2Util.getServiceProvider(clientId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        } catch (IdentityOAuth2Exception ex) {
            assertEquals(ex.getMessage(), "Error while obtaining the service provider for client_id: " +
                    clientId + " of tenantDomain: " + MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            return;
        }
        fail("Expected IdentityOAuth2Exception was not thrown by getServiceProvider method");
    }

    @Test
    public void testGetThumbPrint() throws Exception {

        Certificate certificate = wso2KeyStore.getCertificate("wso2carbon");

        String thumbPrint = OAuth2Util.getThumbPrint(certificate);
        String rsa256Thumbprint = "50:f0:ed:a5:89:8a:f3:a1:15:c2:c5:08:19:49:56:e7:e1:14:fe:23:47:43:e9:d2:2f:70:9a:" +
                "e7:cb:80:1b:bd";
        assertEquals(thumbPrint, Base64URL.encode(rsa256Thumbprint.replaceAll(":", "")).toString());
    }

    @DataProvider(name = "FAPI status data provider")
    public Object[][] getFapiStatus() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "FAPI status data provider")
    public void testIsFapiConformantApp(boolean isFapiConformant) throws Exception {

        spy(OAuth2Util.class);
        mockStatic(IdentityUtil.class);
        if (isFapiConformant) {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setFapiConformanceEnabled(true);
            doReturn(oAuthAppDO).when(OAuth2Util.class, "getAppInformationByClientId", anyString(), anyString());
            when(IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI)).thenReturn("true");
            when(IdentityTenantUtil.resolveTenantDomain()).thenReturn("carbon.super");
            when(IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI)).thenReturn("true");
            Assert.assertEquals(OAuth2Util.isFapiConformantApp(clientId), isFapiConformant);
        } else {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setFapiConformanceEnabled(false);
            doReturn(oAuthAppDO).when(OAuth2Util.class, "getAppInformationByClientId", anyString(), anyString());
            when(IdentityTenantUtil.resolveTenantDomain()).thenReturn("carbon.super");
            when(IdentityUtil.getProperty(any())).thenReturn("true");
            Assert.assertEquals(OAuth2Util.isFapiConformantApp(clientId), isFapiConformant);
        }
    }

    @DataProvider(name = "extractCredentialDataProvider")
    public Object[][] extractCredentialDataProvider() {

        return new Object[][]{
                // AuthzHeader, headerValue, expectedException, expectedResult.
                {HTTPConstants.HEADER_AUTHORIZATION,  "Basic " + base64EncodedClientIdSecret, null,
                        new String[]{clientId, clientSecret}},
                {HTTPConstants.HEADER_AUTHORIZATION.toLowerCase(),  "Basic " + base64EncodedClientIdSecret, null,
                        new String[]{clientId, clientSecret}},
                {HTTPConstants.HEADER_AUTHORIZATION,  null,
                        "Basic authorization header is not available in the request.", null},
                {HTTPConstants.HEADER_AUTHORIZATION,  "Bearer 12345",
                        "Basic authorization header is not available in the request.", null},
                {HTTPConstants.HEADER_AUTHORIZATION,  "Basic1234",
                        "Basic authorization header is not available in the request.", null},
                {HTTPConstants.HEADER_AUTHORIZATION,  "Basic " + base64EncodedClientIdInvalid, null, null}
        };
    }

    @Test(dataProvider = "extractCredentialDataProvider")
    public void testExtractCredentialsFromAuthzHeader(String headerKey, String headerValue,
                                                      String expectedException, String[] expectedResult) {

        mockStatic(OAuthUtils.class);
        when(OAuthUtils.decodeClientAuthenticationHeader(headerValue)).thenReturn(expectedResult);

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader(headerKey)).thenReturn(headerValue);
        mockStatic(Base64Utils.class);
        when(Base64Utils.decode(base64EncodedClientIdSecret)).thenReturn(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        when(Base64Utils.decode(base64EncodedClientIdInvalid)).thenReturn(
                (clientId).getBytes(StandardCharsets.UTF_8));

        try {
            String[] credentials = OAuth2Util.extractCredentialsFromAuthzHeader(httpServletRequest);

            if (expectedException != null) {
                fail("Expected exception: " + expectedException.getClass() + " was not thrown.");
            } else if (expectedResult != null) {
                assertEquals(credentials.length, 2);
                assertEquals(credentials[0], clientId);
                assertEquals(credentials[1], clientSecret);
            } else {
                assertNull(credentials);
            }
        } catch (OAuthClientAuthnException e) {
            if (expectedException == null) {
                fail("Unexpected exception: " + e.getClass() + " was thrown.");
            } else {
                assertEquals(e.getMessage(), expectedException);
            }
        }
    }

    @DataProvider(name = "clientAuthenticatorsDataProvider")
    public Object[][] clientAuthenticatorsDataProvider() {

        OAuthClientAuthenticator basicClientAuthenticator = PowerMockito.mock(OAuthClientAuthenticator.class);
        PowerMockito.when(basicClientAuthenticator.getName()).thenReturn("BasicAuthClientAuthenticator");
        OAuthClientAuthenticator publicClientAuthenticator = PowerMockito.mock(OAuthClientAuthenticator.class);
        PowerMockito.when(publicClientAuthenticator.getName()).thenReturn("PublicClientAuthenticator");
        OAuthClientAuthenticator mtlsClientAuthenticator = PowerMockito.mock(OAuthClientAuthenticator.class);
        PowerMockito.when(mtlsClientAuthenticator.getName()).thenReturn("MutualTLSClientAuthenticator");

        List<OAuthClientAuthenticator> clientAuthenticatorsWithMTLS = new ArrayList<>();
        clientAuthenticatorsWithMTLS.add(basicClientAuthenticator);
        clientAuthenticatorsWithMTLS.add(mtlsClientAuthenticator);
        clientAuthenticatorsWithMTLS.add(publicClientAuthenticator);
        List<OAuthClientAuthenticator> clientAuthenticatorsWithoutMTLS = new ArrayList<>();
        clientAuthenticatorsWithoutMTLS.add(basicClientAuthenticator);
        clientAuthenticatorsWithoutMTLS.add(publicClientAuthenticator);

        return new Object[][]{
                {clientAuthenticatorsWithMTLS, true},
                {clientAuthenticatorsWithoutMTLS, false}
        };
    }

    @Test
    public void testGetSupportedClientAuthMethods() {

        ClientAuthenticationMethodModel secretBasic = new ClientAuthenticationMethodModel("client_secret_basic",
                "Client Secret Basic");
        ClientAuthenticationMethodModel secretPost = new ClientAuthenticationMethodModel("client_secret_post",
                "Client Secret Post");
        ClientAuthenticationMethodModel mtls = new ClientAuthenticationMethodModel("tls_client_auth",
                "Mutual TLS");
        ClientAuthenticationMethodModel pkJwt = new ClientAuthenticationMethodModel("private_key_jwt",
                "Private Key JWT");
        List<OAuthClientAuthenticator> clientAuthenticators = new ArrayList<>();
        OAuthClientAuthenticator basicClientAuthenticator = PowerMockito.mock(OAuthClientAuthenticator.class);
        PowerMockito.when(basicClientAuthenticator.getSupportedClientAuthenticationMethods())
                .thenReturn(Arrays.asList(secretBasic, secretPost));
        clientAuthenticators.add(basicClientAuthenticator);
        OAuthClientAuthenticator mtlsClientAuthenticator = PowerMockito.mock(OAuthClientAuthenticator.class);
        PowerMockito.when(mtlsClientAuthenticator.getSupportedClientAuthenticationMethods())
                .thenReturn(Arrays.asList(mtls));
        clientAuthenticators.add(mtlsClientAuthenticator);
        OAuthClientAuthenticator pkjwtClientAuthenticator = PowerMockito.mock(OAuthClientAuthenticator.class);
        PowerMockito.when(pkjwtClientAuthenticator.getSupportedClientAuthenticationMethods())
                .thenReturn(Arrays.asList(pkJwt));
        clientAuthenticators.add(pkjwtClientAuthenticator);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getAuthenticationHandlers()).thenReturn(clientAuthenticators);
        HashSet<ClientAuthenticationMethodModel> supportedClientAuthMethods = OAuth2Util
                .getSupportedAuthenticationMethods();
        assertTrue(supportedClientAuthMethods.contains(secretBasic));
        assertTrue(supportedClientAuthMethods.contains(secretPost));
        assertTrue(supportedClientAuthMethods.contains(mtls));
        assertTrue(supportedClientAuthMethods.contains(pkJwt));
        assertEquals(supportedClientAuthMethods.size(), 4);
        List<String> supportedAuthMethods = Arrays.asList(OAuth2Util.getSupportedClientAuthMethods());
        assertTrue(supportedAuthMethods.contains("client_secret_basic"));
        assertTrue(supportedAuthMethods.contains("client_secret_post"));
        assertTrue(supportedAuthMethods.contains("tls_client_auth"));
        assertTrue(supportedAuthMethods.contains("private_key_jwt"));
        assertEquals(supportedAuthMethods.size(), 4);
    }

    @Test
    public void getSupportedTokenBindingTypes() {

        List<TokenBindingMetaDataDTO> tokenBindingMetaDataDTOS = new ArrayList<>();
        TokenBindingMetaDataDTO cookieTokenBindingMetaDataDTO = new TokenBindingMetaDataDTO();
        cookieTokenBindingMetaDataDTO.setTokenBindingType(OAuth2Constants.TokenBinderType.COOKIE_BASED_TOKEN_BINDER);
        tokenBindingMetaDataDTOS.add(cookieTokenBindingMetaDataDTO);
        TokenBindingMetaDataDTO ssoTokenBindingMetaDataDTO = new TokenBindingMetaDataDTO();
        ssoTokenBindingMetaDataDTO.setTokenBindingType(OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER);
        tokenBindingMetaDataDTOS.add(ssoTokenBindingMetaDataDTO);
        TokenBindingMetaDataDTO certificateTokenBindingMetaDataDTO = new TokenBindingMetaDataDTO();
        certificateTokenBindingMetaDataDTO
                .setTokenBindingType(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        tokenBindingMetaDataDTOS.add(certificateTokenBindingMetaDataDTO);
        when(oAuthComponentServiceHolderMock.getTokenBindingMetaDataDTOs()).thenReturn(tokenBindingMetaDataDTOS);
        List<String> supportedTokenBindingTypes = OAuth2Util.getSupportedTokenBindingTypes();
        Assert.assertTrue(supportedTokenBindingTypes
                .contains(OAuth2Constants.TokenBinderType.COOKIE_BASED_TOKEN_BINDER));
        Assert.assertTrue(supportedTokenBindingTypes
                .contains(OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER));
        Assert.assertTrue(supportedTokenBindingTypes
                .contains(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER));
        Assert.assertEquals(supportedTokenBindingTypes.size(), 3);
    }
}
