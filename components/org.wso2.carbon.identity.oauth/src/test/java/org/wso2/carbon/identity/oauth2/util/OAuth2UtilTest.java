/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
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
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.OAuthUtil;
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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
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
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.NetworkUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuthError.AuthorizationResponsei18nKey.APPLICATION_NOT_FOUND;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDC_DIALECT;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getIdTokenIssuer;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class OAuth2UtilTest {

    private String[] scopeArraySorted = new String[]{"scope1", "scope2", "scope3"};
    private String[] scopeArrayUnSorted = new String[]{"scope2", "scope3", "scope1"};
    private String[] scopeArray = new String[]{"openid", "scope1", "scope2"};
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

    // Signature algorithms.
    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";
    private static final String SHA256_WITH_PS = "SHA256withPS";
    private static final String RS384 = "RS384";
    private static final String ES256 = "ES256";
    private static final String PS256 = "PS256";
    private static final String ES384 = "ES384";

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
    private OrganizationManager organizationManagerMock;

    @Mock
    private Organization organization;

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
    OAuthAdminServiceImpl oAuthAdminService;

    @Mock
    IdentityKeyStoreResolver identityKeyStoreResolver;

    private KeyStore wso2KeyStore;

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<CarbonUtils> carbonUtils;
    private MockedStatic<IdentityCoreServiceComponent> identityCoreServiceComponent;
    private MockedStatic<NetworkUtils> networkUtils;
    private MockedStatic<IdentityProviderManager> identityProviderManager;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;

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

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthComponentServiceHolder = mockStatic(OAuthComponentServiceHolder.class);
        privilegedCarbonContext = mockStatic(PrivilegedCarbonContext.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        carbonUtils = mockStatic(CarbonUtils.class);
        identityCoreServiceComponent = mockStatic(IdentityCoreServiceComponent.class);
        networkUtils = mockStatic(NetworkUtils.class);
        identityProviderManager = mockStatic(IdentityProviderManager.class);
        loggerUtils = mockStatic(LoggerUtils.class);

        oAuthComponentServiceHolder.when(
                OAuthComponentServiceHolder::getInstance).thenReturn(oAuthComponentServiceHolderMock);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(oauthServerConfigurationMock);
        lenient().when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(timestampSkew);
        PrivilegedCarbonContext mockPrivilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContext.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockPrivilegedCarbonContext);

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;

        identityCoreServiceComponent.when(
                        IdentityCoreServiceComponent::getConfigurationContextService)
                .thenReturn(mockConfigurationContextService);
        lenient().when(mockConfigurationContextService.getServerConfigContext()).thenReturn(mockConfigurationContext);
        lenient().when(mockConfigurationContext.getAxisConfiguration()).thenReturn(mockAxisConfiguration);
        carbonUtils.when(() -> CarbonUtils.getTransportPort(any(AxisConfiguration.class), anyString()))
                .thenReturn(9443);
        carbonUtils.when(() -> CarbonUtils.getTransportProxyPort(any(AxisConfiguration.class), anyString()))
                .thenReturn(9443);
        carbonUtils.when(CarbonUtils::getManagementTransport).thenReturn("https");

        identityProviderManager.when(IdentityProviderManager::getInstance).thenReturn(mockIdentityProviderManager);
        lenient().when(mockIdentityProviderManager.getResidentIdP(anyString())).thenReturn(mockIdentityProvider);
        networkUtils.when(NetworkUtils::getLocalHostname).thenReturn("localhost");
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        identityTenantUtil.when(()->IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        identityTenantUtil.when(()->IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
        identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(-1234);
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }

    @AfterMethod
    public void tearDown() {
        oAuthServerConfiguration.close();
        oAuthComponentServiceHolder.close();
        privilegedCarbonContext.close();
        identityTenantUtil.close();
        carbonUtils.close();
        identityCoreServiceComponent.close();
        networkUtils.close();
        identityProviderManager.close();
        loggerUtils.close();
        identityKeyStoreResolverMockedStatic.close();
    }

    @Test
    public void testAuthenticateClientCacheHit() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(appDO);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            assertTrue(OAuth2Util.authenticateClient(clientId, clientSecret));
        }
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

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecretInDB);

            // Mock the cache result
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn((OAuthAppDO) cacheResult);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            // Mock the DB result
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, -1234)).thenReturn(appDO);
                    })) {

                lenient().when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(
                        new PlainTextPersistenceProcessor());
                assertEquals(OAuth2Util.authenticateClient(clientId, clientSecret), expectedResult);
            }
        }
    }

    @Test(dataProvider = "AuthenticateClient")
    public void testAuthenticateClientWithHashPersistenceProcessor(Object cacheResult,
                                                                   String clientSecretInDB,
                                                                   boolean expectedResult) throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecretInDB);

            // Mock the cache result
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn((OAuthAppDO) cacheResult);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            // Mock the DB result
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, -1234)).thenReturn(appDO);
                    })) {

                TokenPersistenceProcessor hashingProcessor = mock(HashingPersistenceProcessor.class);
                when(hashingProcessor.getProcessedClientSecret(clientSecret)).thenReturn(clientSecret);

                when(oauthServerConfigurationMock.isClientSecretHashEnabled()).thenReturn(true);

                when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(hashingProcessor);
                assertEquals(OAuth2Util.authenticateClient(clientId, clientSecret), expectedResult);
            }
        }
    }

    @Test
    public void testAuthenticateClientWithAppTenant() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);

            // Mock the cache result.
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            lenient().when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);
            lenient().when(mockAppInfoCache.getValueFromCache(eq(clientId), anyInt())).thenReturn(null);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            // Mock the DB result.
            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(eq(clientId), anyInt())).thenReturn(appDO);
                    })) {
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(clientTenantDomain))
                        .thenReturn(clientTenantId);

                // Mock realm and tenant manager.
                when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
                when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
                when(tenantManagerMock.getTenantId(clientTenantDomain)).thenReturn(clientTenantId);
                when(tenantManagerMock.isTenantActive(clientTenantId)).thenReturn(true);

                assertTrue(OAuth2Util.authenticateClient(clientId, clientSecret, clientTenantDomain));
            }
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
        MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
        MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {

            identityUtil.when(() -> IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString()))
                    .thenReturn(isUsernameCaseSensitive);

            oAuthCache.when(OAuthCache::getInstance).thenReturn(oAuthCacheMock);
            lenient().when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class)))
                    .thenReturn((CacheEntry) cacheResult);
            try (MockedConstruction<OAuthConsumerDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthConsumerDAO.class,
                    (mock, context) -> {
                        when(mock.getAuthenticatedUsername(anyString(), anyString())).thenReturn(dummyUserName);
                    })) {
                OAuthAppDO appDO = new OAuthAppDO();
                appDO.setOauthConsumerKey(clientId);
                appDO.setOauthConsumerSecret(clientSecretInDB);

                // Mock the cache result
                AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
                when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);

                appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

                // Mock the DB result
                try (MockedConstruction<OAuthAppDAO> mockedConstruction1 = Mockito.mockConstruction(
                        OAuthAppDAO.class,
                        (mock, context) -> {
                            when(mock.getAppInformation(clientId, -1234)).thenReturn(appDO);
                        })) {

                    lenient().when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(
                            new PlainTextPersistenceProcessor());

                    assertEquals(OAuth2Util.getAuthenticatedUsername(clientId, clientSecret), expectedResult);
                }
            }
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            String authorizedUser = "testAuthzUser";
            String scope = "testScope";
            String userId = "4d458e40-afa4-466f-b668-b01cfbfba827";
            identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();
            identityUtil.when(IdentityUtil::getPrimaryDomainName)
                    .thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                    .thenReturn(userId);
            String expected = clientId + ":" + userId + ":" + scope;
            assertEquals(OAuth2Util.buildCacheKeyStringForToken(clientId, scope, authorizedUser), expected);
        }
    }

    @Test
    public void testBuildCacheKeyStringForTokenWithAuthenticatedIDP() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            String authorizedUser = "testAuthzUser";
            String scope = "testScope";
            String authenticatedIDP = "testAuthenticatedIDP";
            String userId = "4d458e40-afa4-466f-b668-b01cfbfba827";
            identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();
            identityUtil.when(
                    IdentityUtil::getPrimaryDomainName).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                    .thenReturn(userId);
            String expected = clientId + ":" + userId + ":" + scope + ":" + authenticatedIDP;

            assertEquals(OAuth2Util.buildCacheKeyStringForToken(clientId, scope, authorizedUser, authenticatedIDP),
                    expected);

        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            lenient().when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");

            assertEquals(OAuth2Util.getPartitionedTableByUserStore(tableName, userstoreDomain), partionedTableName);
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled())
                    .thenReturn(accessTokenPartitioningEnabled);
            lenient().when(oauthServerConfigurationMock.isUserNameAssertionEnabled())
                    .thenReturn(assertionsUserNameEnabled);
            lenient().when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");
            assertEquals(OAuth2Util.getTokenPartitionedSqlByUserStore(sql, "H2"), partitionedSql);
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled())
                    .thenReturn(accessTokenPartitioningEnabled);
            lenient().when(oauthServerConfigurationMock.isUserNameAssertionEnabled())
                    .thenReturn(assertionsUserNameEnabled);
            lenient().when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");
            assertEquals(OAuth2Util.getTokenPartitionedSqlByUserId(sql, username), partitionedSql);
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            when(oauthServerConfigurationMock.isAccessTokenPartitioningEnabled())
                    .thenReturn(accessTokenPartitioningEnabled);
            lenient().when(oauthServerConfigurationMock.isUserNameAssertionEnabled())
                    .thenReturn(assertionsUserNameEnabled);
            lenient().when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");
            identityUtil.when(() -> IdentityUtil.isTokenLoggable(anyString())).thenReturn(isTokenLoggable);
            assertEquals(OAuth2Util.getTokenPartitionedSqlByToken(sql, apiKey), partitionedSql);
        }
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
        lenient().when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            lenient().when(oauthServerConfigurationMock.getAccessTokenPartitioningDomains()).thenReturn("A:H2, B:AD");
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");
            assertEquals(OAuth2Util.getAccessTokenStoreTableFromUserId(userId), accessTokenStoreTable);
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            validityPeriodInMillis = -100;
            AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                    refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                    authorizationCode);
            String accessToken = "dummyAccessToken";
            accessTokenDO.setAccessToken(accessToken);
            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");
            identityUtil.when(() -> IdentityUtil.isTokenLoggable(anyString())).thenReturn(isTokenLoggable);
            assertEquals(OAuth2Util.getAccessTokenExpireMillis(accessTokenDO), -1);
        }
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
        lenient().when(((Supplier<String>) OAuthServerConfiguration.getInstance()::getOAuth2TokenEPUrl).get())
                .thenReturn(serverUrl);

        assertEquals(OAuth2Util.getIDTokenIssuer(), issuer);
    }

    @DataProvider(name = "organizationValidityData")
    public Object[][] organizationValidityData() {

        return new Object[][]{
                {"id1", false, "null", false},
                {"id2", true, "ACTIVE", true},
                {"id3", true, "DISABLED", false},
                {"id4", true, "InvalidState", false},
                {"id5", true, "null", false}
        };
    }

    @Test(dataProvider = "organizationValidityData")
    public void testIsOrganizationValidAndActive(String organizationId, boolean isExistingOrganization, String status,
                                                 boolean isValid) throws Exception {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManagerMock);
        when(organizationManagerMock.isOrganizationExistById(organizationId)).thenReturn(isExistingOrganization);
        lenient().when(organizationManagerMock.getOrganization(organizationId, false, false)).thenReturn(organization);
        lenient().when(organization.getStatus()).thenReturn(status);
        assertEquals(OAuth2Util.isOrganizationValidAndActive(organizationId), isValid);
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

        try (MockedStatic<IdentityApplicationManagementUtil> identityApplicationManagementUtil =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled)
                    .thenReturn(enableTenantURLSupport);
            identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs)
                    .thenReturn(enableTenantURLSupport);
            identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
            PrivilegedCarbonContext mockPrivilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            privilegedCarbonContext.when(
                    PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockPrivilegedCarbonContext);
            lenient().when(mockPrivilegedCarbonContext.getTenantDomain()).thenReturn("carbon.super");

            FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[0];
            lenient().when(mockIdentityProvider.getFederatedAuthenticatorConfigs())
                    .thenReturn(federatedAuthenticatorConfigs);

            Property property = mock(Property.class);
            Property[] properties = new Property[0];
            identityApplicationManagementUtil.when(
                    () -> IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs,
                            "openidconnect")).thenReturn(mockFederatedAuthenticatorConfig);
            lenient().when(mockFederatedAuthenticatorConfig.getProperties()).thenReturn(properties);
            identityApplicationManagementUtil.when(
                            () -> IdentityApplicationManagementUtil.getProperty(properties, "IdPEntityId"))
                    .thenReturn(property);
            lenient().when(property.getValue()).thenReturn(oidcConfigUrl);
            assertEquals(getIdTokenIssuer(tenantDomain), expected);
        }
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            when(oauthServerConfigurationMock.getOAuth1RequestTokenUrl()).thenReturn(configUrl);
            identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                    .thenReturn(serverUrl);
            assertEquals(OAuth2Util.OAuthURL.getOAuth1RequestTokenUrl(), oauthUrl);
        }
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1AuthorizeUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {
        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            when(oauthServerConfigurationMock.getOAuth1AuthorizeUrl()).thenReturn(configUrl);
            identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                    .thenReturn(serverUrl);
            assertEquals(OAuth2Util.OAuthURL.getOAuth1AuthorizeUrl(), oauthUrl);
        }
    }

    @Test(dataProvider = "OAuthURLData")
    public void testGetOAuth1AccessTokenUrl(String configUrl, String serverUrl, String oauthUrl) throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            when(oauthServerConfigurationMock.getOAuth1AccessTokenUrl()).thenReturn(configUrl);
            identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                    .thenReturn(serverUrl);
            assertEquals(OAuth2Util.OAuthURL.getOAuth1AccessTokenUrl(), oauthUrl);
        }
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
        identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                .thenReturn("carbon.super");
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
        identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                .thenReturn("carbon.super");
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
        identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                .thenReturn("carbon.super");
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
        identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                .thenReturn("carbon.super");
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
        identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                .thenReturn("carbon.super");
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
        identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).thenReturn(enableTenantURLSupport);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                .thenReturn("carbon.super");
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

        try (MockedStatic<IdentityConfigParser> identityConfigParser = mockStatic(IdentityConfigParser.class)) {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            String[] configuredAudiences = (String[]) oidcAudienceConfiguredInApp;
            oAuthAppDO.setAudiences(configuredAudiences);

            OAuth2ServiceComponentHolder.setAudienceEnabled(true);

            IdentityConfigParser mockConfigParser = mock(IdentityConfigParser.class);
            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(mockConfigParser);
            OMElement mockOAuthConfigElement = mock(OMElement.class);
            lenient().when(mockConfigParser.getConfigElement(OAuth2Util.CONFIG_ELEM_OAUTH))
                    .thenReturn(mockOAuthConfigElement);

            List<String> oidcAudience = OAuth2Util.getOIDCAudience(clientId, oAuthAppDO);
            assertNotNull(oidcAudience);
            assertEquals(oidcAudience.size(), expectedAudiencesInTheList);
            // We except the client_id to be the first value in the audience list.
            assertEquals(oidcAudience.get(0), clientId);
            if (configuredAudiences != null) {
                // Check whether all configured audience values are available.
                for (String configuredAudience : configuredAudiences) {
                    assertTrue(oidcAudience.contains(configuredAudience));
                }
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

        identityTenantUtil.when(
                IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(isTenantQualifiedURLsEnabled);
        identityTenantUtil.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(requestTenantDomain);

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
    public void testGetOIDCScopes() throws Exception {

        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        ScopeClaimMappingDAO scopeClaimMappingDAOMock = mock(ScopeClaimMappingDAO.class);
        setPrivateField(OAuthTokenPersistenceFactory.getInstance(), "scopeClaimMappingDAO",
                scopeClaimMappingDAOMock);
        List<ScopeDTO> scopes = new ArrayList<>(Arrays.asList(new ScopeDTO("dummyName", "displayName",
                "description", null)));
        when(scopeClaimMappingDAOMock.getScopes(anyInt())).thenReturn(scopes);
        List<String> result = OAuth2Util.getOIDCScopes(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(result.get(0), scopes.get(0).getName());
    }

    @Test
    public void testGetOIDCScopesWithException() throws Exception {

        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        ScopeClaimMappingDAO scopeClaimMappingDAOMock = mock(ScopeClaimMappingDAO.class);
        setPrivateField(OAuthTokenPersistenceFactory.getInstance(), "scopeClaimMappingDAO",
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

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setTokenType(tokenType);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId, clientTenantDomain)).thenReturn(appDO);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuer.class);
            when(oauthServerConfigurationMock.getIdentityOauthTokenIssuer()).thenReturn(oauthTokenIssuer);
            identityTenantUtil.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(clientTenantDomain);
            assertEquals(OAuth2Util.getOAuthTokenIssuerForOAuthApp(clientId), oauthTokenIssuer);
        }
    }

    @Test
    public void testGetOAuthTokenIssuerForOAuthAppWithException() {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId, clientTenantDomain)).
                    thenAnswer(i -> {
                        throw new IdentityOAuth2Exception("IdentityOAuth2Exception");
                    });
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            identityTenantUtil.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(clientTenantDomain);

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
    }

    @Test
    public void testGetAppInformationByClientIdWithTenant() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            lenient().when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);
            lenient().when(mockAppInfoCache.getValueFromCache(eq(clientId), anyInt())).thenReturn(null);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, clientTenantId)).thenReturn(appDO);
                    })) {
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(clientTenantDomain))
                        .thenReturn(clientTenantId);

                assertEquals(OAuth2Util.getAppInformationByClientId(clientId, clientTenantDomain), appDO);
            }
        }
    }

    @Test
    public void testGetAppInformationByClientIdOnly() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO[] appDOs = new OAuthAppDO[1];
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);
            appDOs[0] = appDO;

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppsForConsumerKey(clientId)).thenReturn(appDOs);
                    })) {

                assertEquals(OAuth2Util.getAppInformationByClientIdOnly(clientId), appDO);
            }
        }
    }

    @Test
    public void testGetAppInformationByClientIdOnlyWithException() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO[] appDOs = new OAuthAppDO[2];
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);
            appDOs[0] = appDO;
            appDOs[1] = appDO;

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppsForConsumerKey(clientId)).thenReturn(appDOs);
                    })) {

                try {
                    OAuth2Util.getAppInformationByClientIdOnly(clientId);
                } catch (InvalidOAuthClientException ex) {
                    assertEquals(ex.getMessage(), APPLICATION_NOT_FOUND);
                    return;
                }
                fail("Expected InvalidOAuthClientException was not thrown.");
            }
        }
    }

    @Test
    public void testGetAppInformationByAccessTokenDO() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);

            AccessTokenDO accessTokenDO = new AccessTokenDO();
            accessTokenDO.setConsumerKey(clientId);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, accessTokenDO)).thenReturn(appDO);
                    })) {

                assertEquals(OAuth2Util.getAppInformationByAccessTokenDO(accessTokenDO), appDO);
            }
        }
    }

    @Test
    public void testGetAllAppInformationByClientId() throws Exception {

        OAuthAppDO[] appDOs = new OAuthAppDO[2];
        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        appDO.setOauthConsumerSecret(clientSecret);
        appDOs[0] = appDO;
        appDOs[1] = appDO;

        try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                OAuthAppDAO.class,
                (mock, context) -> {
                    when(mock.getAppsForConsumerKey(clientId)).thenReturn(appDOs);
                })) {

            OAuthAppDO[] result = OAuth2Util.getAppsForClientId(clientId);
            assertEquals(result.length, appDOs.length);
            assertNotNull(result[0]);
            assertNotNull(result[1]);
        }
    }

    @Test
    public void testGetClientSecret() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(appDO);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            assertEquals(OAuth2Util.getClientSecret(clientId), appDO.getOauthConsumerSecret());
        }
    }

    @Test
    public void testGetClientSecretWithException() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);

            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(anyString())).thenReturn(null);
                    })) {

                try {
                    OAuth2Util.getClientSecret(clientId);
                } catch (InvalidOAuthClientException ex) {
                    assertEquals(ex.getMessage(), "Unable to retrieve app information for consumer key: "
                            + clientId);
                    return;
                }
                fail("Expected InvalidOAuthClientException was not thrown by getClientSecret method");
            }
        }
    }

    @Test
    public void testGetClientSecretWithTenant() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            OAuthAppDO appDO = new OAuthAppDO();
            appDO.setOauthConsumerKey(clientId);
            appDO.setOauthConsumerSecret(clientSecret);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            lenient().when(mockAppInfoCache.getValueFromCache(clientId)).thenReturn(null);
            lenient().when(mockAppInfoCache.getValueFromCache(eq(clientId), anyInt())).thenReturn(null);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try (MockedConstruction<OAuthAppDAO> mockedConstruction = Mockito.mockConstruction(
                    OAuthAppDAO.class,
                    (mock, context) -> {
                        when(mock.getAppInformation(clientId, clientTenantId)).thenReturn(appDO);
                    })) {
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(clientTenantDomain))
                        .thenReturn(clientTenantId);

                assertEquals(OAuth2Util.getClientSecret(clientId, clientTenantDomain), clientSecret);
            }
        }
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

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class)) {

            getAccessTokenDOFromTokenIdentifier(isCacheAvailable, oAuthCache);
            assertNotNull(OAuth2Util.getAccessTokenDOfromTokenIdentifier("dummyIdentifier"));
        }
    }

    @Test
    public void testGetAccessTokenDOFromTokenIdentifierWithException() throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class)) {
            getAccessTokenDOFromTokenIdentifier(false, oAuthCache);
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
    }

    @Test(dataProvider = "accessTokenData")
    public void testGetClientIdForAccessToken(boolean isCacheAvailable) throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class)) {
            AccessTokenDO accessTokenDO = getAccessTokenDOFromTokenIdentifier(isCacheAvailable, oAuthCache);
            assertEquals(OAuth2Util.getClientIdForAccessToken("dummyIdentifier"), accessTokenDO.getConsumerKey());
        }
    }

    private AccessTokenDO getAccessTokenDOFromTokenIdentifier(boolean isCacheAvailable,
                                                              MockedStatic<OAuthCache> oAuthCache) throws Exception {

        when(oauthServerConfigurationMock.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey("dummyConsumerKey");

        oAuthCache.when(OAuthCache::getInstance).thenReturn(oAuthCacheMock);
        if (isCacheAvailable) {
            when(oAuthCacheMock.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(accessTokenDO);
        } else {
            setPrivateField(OAuthTokenPersistenceFactory.getInstance(), "tokenDAO", accessTokenDAO);
            when(accessTokenDAO.getAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);
        }
        lenient().when(oauthServerConfigurationMock.isClientSecretHashEnabled()).thenReturn(false);
        return accessTokenDO;
    }

    @Test
    public void testGetServiceProvider() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            setCache(appInfoCache);
            ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
            OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
            when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                    .thenReturn(new ServiceProvider());
            assertNotNull(OAuth2Util.getServiceProvider(clientId));
        }
    }

    @Test
    public void testGetServiceProviderWithIdentityApplicationManagementException() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            setCache(appInfoCache);
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
    }

    private void setCache(MockedStatic<AppInfoCache> appInfoCache) {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setOauthConsumerKey(clientId);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        appDO.setUser(user);

        AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
        lenient().when(mockAppInfoCache.getValueFromCache(clientId, SUPER_TENANT_DOMAIN_NAME)).thenReturn(appDO);
        appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
    }

    @Test
    public void testGetServiceProviderWithIdentityInvalidOAuthClientException() {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            when(mockAppInfoCache.getValueFromCache(clientId, SUPER_TENANT_DOMAIN_NAME)).
                    thenAnswer(i -> {
                        throw new InvalidOAuthClientException("InvalidOAuthClientException");
                    });
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);

            try {
                OAuth2Util.getServiceProvider(clientId);
            } catch (IdentityOAuth2Exception ex) {
                assertEquals(ex.getMessage(), "Could not find an existing app for clientId: " + clientId);
                return;
            }
            fail("Expected IdentityOAuth2Exception was not thrown by getServiceProvider method");
        }
    }

    @Test
    public void testGetServiceProviderWithGivenTenantDomain() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            setCache(appInfoCache);
            ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
            OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
            when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                    .thenReturn(new ServiceProvider());
            assertNotNull(OAuth2Util.getServiceProvider(clientId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
        }
    }

    @Test
    public void testGetServiceProviderWithGivenTenantDomainWithException() throws Exception {

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            setCache(appInfoCache);
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

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS)) {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setFapiConformanceEnabled(isFapiConformant);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                    .thenReturn(oAuthAppDO);

            identityTenantUtil.when(IdentityTenantUtil::resolveTenantDomain).thenReturn("carbon.super");
            identityUtil.when(() -> IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI)).thenReturn("true");
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

        try (MockedStatic<OAuthUtils> oAuthUtils = mockStatic(OAuthUtils.class);
             MockedStatic<Base64Utils> base64Utils = mockStatic(Base64Utils.class)) {
            oAuthUtils.when(() -> OAuthUtils.decodeClientAuthenticationHeader(headerValue)).thenReturn(expectedResult);

            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
            lenient().when(httpServletRequest.getHeader(headerKey)).thenReturn(headerValue);
            base64Utils.when(() -> Base64Utils.decode(base64EncodedClientIdSecret)).thenReturn(
                    (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            base64Utils.when(() -> Base64Utils.decode(base64EncodedClientIdInvalid)).thenReturn(
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
    }

    @DataProvider(name = "extractBearerTokenDataProvider")
    public Object[][] extractBearerTokenDataProvider() {

        String errorMessage = "Bearer authorization header is not available in the request.";

        return new Object[][]{
                // authzHeaderKey, authzHeaderValue, expectedResult
                { "Authorization", "Bearer f2c8a9b3-7e4a-42cd-91df-64f61aaf9a87",
                        "f2c8a9b3-7e4a-42cd-91df-64f61aaf9a87" },
                { "authorization", "Bearer a6db9d92-13c0-441d-8c96-77ebf8b9ea56",
                        "a6db9d92-13c0-441d-8c96-77ebf8b9ea56" },
                { "authorization", "BearerXY 0a4d6e11-c8c2-47a5-9ad0-7c82fa4db938", errorMessage }

        };
    }


    @Test(dataProvider = "extractBearerTokenDataProvider")
    public void testExtractBearerTokenFromAuthzHeader(String authzHeaderKey, String authzHeaderValue,
                                                     String expectedResult) {

        try (MockedStatic<OAuthUtils> oauthUtils = mockStatic(OAuthUtils.class)) {
            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
            lenient().when(httpServletRequest.getHeader(authzHeaderKey)).thenReturn(authzHeaderValue);

            oauthUtils.when(() -> OAuthUtils.getAuthHeaderField(authzHeaderValue)).thenReturn(expectedResult);

            try {
                String extractedToken = OAuth2Util.extractBearerTokenFromAuthzHeader(httpServletRequest);
                assertEquals(extractedToken, expectedResult);
            } catch (OAuthClientAuthnException ex) {
                assertThrows(OAuthClientAuthnException.class, () ->
                        OAuth2Util.extractBearerTokenFromAuthzHeader(httpServletRequest));
            }
        }
    }

    @DataProvider(name = "clientAuthenticatorsDataProvider")
    public Object[][] clientAuthenticatorsDataProvider() {

        OAuthClientAuthenticator basicClientAuthenticator = mock(OAuthClientAuthenticator.class);
        when(basicClientAuthenticator.getName()).thenReturn("BasicAuthClientAuthenticator");
        OAuthClientAuthenticator publicClientAuthenticator = mock(OAuthClientAuthenticator.class);
        when(publicClientAuthenticator.getName()).thenReturn("PublicClientAuthenticator");
        OAuthClientAuthenticator mtlsClientAuthenticator = mock(OAuthClientAuthenticator.class);
        when(mtlsClientAuthenticator.getName()).thenReturn("MutualTLSClientAuthenticator");

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

        try (MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                mockStatic(OAuth2ServiceComponentHolder.class)) {
            ClientAuthenticationMethodModel secretBasic = new ClientAuthenticationMethodModel("client_secret_basic",
                    "Client Secret Basic");
            ClientAuthenticationMethodModel secretPost = new ClientAuthenticationMethodModel("client_secret_post",
                    "Client Secret Post");
            ClientAuthenticationMethodModel mtls = new ClientAuthenticationMethodModel("tls_client_auth",
                    "Mutual TLS");
            ClientAuthenticationMethodModel pkJwt = new ClientAuthenticationMethodModel("private_key_jwt",
                    "Private Key JWT");
            List<OAuthClientAuthenticator> clientAuthenticators = new ArrayList<>();
            OAuthClientAuthenticator basicClientAuthenticator = mock(OAuthClientAuthenticator.class);
            when(basicClientAuthenticator.getSupportedClientAuthenticationMethods())
                    .thenReturn(Arrays.asList(secretBasic, secretPost));
            clientAuthenticators.add(basicClientAuthenticator);
            OAuthClientAuthenticator mtlsClientAuthenticator = mock(OAuthClientAuthenticator.class);
            when(mtlsClientAuthenticator.getSupportedClientAuthenticationMethods())
                    .thenReturn(Arrays.asList(mtls));
            clientAuthenticators.add(mtlsClientAuthenticator);
            OAuthClientAuthenticator pkjwtClientAuthenticator = mock(OAuthClientAuthenticator.class);
            when(pkjwtClientAuthenticator.getSupportedClientAuthenticationMethods())
                    .thenReturn(Arrays.asList(pkJwt));
            clientAuthenticators.add(pkjwtClientAuthenticator);
            oAuth2ServiceComponentHolder.when(
                    OAuth2ServiceComponentHolder::getAuthenticationHandlers).thenReturn(clientAuthenticators);
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

    @Test(dataProvider = "initiateOIDCScopesDataProvider")
    public void testInitiateOIDCScopes(List<ScopeDTO> scopeClaimsList, List<ExternalClaim> oidcDialectClaims)
            throws Exception {

        try (MockedStatic<OAuthTokenPersistenceFactory> mockedOAuthTokenPersistenceFactory =
                     mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedOAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<LogFactory> mockedLogFactory = mockStatic(LogFactory.class)) {

            OAuth2ServiceComponentHolder mockServiceComponentHolder = mock(OAuth2ServiceComponentHolder.class);
            OAuthTokenPersistenceFactory mockTokenPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
            ClaimMetadataManagementService claimService = mock(ClaimMetadataManagementService.class);
            ScopeClaimMappingDAO scopeClaimMappingDAO = mock(ScopeClaimMappingDAO.class);
            Log log = mock(Log.class);

            mockedOAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance)
                    .thenReturn(mockTokenPersistenceFactory);
            mockedOAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(mockServiceComponentHolder);
            mockedLogFactory.when(() -> LogFactory.getLog(any(Class.class))).thenReturn(log);
            setPrivateStaticFinalField(OAuth2Util.class, "log", log);

            when(mockTokenPersistenceFactory.getScopeClaimMappingDAO()).thenReturn(scopeClaimMappingDAO);
            doNothing().when(scopeClaimMappingDAO).initScopeClaimMapping(SUPER_TENANT_ID, scopeClaimsList);
            when(mockServiceComponentHolder.getClaimMetadataManagementService()).thenReturn(claimService);
            when(claimService.getExternalClaims(OIDC_DIALECT, SUPER_TENANT_DOMAIN_NAME)).thenReturn(oidcDialectClaims);
            when(mockServiceComponentHolder.getOIDCScopesClaims()).thenReturn(scopeClaimsList);

            OAuth2Util.initiateOIDCScopes(SUPER_TENANT_ID);
            verify(scopeClaimMappingDAO, times(1))
                    .initScopeClaimMapping(SUPER_TENANT_ID, scopeClaimsList);
            verify(claimService, times(4)).updateExternalClaim(any(), anyString());

            ClaimMetadataException claimMetadataException = new ClaimMetadataException("error");
            when(claimService.getExternalClaims(OIDC_DIALECT, SUPER_TENANT_DOMAIN_NAME))
                    .thenThrow(claimMetadataException);
            OAuth2Util.initiateOIDCScopes(SUPER_TENANT_ID);
            verify(log, times(1))
                    .error(claimMetadataException.getMessage(), claimMetadataException);
        }
    }

    @DataProvider(name = "initiateOIDCScopesDataProvider")
    public Object[][] initiateOIDCScopesDataProvider() {

        List<ScopeDTO> scopeClaimsList = new ArrayList<>();

        ScopeDTO scope1 = new ScopeDTO();
        scope1.setName("openid");
        scope1.setDescription("OpenID scope");
        scope1.setClaim(new String[] {
                "http://wso2.org/oidc/claim/email",
                "http://wso2.org/oidc/claim/profile"
        });

        ScopeDTO scope2 = new ScopeDTO();
        scope2.setName("profile");
        scope2.setDescription("Profile scope");
        scope2.setClaim(new String[] {
                "http://wso2.org/oidc/claim/first_name",
                "http://wso2.org/oidc/claim/last_name",
                "http://wso2.org/oidc/claim/profile"
        });

        ScopeDTO scope3 = new ScopeDTO();
        scope3.setName("email");
        scope3.setDescription("Email scope");
        scope3.setClaim(new String[] {
                "http://wso2.org/oidc/claim/email",
                "http://wso2.org/oidc/claim/email_verified"
        });

        scopeClaimsList.add(scope1);
        scopeClaimsList.add(scope2);
        scopeClaimsList.add(scope3);

        List<ExternalClaim> oidcDialectClaims = new ArrayList<>();

        ExternalClaim claim1 = new ExternalClaim("http://wso2.org/oidc",
                "http://wso2.org/oidc/claim/email", "http://wso2.org/claims/emailaddress");
        ExternalClaim claim2 = new ExternalClaim("http://wso2.org/oidc",
                "http://wso2.org/oidc/claim/profile", "http://wso2.org/claims/url");
        ExternalClaim claim3 = new ExternalClaim("http://wso2.org/oidc",
                "http://wso2.org/oidc/claim/first_name", "http://wso2.org/claims/givenname");
        ExternalClaim claim4 = new ExternalClaim("http://wso2.org/oidc",
                "http://wso2.org/oidc/claim/last_name", "http://wso2.org/claims/lastname");
        ExternalClaim claim5 = new ExternalClaim("http://wso2.org/oidc",
                "http://wso2.org/oidc/claim/phone_number", "http://wso2.org/claims/mobile");

        oidcDialectClaims.add(claim1);
        oidcDialectClaims.add(claim2);
        oidcDialectClaims.add(claim3);
        oidcDialectClaims.add(claim4);
        oidcDialectClaims.add(claim5);

        return new Object[][]{
                {scopeClaimsList, oidcDialectClaims}
        };
    }

    @DataProvider(name = "isAppVersionAllowedDataProvider")
    public Object[][] isAppVersionAllowedDataProvider() {

        return new Object[][]{
                {"v0.0.0", "v1.0.0", false},
                {"v1.0.0", "v1.0.0", true},
                {"v2.0.0", "v1.0.0", true},
                {"v0.0.0", "v2.0.0", false},
                {"v1.0.0", "v2.0.0", false},
                {"v2.0.0", "v2.0.0", true},
        };
    }

    @Test(dataProvider = "isAppVersionAllowedDataProvider")
    public void testIsAppVersionAllowed(String appVersion, String allowedVersions, boolean expected) {

        assertEquals(OAuth2Util.isAppVersionAllowed(appVersion, allowedVersions), expected);
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

    private void setPrivateStaticFinalField(Class<?> clazz, String fieldName, Object value) throws Exception {

        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        field.set(null, value);
    }

    @DataProvider(name = "appResidentOrganizationIdProvider")
    public Object[][] appResidentOrganizationIdProvider() {

        return new Object[][]{
                {"application-resident-org-id", "application-resident-tenant-domain"},
                {null, null}
        };
    }

    @Test(dataProvider = "appResidentOrganizationIdProvider")
    public void testGetAppResidentTenantDomain(String appResidentOrgId, String expected) throws Exception {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManagerMock);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getApplicationResidentOrganizationId())
                .thenReturn(appResidentOrgId);
        lenient().when(organizationManagerMock.resolveTenantDomain(appResidentOrgId)).thenReturn(expected);
        assertEquals(OAuth2Util.getAppResidentTenantDomain(), expected);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Error occurred while resolving the tenant domain for the " +
                    "organization id.")
    public void testGetAppResidentTenantDomainWithException() throws Exception {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManagerMock);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext().getApplicationResidentOrganizationId())
                .thenReturn("application-resident-org-id");
        lenient().when(organizationManagerMock.resolveTenantDomain("application-resident-org-id")).
                thenThrow(OrganizationManagementException.class);
        OAuth2Util.getAppResidentTenantDomain();
    }
    @DataProvider(name = "signatureAlgorithmProvider")
    public Object[][] provideSignatureAlgorithm() {
        return new Object[][]{
                {NONE, JWSAlgorithm.NONE},
                {SHA256_WITH_RSA, JWSAlgorithm.RS256},
                {SHA384_WITH_RSA, JWSAlgorithm.RS384},
                {RS384, JWSAlgorithm.RS384},
                {SHA512_WITH_RSA, JWSAlgorithm.RS512},
                {SHA256_WITH_HMAC, JWSAlgorithm.HS256},
                {SHA384_WITH_HMAC, JWSAlgorithm.HS384},
                {SHA512_WITH_HMAC, JWSAlgorithm.HS512},
                {SHA256_WITH_EC, JWSAlgorithm.ES256},
                {ES256, JWSAlgorithm.ES256},
                {SHA384_WITH_EC, JWSAlgorithm.ES384},
                {ES384, JWSAlgorithm.ES384},
                {SHA512_WITH_EC, JWSAlgorithm.ES512},
                {SHA256_WITH_PS, JWSAlgorithm.PS256},
                {PS256, JWSAlgorithm.PS256}
        };
    }

    @Test(dataProvider = "signatureAlgorithmProvider")
    public void testMapSignatureAlgorithmForJWSAlgorithm(String signatureAlgo,
                                                         Object expectedNimbusdsAlgorithm) throws Exception {
        JWSAlgorithm actual = mapSignatureAlgorithmForJWSAlgorithm(signatureAlgo);
        Assert.assertEquals(actual, expectedNimbusdsAlgorithm);
    }

    @Test(description = "Test get certificate with alias")
    public void testGetCertificateWithAlias() throws Exception {

        // Verify the success case.
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(wso2KeyStore);
        Certificate certificate = OAuth2Util.getCertificate(SUPER_TENANT_DOMAIN_NAME, "test-client-cert");
        assertEquals(((X509Certificate) certificate).getIssuerDN().getName(), "CN=MyCert");

        // Test when the IdentityKeyStoreResolverException is thrown.
        when(identityKeyStoreResolver.getKeyStore("tenant-1",
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenThrow(
                new IdentityKeyStoreResolverException("test-error-code", "test-error"));
        try {
            OAuth2Util.getCertificate("tenant-1", "test-client-cert");
            Assert.fail("Expected IdentityOAuth2Exception to be thrown");
        } catch (IdentityOAuth2Exception e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Error while obtaining public certificate for the alias test-client-cert " +
                            "in the tenant domain tenant-1"));
        }
    }

    @Test(description = "Test the validateIdToken method")
    public void testValidateIdToken() throws Exception {

        String idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImMxMGMzODUwMjNjYzIwOGQ0OWY0YWE5MjUzNTkwY2I1MDdmN2"
                + "JjNDYifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJteS1jbGllbnQtaWQi"
                + "LCJleHAiOjE2MTY3MTcyMDAsImlhdCI6MTYxNjcxMzYwMCwic3ViIjoiMTIzNDU2Nzg5MCIsImVtYWlsIjoid"
                + "GVzdEBleGFtcGxlLmNvbSJ9.signature";
        String userId = "550e8400-e29b-41d4-a716-446655440000";
        String clientId = "750a8400-e29b-56d4-a716-446655440000";

        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                wso2KeyStore.getCertificate("wso2carbon"));

        // Mock the required components
        try (MockedStatic<SignedJWT> signedJWTMock = mockStatic(SignedJWT.class);
             MockedStatic<MultitenantUtils> multiTenantUtilsMock = mockStatic(MultitenantUtils.class)) {
            multiTenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                    .thenReturn(SUPER_TENANT_DOMAIN_NAME);
            JWTClaimsSet claimsSet = mock(JWTClaimsSet.class);
            when(claimsSet.getSubject()).thenReturn(userId);
            when(claimsSet.getAudience()).thenReturn(Collections.singletonList(clientId));

            // Setup JWT parser mock
            SignedJWT signedJWT = mock(SignedJWT.class);
            when(signedJWT.getJWTClaimsSet()).thenReturn(claimsSet);

            // Mock static methods
            signedJWTMock.when(() -> SignedJWT.parse(idToken)).thenReturn(signedJWT);

            ArgumentCaptor<RSASSAVerifier> verifierCaptor = ArgumentCaptor.forClass(RSASSAVerifier.class);
            when(signedJWT.verify(verifierCaptor.capture())).thenReturn(true);

            // Test successful validation
            boolean result = OAuth2Util.validateIdToken(idToken);
            assertTrue(result, "Valid ID token should pass validation");

            RSASSAVerifier capturedVerifier = verifierCaptor.getValue();
            RSAPublicKey capturedPublicKey = capturedVerifier.getPublicKey();
            assertEquals(capturedPublicKey.toString(),
                    wso2KeyStore.getCertificate("wso2carbon").getPublicKey().toString(),
                    "The public key used for verification should match the one in the keystore");
        }
    }

    @Test(description = "Test the getPrivateKey method")
    public void testGetPrivateKey() throws Exception {

        Key testKey = wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        when(identityKeyStoreResolver.getPrivateKey(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(testKey);
        Key privateKey = OAuth2Util.getPrivateKey(SUPER_TENANT_DOMAIN_NAME, -1234);
        assertEquals(privateKey.toString(), testKey.toString(),
                "The private key should match the one in the keystore");
    }

    @Test(description = "Test the getCertificate method")
    public void testGetCertificate() throws Exception {

        Certificate testCert = wso2KeyStore.getCertificate("wso2carbon");
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(testCert);
        Certificate certificate = OAuth2Util.getCertificate(SUPER_TENANT_DOMAIN_NAME, -1234);
        assertEquals(certificate.toString(), testCert.toString(),
                "The certificate should match the one in the keystore");
    }

    @DataProvider
    public Object[][] getTestBuildServiceUrlWithHostnameTestData() {

        return new Object[][]{
                // defaultContext, hostname, oauth2EndpointURLInFile, oauth2EndpointURLInFileV2,
                // shouldUseTenantQualifiedURLs, tenantDomain, expectedServiceURL
                { "oauth2/authorize", "localhost", "https://localhost:9443/oauth2/authorize", null, true, "abc.com",
                        "https://localhost:9443/t/abc.com/oauth2/authorize" },
                { "oauth2/authorize", "localhost", "https://localhost:9443/oauth2/authorize",
                        "https://localhost:9443/t/abc.com/oauth2/authorize", true, "abc.com",
                        "https://localhost:9443/t/abc.com/oauth2/authorize" },
                { "oauth2/userinfo", "localhost", "https://localhost:9443/oauth2/userinfo", null, false, "carbon.super",
                        "https://localhost:9443/oauth2/userinfo" }
        };
    }

    @Test(dataProvider = "getTestBuildServiceUrlWithHostnameTestData")
    public void testBuildServiceUrlWithHostname(String defaultContext, String hostname, String oauth2EndpointURLInFile,
                                                String oauth2EndpointURLInFileV2, boolean shouldUseTenantQualifiedURLs,
                                                String tenantDomain, String expectedServiceURL) {

        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).
                thenReturn(shouldUseTenantQualifiedURLs);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class)) {
            serviceURLBuilder.when(() -> ServiceURLBuilder.create().addPath(defaultContext).
                    setOrganization(null)).thenCallRealMethod();
        }

        String actualServiceURL = OAuth2Util.buildServiceUrlWithHostname(defaultContext, oauth2EndpointURLInFile,
                oauth2EndpointURLInFileV2, hostname);

        assertEquals(actualServiceURL, expectedServiceURL);
    }

    @DataProvider
    public Object[][] getTestGetIdTokenIssuerTestData() {

        String consoleTenantedClientID = ApplicationConstants.CONSOLE_APPLICATION_CLIENT_ID + "_abc.com";

        return new Object[][]{
                // tenantDomain, clientID, isMtlsRequest, isIncorrectHostName, expectedResult
                { "abc.com", consoleTenantedClientID, true, false, "https://localhost:9443/t/abc.com/oauth2/token" },
                { "abc.com", consoleTenantedClientID, false, true, "https://localhost:9443/t/abc.com/oauth2/token" },
                { ApplicationConstants.SUPER_TENANT, ApplicationConstants.CONSOLE_APPLICATION_CLIENT_ID, true, false,
                        "https://localhost:9443/oauth2/token" }
        };
    }

    @Test(dataProvider = "getTestGetIdTokenIssuerTestData")
    public void testGetIdTokenIssuer(String tenantDomain, String clientID, boolean isMtlsRequest,
                                     boolean isIncorrectHostName, String expectedResult)
            throws IdentityOAuth2Exception {

        String defaultContext = "oauth2/token";
        String incorrectHostName = "#host_name";

        identityTenantUtil.when(IdentityTenantUtil::shouldUseTenantQualifiedURLs).
                thenReturn(true);
        identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).
                thenReturn(tenantDomain);

        if (isIncorrectHostName) {
            try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
                identityUtil.when(() -> IdentityUtil.getProperty(IdentityCoreConstants.SERVER_HOST_NAME)).
                        thenReturn(incorrectHostName);
            }
            IdentityUtil.getProperty(IdentityCoreConstants.SERVER_HOST_NAME);
        }

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class)) {
            serviceURLBuilder.when(() -> ServiceURLBuilder.create().addPath(defaultContext).
                    setOrganization(null)).thenCallRealMethod();
        }

        String actualIdTokenIssuer = OAuth2Util.getIdTokenIssuer(tenantDomain, clientID, isMtlsRequest);
        assertEquals(actualIdTokenIssuer, expectedResult);
    }

    @DataProvider(name = "getAuthenticatedUserDataProvider")
    public Object[][] getAuthenticatedUserDataProvider() {
        return new Object[][]{
                // userId, tenantDomain, clientId, expectedException, mockUserExists
                {"testuser123", "carbon.super", "testclientid", null, true},
                {"invaliduser", "carbon.super", "testclientid", IdentityOAuth2Exception.class, false},
                {null, "carbon.super", "testclientid", IdentityOAuth2Exception.class, false},
                {"testuser123", "carbon.super", "testclientid", IdentityOAuth2Exception.class, false}
        };
    }

    @Test(dataProvider = "getAuthenticatedUserDataProvider")
    public void testGetAuthenticatedUser(String userId, String tenantDomain, String clientId, 
                                       Class<? extends Exception> expectedException, boolean mockUserExists) 
            throws Exception {
        
        // Mock dependencies
        User mockUser = mock(User.class);
        lenient().when(mockUser.getUserName()).thenReturn("testusername");
        lenient().when(mockUser.getUserStoreDomain()).thenReturn("PRIMARY");
        
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(anyString())).thenReturn(1);
        
        // Mock OAuthUtil.getUserFromTenant
        try (MockedStatic<OAuthUtil> oAuthUtilMockedStatic = mockStatic(OAuthUtil.class)) {
            if (mockUserExists) {
                oAuthUtilMockedStatic.when(() -> OAuthUtil.getUserFromTenant(anyString(), anyInt()))
                        .thenReturn(mockUser);
            } else {
                oAuthUtilMockedStatic.when(() -> OAuthUtil.getUserFromTenant(anyString(), anyInt()))
                        .thenReturn(null);
            }
            
            // Mock the overloaded getAuthenticatedUser method
            try (MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class)) {
                AuthenticatedUser expectedAuthUser = new AuthenticatedUser();
                expectedAuthUser.setUserId(userId);
                expectedAuthUser.setUserName("testusername");
                expectedAuthUser.setUserStoreDomain("PRIMARY");
                expectedAuthUser.setTenantDomain(tenantDomain);
                
                oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(anyString(), anyString(), 
                        anyString(), anyString(), anyString(), any()))
                        .thenReturn(expectedAuthUser);
                
                // Call the real method
                oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(userId, tenantDomain, clientId))
                        .thenCallRealMethod();
                
                if (expectedException != null) {
                    assertThrows(expectedException, 
                            () -> OAuth2Util.getAuthenticatedUser(userId, tenantDomain, clientId));
                } else {
                    AuthenticatedUser result = OAuth2Util.getAuthenticatedUser(userId, tenantDomain, clientId);
                    assertNotNull(result);
                    if (mockUserExists) {
                        assertEquals(result.getUserId(), userId);
                        assertEquals(result.getUserName(), "testusername");
                        assertEquals(result.getUserStoreDomain(), "PRIMARY");
                        assertEquals(result.getTenantDomain(), tenantDomain);
                    }
                }
            }
        }
    }

    @DataProvider(name = "getOrgAuthenticatedUserDataProvider")
    public Object[][] getOrgAuthenticatedUserDataProvider() {
        return new Object[][]{
                // userId, tenantDomain, userAccessingOrg, userResidentOrg, clientId, expectedException, mockUserExists, mockResolveOrgSuccessful
                {"testuser123", "carbon.super", "org1", "org2", "testclientid", null, true, true},
                {"testuser123", "carbon.super", "org1", "org2", "testclientid", IdentityOAuth2Exception.class, false, true},
                {"testuser123", "carbon.super", "org1", "org2", "testclientid", IdentityOAuth2Exception.class, true, false},
                {null, "carbon.super", "org1", "org2", "testclientid", IdentityOAuth2Exception.class, true, true}
        };
    }

    @Test(dataProvider = "getOrgAuthenticatedUserDataProvider")
    public void testGetOrgAuthenticatedUser(String userId, String tenantDomain, String userAccessingOrg,
                                                        String userResidentOrg, String clientId, 
                                                        Class<? extends Exception> expectedException, 
                                                        boolean mockUserExists, boolean mockResolveOrgSuccessful) 
            throws Exception {
        
        User mockUser = mock(User.class);
        lenient().when(mockUser.getUserName()).thenReturn("testusername");
        lenient().when(mockUser.getUserStoreDomain()).thenReturn("PRIMARY");
        
        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManagerMock);
        when(oAuthComponentServiceHolderMock.getRealmService()).thenReturn(realmServiceMock);

        lenient().when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        lenient().when(tenantManagerMock.getTenantId(anyString())).thenReturn(1);
        
        if (mockResolveOrgSuccessful && userResidentOrg != null) {
            when(organizationManagerMock.resolveTenantDomain(userResidentOrg)).thenReturn("resolved.domain");
        } else if (userResidentOrg != null) {
            when(organizationManagerMock.resolveTenantDomain(userResidentOrg))
                    .thenThrow(new OrganizationManagementException("Failed to resolve organization"));
        }
        
        try (MockedStatic<OAuthUtil> oAuthUtilMockedStatic = mockStatic(OAuthUtil.class)) {
            if (mockUserExists && userId != null) {
                oAuthUtilMockedStatic.when(() -> OAuthUtil.getUserFromTenant(anyString(), anyInt()))
                        .thenReturn(mockUser);
            } else {
                oAuthUtilMockedStatic.when(() -> OAuthUtil.getUserFromTenant(anyString(), anyInt()))
                        .thenReturn(null);
            }

            try (MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class)) {
                AuthenticatedUser expectedAuthUser = new AuthenticatedUser();
                expectedAuthUser.setUserId(userId);
                expectedAuthUser.setUserName("testusername");
                expectedAuthUser.setUserStoreDomain("PRIMARY");
                expectedAuthUser.setTenantDomain(tenantDomain);
                
                oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(anyString(), anyString(), 
                        anyString(), anyString(), anyString(), anyString(), anyString(), any()))
                        .thenReturn(expectedAuthUser);
                
                // Call the real method under test
                oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(userId, tenantDomain, 
                        userAccessingOrg, userResidentOrg, clientId))
                        .thenCallRealMethod();
                
                if (expectedException != null) {
                    assertThrows(expectedException, 
                            () -> OAuth2Util.getAuthenticatedUser(userId, tenantDomain, userAccessingOrg, 
                                    userResidentOrg, clientId));
                } else {
                    AuthenticatedUser result = OAuth2Util.getAuthenticatedUser(userId, tenantDomain, 
                            userAccessingOrg, userResidentOrg, clientId);
                    
                    assertNotNull(result);
                    if (mockUserExists && userId != null) {
                        assertEquals(result.getUserId(), userId);
                        assertEquals(result.getUserName(), "testusername");
                        assertEquals(result.getUserStoreDomain(), "PRIMARY");
                        assertEquals(result.getTenantDomain(), tenantDomain);
                    }
                }
            }
        }
    }
}
