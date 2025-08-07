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
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.testng.collections.Sets;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.DefaultOIDCProviderRequestBuilder;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.expmapper.InvalidRequestExceptionMapper;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuth2ServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuth2TokenValidatorServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuthAdminServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuthServerConfigurationFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OIDCProviderServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.Oauth2ScopeServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.RequestObjectServiceFactory;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.model.OAuth2ScopeConsentResponse;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;

@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class EndpointUtilTest {

    @Mock
    Log mockedLog;

    @Mock
    SessionDataCache mockedSessionDataCache;

    @Mock
    SessionDataCacheEntry mockedSessionDataCacheEntry;

    @Mock
    OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    OAuthASResponse mockedOAuthResponse;

    @Mock
    HttpServletRequest mockedHttpServletRequest;

    @Mock
    HttpServletResponse mockedHttpServletResponse;

    @Mock
    ServerConfiguration mockedServerConfiguration;

    @Mock
    OAuth2Service mockedOAuth2Service;

    @Mock
    OAuthAdminServiceImpl mockedOAuthAdminService;

    @Mock
    OAuth2ScopeService oAuth2ScopeService;

    @Mock
    private AuthorizationDetailsService authorizationDetailsServiceMock;

    @Mock
    FileBasedConfigurationBuilder mockFileBasedConfigurationBuilder;

    @Mock
    BundleContext bundleContext;

    MockedConstruction<ServiceTracker> mockedConstruction;

    private static final String COMMONAUTH_URL = "https://localhost:9443/commonauth";
    private static final String OIDC_CONSENT_PAGE_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_consent.do";
    private static final String OAUTH2_CONSENT_PAGE_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_authz.do";
    private static final String ERROR_PAGE_URL = "https://localhost:9443/authenticationendpoint/oauth2_error.do";
    private static final String ERROR_PAGE_URL_WITH_APP =
            "https://localhost:9443/authenticationendpoint/oauth2_error.do?oauthErrorCode=3002&" +
                    "oauthErrorMsg=errorMessage&application=myApp";
    private static final String ERROR_PAGE_URL_WITHOUT_APP =
            "https://localhost:9443/authenticationendpoint/oauth2_error.do?oauthErrorCode=3002&" +
                    "oauthErrorMsg=errorMessage";

    private static final String USER_INFO_CLAIM_DIALECT = "http://wso2.org/claims";
    private static final String USER_INFO_CLAIM_RETRIEVER =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoUserStoreClaimRetriever";
    private static final String USER_INFO_REQUEST_VALIDATOR =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInforRequestDefaultValidator";
    private static final String USER_INFO_TOKEN_VALIDATOR =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoISAccessTokenValidator";
    private static final String USER_INFO_RESPONSE_BUILDER =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoJSONResponseBuilder";

    private static final String REQUESTED_OIDC_SCOPES_KEY = "requested_oidc_scopes=";
    private static final String REQUESTED_OIDC_SCOPES_VALUES = "openid+profile";
    private static final String EXTERNAL_CONSENTED_APP_NAME = "testApp";
    private static final String REDIRECT = "redirect";
    private static final String EXTERNAL_CONSENT_URL = "https://localhost:9443/consent";
    private String username = "myUsername";
    private String password = "myPassword";
    private String sessionDataKey;
    private String clientId;
    private AuthenticatedUser user;
    private OAuth2ScopeConsentResponse oAuth2ScopeConsentResponse;
    private final AuthorizationDetails testAuthorizationDetails;

    public EndpointUtilTest() {

        final AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType("test_type");
        this.testAuthorizationDetails = new AuthorizationDetails(Sets.newHashSet(testAuthorizationDetail));
    }

    @BeforeMethod
    public void setUp() {

        sessionDataKey = "1234567890";
        clientId = "myClientId";
        user = new AuthenticatedUser();
        user.setFederatedUser(false);
        user.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        oAuth2ScopeConsentResponse = new OAuth2ScopeConsentResponse("sampleUser", "sampleApp",
                -1234, new ArrayList<>(), new ArrayList<>());

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(DefaultOIDCProviderRequestBuilder.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{new DefaultOIDCProviderRequestBuilder()});
                    }
                    if (argumentCaptor.getValue().contains(OAuthServerConfiguration.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{mockedOAuthServerConfiguration});
                    }
                    if (argumentCaptor.getValue().contains(WebFingerProcessor.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{DefaultWebFingerProcessor.getInstance()});
                    }
                    if (argumentCaptor.getValue().contains(OIDCProcessor.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{DefaultOIDCProcessor.getInstance()});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2Service.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{new OAuth2Service()});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2TokenValidationService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{new OAuth2TokenValidationService()});
                    }
                    if (argumentCaptor.getValue().contains(RequestObjectService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{new RequestObjectService()});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2ScopeService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{new OAuth2ScopeService()});
                    }
                    if (argumentCaptor.getValue().contains(OAuthAdminServiceImpl.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{new OAuthAdminServiceImpl()});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() {

        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
        Mockito.reset(bundleContext);
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @DataProvider(name = "provideAuthzHeader")
    public Object[][] provideAuthzHeader() {

        String authzValue = "Basic " + Base64Utils.encode((username + ":" + password).getBytes());
        String incorrectAuthzValue = "SomeValue " + Base64Utils.encode((username + ":" + password).getBytes());

        return new Object[][]{
                {authzValue, username, null},
                {incorrectAuthzValue, username, "Error decoding authorization header"},
                {username, null, "Error decoding authorization header"},
                {"Basic " + Base64Utils.encode(username.getBytes()), null, "Error decoding authorization header"},
                {null, null, "Authorization header value is null"},
        };
    }

    @Test(dataProvider = "provideAuthzHeader")
    public void testExtractCredentialsFromAuthzHeader(String header, String expected, String msg) {

        String[] credentials = null;
        try {
            credentials = EndpointUtil.extractCredentialsFromAuthzHeader(header);
            Assert.assertEquals(credentials[0], expected, "Invalid credentials returned");
        } catch (OAuthClientException e) {
            Assert.assertTrue(e.getMessage().contains(msg), "Unexpected Exception");
        }

    }

    @DataProvider(name = "provideDataForUserConsentURL")
    public Object[][] provideDataForUserConsentURL() {

        OAuth2Parameters params = new OAuth2Parameters();
        params.setApplicationName("TestApplication");
        params.setClientId("testClientId");
        params.setTenantDomain("testTenantDomain");
        params.setScopes(new HashSet<String>(Arrays.asList("scope1", "scope2", "internal_login")));
        params.setAuthorizationDetails(testAuthorizationDetails);

        OAuth2Parameters paramsOIDC = new OAuth2Parameters();
        paramsOIDC.setApplicationName("TestApplication");
        paramsOIDC.setClientId("testClientId");
        paramsOIDC.setTenantDomain("testTenantDomain");
        paramsOIDC.setScopes(
                new HashSet<String>(Arrays.asList("openid", "profile", "scope1", "scope2", "internal_login")));

        OAuth2Parameters paramsExternalConsentUrl = new OAuth2Parameters();
        paramsExternalConsentUrl.setApplicationName(EXTERNAL_CONSENTED_APP_NAME);
        paramsExternalConsentUrl.setClientId("testClientId");
        paramsExternalConsentUrl.setTenantDomain("testTenantDomain");
        paramsExternalConsentUrl.setScopes(new HashSet<String>(Arrays.asList("scope1", "scope2", "internal_login")));

        return new Object[][]{
                {params, true, true, false, "QueryString", true, false},
                {null, true, true, false, "QueryString", true, false},
                {params, false, true, false, "QueryString", true, true},
                {params, true, false, false, "QueryString", true, false},
                {params, true, false, false, "QueryString", false, false},
                {params, true, true, false, null, true, true},
                {params, true, true, true, "QueryString", true, false},
                {paramsOIDC, true, true, true, "QueryString", true, false},
                {paramsExternalConsentUrl, false, true, true, "QueryString", true, false},
        };
    }

    @Test(dataProvider = "provideDataForUserConsentURL")
    public void testGetUserConsentURL(Object oAuth2ParamObject, boolean isOIDC, boolean cacheEntryExists,
                                      boolean throwError, String queryString, boolean isDebugEnabled,
                                      boolean isConfigAvailable) throws Exception {

        setMockedLog(isDebugEnabled);
        OAuth2Parameters parameters = (OAuth2Parameters) oAuth2ParamObject;

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder =
                     mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<OAuthServerConfigurationFactory> oAuthServerConfigurationFactory =
                     mockStatic(OAuthServerConfigurationFactory.class)) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockedOAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<OAuth2ServiceComponentHolder> serviceComponentHolder =
                         mockStatic(OAuth2ServiceComponentHolder.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<Oauth2ScopeServiceFactory> oauth2ScopeServiceFactory =
                         mockStatic(Oauth2ScopeServiceFactory.class);
                 MockedStatic<OAuthAdminServiceFactory> oAuthAdminServiceFactory =
                         mockStatic(OAuthAdminServiceFactory.class)) {

                oAuthServerConfigurationFactory.when(OAuthServerConfigurationFactory::getOAuthServerConfiguration)
                        .thenReturn(mockedOAuthServerConfiguration);
                lenient().when(mockedOAuthServerConfiguration.isDropUnregisteredScopes()).thenReturn(false);
                oauth2ScopeServiceFactory.when(Oauth2ScopeServiceFactory::getOAuth2ScopeService)
                        .thenReturn(oAuth2ScopeService);
                lenient().when(oAuth2ScopeService.getUserConsentForApp(anyString(), anyString(), anyInt()))
                        .thenReturn(oAuth2ScopeConsentResponse);

                oAuth2Util.when(() -> OAuth2Util.isOIDCAuthzRequest(any(Set.class))).thenReturn(isOIDC);
                if (parameters != null && parameters.getApplicationName().equals(EXTERNAL_CONSENTED_APP_NAME)) {
                    oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString())).thenReturn(getServiceProvider());
                } else {
                    ServiceProvider serviceProvider = new ServiceProvider();
                    serviceProvider.setApplicationResourceId("sampleId");
                    oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString())).thenReturn(serviceProvider);
                }
                oAuth2Util.when(() -> OAuth2Util.resolveExternalConsentPageUrl(anyString()))
                        .thenReturn(EXTERNAL_CONSENT_URL);

                oAuthURL.when(OAuth2Util.OAuthURL::getOIDCConsentPageUrl).thenReturn(OIDC_CONSENT_PAGE_URL);
                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ConsentPageUrl).thenReturn(OAUTH2_CONSENT_PAGE_URL);

                fileBasedConfigurationBuilder.when(
                        FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);
                lenient().when(mockFileBasedConfigurationBuilder.isAuthEndpointRedirectParamsConfigAvailable())
                        .thenReturn(isConfigAvailable);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn("sample");
                frameworkUtils.when(() -> FrameworkUtils.getRedirectURLWithFilteredParams(anyString(), anyMap()))
                        .then(i -> i.getArgument(0));
                frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                        .then(i -> i.getArgument(0));

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockedSessionDataCache);
                if (cacheEntryExists) {
                    when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                            thenReturn(mockedSessionDataCacheEntry);
                    when(mockedSessionDataCacheEntry.getQueryString()).thenReturn(queryString);
                    lenient().when(mockedSessionDataCacheEntry.getLoggedInUser()).thenReturn(user);
                    lenient().when(mockedSessionDataCacheEntry.getEndpointParams()).thenReturn(new HashMap<>());
                } else {
                    when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                            thenReturn(null);
                }

                oAuthAdminServiceFactory.when(OAuthAdminServiceFactory::getOAuthAdminService)
                        .thenReturn(mockedOAuthAdminService);
                lenient().when(mockedOAuthAdminService.getScopeNames()).thenReturn(new String[0]);
                lenient().when(mockedOAuthAdminService.getRegisteredOIDCScope(anyString()))
                        .thenReturn(Arrays.asList("openid", "email", "profile", "groups"));

                lenient().when(authorizationDetailsServiceMock.getConsentRequiredAuthorizationDetails(user, parameters))
                        .thenReturn(testAuthorizationDetails);
                OAuth2ServiceComponentHolder.getInstance()
                        .setAuthorizationDetailsService(authorizationDetailsServiceMock);

                String consentUrl;
                try {
                    consentUrl = EndpointUtil.getUserConsentURL(parameters, username, sessionDataKey, isOIDC);
                    if (isOIDC) {
                        Assert.assertTrue(consentUrl.contains(OIDC_CONSENT_PAGE_URL),
                                "Incorrect consent page url for OIDC");
                    } else {
                        if (parameters != null && parameters.getApplicationName().equals(EXTERNAL_CONSENTED_APP_NAME)) {
                            Assert.assertTrue(consentUrl.contains(EXTERNAL_CONSENT_URL),
                                    "Incorrect consent page url for OIDC");
                        } else {
                            Assert.assertTrue(consentUrl.contains(OAUTH2_CONSENT_PAGE_URL),
                                    "Incorrect consent page url for OAuth");
                        }
                    }

                    if (isConfigAvailable) {
                        Assert.assertTrue(consentUrl.contains(URLEncoder.encode(username, "UTF-8")),
                                "loggedInUser parameter value is not found in url");
                        Assert.assertTrue(consentUrl.contains(URLEncoder.encode("TestApplication", "ISO-8859-1")),
                                "application parameter value is not found in url");
                        List<NameValuePair> nameValuePairList =
                                URLEncodedUtils.parse(consentUrl, StandardCharsets.UTF_8);
                        Optional<NameValuePair> optionalScope = nameValuePairList.stream().filter(nameValuePair ->
                                nameValuePair.getName().equals("scope")).findAny();
                        Assert.assertTrue(optionalScope.isPresent());
                        NameValuePair scopeNameValuePair = optionalScope.get();
                        String[] scopeArray = scopeNameValuePair.getValue().split(" ");
                        Assert.assertTrue(ArrayUtils.contains(scopeArray, "scope2"), "scope parameter value " +
                                "is not found in url");
                        Assert.assertTrue(ArrayUtils.contains(scopeArray, "internal_login"), "internal_login " +
                                "scope parameter value is not found in url");

                        if (queryString != null && cacheEntryExists) {
                            Assert.assertTrue(consentUrl.contains(queryString),
                                    "spQueryParams value is not found in url");
                        }

                        if (parameters.getScopes().contains("openid")) {
                            String decodedConsentUrl = URLDecoder.decode(consentUrl, "UTF-8");
                            int checkIndex = decodedConsentUrl.indexOf(REQUESTED_OIDC_SCOPES_KEY);
                            Assert.assertTrue(checkIndex != -1,
                                    "Requested OIDC scopes query parameter is not found in url.");

                            String requestedClaimString = decodedConsentUrl.substring(checkIndex);
                            checkIndex = requestedClaimString.indexOf("&");
                            if (checkIndex != -1) {
                                requestedClaimString = requestedClaimString.substring(0, checkIndex);
                            }
                            Assert.assertTrue(StringUtils.equals(
                                            requestedClaimString, REQUESTED_OIDC_SCOPES_KEY +
                                                    REQUESTED_OIDC_SCOPES_VALUES),
                                    "Incorrect requested OIDC scopes in query parameter.");
                        }
                    } else {
                        String queryParamString = consentUrl.substring(consentUrl.indexOf("?") + 1);
                        List<NameValuePair> nameValuePairList =
                                URLEncodedUtils.parse(queryParamString, StandardCharsets.UTF_8);
                        if (cacheEntryExists) {
                            Assert.assertEquals(nameValuePairList.size(), 1);
                        }
                        Optional<NameValuePair> sessionDataKeyConsent =
                                nameValuePairList.stream().filter(nameValuePair ->
                                        nameValuePair.getName().equals("sessionDataKeyConsent")).findAny();
                        Assert.assertTrue(sessionDataKeyConsent.isPresent());
                    }

                } catch (OAuthSystemException e) {
                    Assert.assertTrue(
                            e.getMessage().contains("Error while retrieving the application name") || e.getMessage()
                                    .contains("Unable to find a service provider with client_id:"));
                }
            }
        }
    }

    @DataProvider(name = "provideScopeData")
    public Object[][] provideScopeData() {

        return new Object[][]{
                {null, "oauth2"},
                {new HashSet<String>() {{
                    add("scope1");
                }}, "oauth2"},
                {new HashSet<String>() {{
                    add("openid");
                }}, "oidc"},
        };
    }

    @Test(dataProvider = "provideScopeData")
    public void testGetLoginPageURL(Set<String> scopes, String queryParam) throws Exception {

        Map<String, String[]> reqParams = new HashedMap();
        reqParams.put("param1", new String[]{"value1"});

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockedOAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {
                oAuth2Util.when(OAuth2Util::getClientTenatId).thenReturn(-1234);

                frameworkUtils.when(() -> FrameworkUtils.addAuthenticationRequestToCache(anyString(),
                                any(AuthenticationRequestCacheEntry.class)))
                        .thenAnswer(invocation -> null);

                mockServiceURLBuilder(COMMONAUTH_URL, serviceURLBuilder);

                String url = EndpointUtil.getLoginPageURL(clientId, sessionDataKey, true, true, scopes, reqParams);
                Assert.assertTrue(url.contains("type=" + queryParam),
                        "type parameter is not set according to the scope");
            }
        }
    }

    private void mockServiceURLBuilder(String url, MockedStatic<ServiceURLBuilder> serviceURLBuilder)
            throws URLBuilderException {

        ServiceURLBuilder mockServiceURLBuilder = mock(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);

        ServiceURL serviceURL = mock(ServiceURL.class);
        when(serviceURL.getAbsolutePublicURL()).thenReturn(url);
        when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
    }

    @DataProvider(name = "provideErrorData")
    public Object[][] provideErrorData() {

        return new Object[][]{
                {"myApp", ERROR_PAGE_URL_WITH_APP},
                {null, ERROR_PAGE_URL_WITHOUT_APP}
        };
    }

    @Test(dataProvider = "provideErrorData")
    public void testGetErrorPageURL(String applicationName, String expected) throws Exception {

        try (MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class)) {
            oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

            String url = EndpointUtil.getErrorPageURL("3002", "errorMessage", applicationName);
            Assert.assertEquals(url, expected, "Incorrect error page url");
        }
    }

    @DataProvider(name = "provideErrorRedirectData")
    public Object[][] provideErrorRedirectData() {

        OAuth2Parameters params1 = new OAuth2Parameters();
        OAuth2Parameters params2 = new OAuth2Parameters();
        String state = "active";
        String responseType = "dummyResponceType";
        String appName = "myApp";

        params1.setState(state);
        params1.setResponseType(responseType);
        params1.setApplicationName(appName);
        params1.setRedirectURI("http://localhost:8080/callback");

        params2.setState(state);
        params2.setResponseType(responseType);
        params2.setApplicationName(appName);
        params2.setRedirectURI(null);

        return new Object[][]{
                {true, true, params1, null, "http://localhost:8080/location", false},
                {true, false, params1, null, "http://localhost:8080/location", false},
                {false, true, params1, null, "http://localhost:8080/location", false},
                {true, true, params2, null, ERROR_PAGE_URL, false},
                {true, true, null, null, ERROR_PAGE_URL, false},
                {true, true, params1, new OAuthSystemException(), ERROR_PAGE_URL, false},
                {true, true, params1, new OAuthSystemException(), ERROR_PAGE_URL, true}
        };
    }

    @Test(dataProvider = "provideErrorRedirectData")
    public void testGetErrorRedirectURL(boolean isImplicitResponse, boolean isImplicitFragment,
                                        Object oAuth2ParamObject, Object exeObject, String expected, boolean isDebugOn)
            throws Exception {

        setMockedLog(isDebugOn);
        OAuth2Parameters parameters = (OAuth2Parameters) oAuth2ParamObject;
        OAuthProblemException exception = OAuthProblemException.error("OAuthProblemExceptionErrorMessage");

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);
            lenient().when(mockedOAuthServerConfiguration.isImplicitErrorFragment()).thenReturn(isImplicitFragment);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);) {
                oAuth2Util.when(() -> OAuth2Util.isImplicitResponseType(anyString())).thenReturn(isImplicitResponse);

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                try (MockedConstruction<OAuthResponse.OAuthErrorResponseBuilder> mockedConstruction =
                             Mockito.mockConstruction(OAuthResponse.OAuthErrorResponseBuilder.class,
                                     (mock, context) -> {
                                         when(mock.error(any(OAuthProblemException.class))).thenReturn(mock);
                                         when(mock.location(anyString())).thenReturn(mock);
                                         when(mock.setState(anyString())).thenReturn(mock);
                                         when(mock.setParam(anyString(), isNull())).
                                                 thenReturn(mock);
                                         if (exeObject != null) {
                                             OAuthSystemException oAuthSystemException =
                                                     (OAuthSystemException) exeObject;
                                             when(mock.buildQueryMessage()).thenThrow(oAuthSystemException);
                                         } else {
                                             when(mock.buildQueryMessage()).thenReturn(mockedOAuthResponse);
                                         }
                                     })) {
                    lenient().when(mockedOAuthResponse.getLocationUri()).thenReturn("http://localhost:8080/location");

                    String url = EndpointUtil.getErrorRedirectURL(exception, parameters);
                    Assert.assertTrue(url.contains(expected), "Expected error redirect url not returned");
                }

            }
        }
    }

    @DataProvider(name = "provideErrorPageData")
    public Object[][] provideErrorPageData() {

        OAuth2Parameters params1 = new OAuth2Parameters();
        OAuth2Parameters params2 = new OAuth2Parameters();
        OAuth2Parameters params3 = new OAuth2Parameters();
        String state = "active";
        String responseType = "dummyResponceType";
        String appName = "myApp";

        params1.setState(state);
        params1.setResponseType(responseType);
        params1.setApplicationName(appName);
        params1.setRedirectURI("http://localhost:8080/callback");

        params2.setState(state);
        params2.setResponseType(responseType);
        params2.setApplicationName(appName);
        params2.setRedirectURI(null);

        params3.setState(null);
        params3.setResponseType(responseType);
        params3.setApplicationName(appName);
        params3.setRedirectURI("http://localhost:8080/callback");

        return new Object[][]{
                {true, true, true, params1, "http://localhost:8080/location", false},
                {true, false, true, params1, "http://localhost:8080/location", false},
                {false, true, true, params1, "http://localhost:8080/location", true},
                {false, false, false, params1, ERROR_PAGE_URL, true},
                {true, true, true, params3, "http://localhost:8080/location", false},
        };
    }

    @Test(dataProvider = "provideErrorPageData")
    public void testGetErrorPageURL(boolean isImplicitResponse, boolean isHybridResponse,
                                    boolean isRedirectToRedirectURI, Object oAuth2ParamObject, String expected,
                                    boolean isDebugOn)
            throws Exception {

        setMockedLog(isDebugOn);

        OAuth2Parameters parameters = (OAuth2Parameters) oAuth2ParamObject;

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);
            when(mockedOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled())
                    .thenReturn(isRedirectToRedirectURI);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);) {
                oAuth2Util.when(() -> OAuth2Util.isImplicitResponseType(anyString())).thenReturn(isImplicitResponse);
                oAuth2Util.when(() -> OAuth2Util.isHybridResponseType(anyString())).thenReturn(isHybridResponse);

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                lenient().when(mockedOAuthResponse.getLocationUri()).thenReturn("http://localhost:8080/location");
                lenient().when(mockedHttpServletRequest.getParameter(contains(REDIRECT))).thenReturn(
                        "http://localhost:8080/location");

                String url = EndpointUtil.getErrorPageURL(mockedHttpServletRequest, "invalid request",
                        "invalid request object", "invalid request", "test", parameters);

                Assert.assertTrue(url.contains(expected), "Expected error redirect url not returned");
            }
        }
    }

    @DataProvider(name = "provideParams")
    public Object[][] provideParams() {

        MultivaluedMap<String, String> paramMap1 = new MultivaluedHashMap<>();
        List<String> list1 = new ArrayList<>();
        list1.add("value1");
        list1.add("value2");
        paramMap1.put("paramName1", list1);

        Map<String, String[]> requestParams1 = new HashedMap();
        requestParams1.put("reqParam1", new String[]{"val1", "val2"});

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<>();
        List<String> list2 = new ArrayList<>();
        list2.add("value1");
        paramMap2.put("paramName1", list2);

        Map<String, String[]> requestParams2 = new HashedMap();
        requestParams2.put("reqParam1", new String[]{"val1"});

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {paramMap1, requestParams1, false},
                {paramMap2, requestParams1, false},
                {paramMap2, requestParams2, true},
                {null, null, true}
        });
    }

    @Test(dataProvider = "provideParams")
    public void testValidateParams(Object paramObject, Map<String, String[]> requestParams, boolean expected,
                                   boolean diagnosticLogEnabled) {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);) {
            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogEnabled);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramObject;
            lenient().when(mockedHttpServletRequest.getParameterMap()).thenReturn(requestParams);
            boolean isValid =
                    EndpointUtil.validateParams(mockedHttpServletRequest, mockedHttpServletResponse, paramMap);
            Assert.assertEquals(isValid, expected);
        }
    }

    @Test
    public void testGetLoginPageURLFromCache() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class)) {
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);

            try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);) {
                Map<String, String[]> reqParams = new HashedMap();
                reqParams.put("param1", new String[]{"value1"});

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockedSessionDataCache);
                when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                        thenReturn(mockedSessionDataCacheEntry);
                when(mockedSessionDataCacheEntry.getParamMap()).thenReturn(reqParams);

                oAuth2Util.when(OAuth2Util::getClientTenatId).thenReturn(-1234);
                oAuth2Util.when(OAuth2Util::clearClientTenantId).thenAnswer(invocation -> null);

                mockServiceURLBuilder(COMMONAUTH_URL, serviceURLBuilder);
                frameworkUtils.when(() -> FrameworkUtils.addAuthenticationRequestToCache(anyString(),
                                any(AuthenticationRequestCacheEntry.class)))
                        .thenAnswer(invocation -> null);

                String url = EndpointUtil.getLoginPageURL(clientId, sessionDataKey, true, true,
                        new HashSet<String>() {{
                            add("openid");
                        }});
                Assert.assertEquals(url, "https://localhost:9443/commonauth?sessionDataKey=1234567890&type=oidc");
            }
        }
    }

    @Test
    public void testGetServices() {

        assertTrue(OIDCProviderServiceFactory.getOIDCService() instanceof DefaultOIDCProcessor,
                "Retrieved incorrect OIDCService");
        assertTrue(OAuth2ServiceFactory.getOAuth2Service() instanceof OAuth2Service,
                "Retrieved incorrect OAuth2Service");
        assertTrue(OAuthServerConfigurationFactory.getOAuthServerConfiguration()
                        instanceof OAuthServerConfiguration,
                "Retrieved incorrect OAuthServerConfiguration");
        assertTrue(OAuth2TokenValidatorServiceFactory.getOAuth2TokenValidatorService()
                        instanceof OAuth2TokenValidationService,
                "Retrieved incorrect OAuth2TokenValidationService");
        assertTrue(RequestObjectServiceFactory.getRequestObjectService() instanceof RequestObjectService,
                "Retrieved incorrect RequestObjectService");
    }

    @Test
    public void testGetRealmInfo() {

        String expectedRealm = "Basic realm=is.com";
        try (MockedStatic<ServerConfiguration> serverConfiguration = mockStatic(ServerConfiguration.class);) {
            serverConfiguration.when(ServerConfiguration::getInstance).thenReturn(mockedServerConfiguration);
            when(mockedServerConfiguration.getFirstProperty("HostName")).thenReturn("is.com");
            assertEquals(EndpointUtil.getRealmInfo(), expectedRealm);
        }
    }

    @Test
    public void testGetOAuthServerConfigProperties() throws Exception {

        try (MockedStatic<OAuthServerConfigurationFactory> oAuthServerConfigurationFactory =
                mockStatic(OAuthServerConfigurationFactory.class)) {
            oAuthServerConfigurationFactory.when(OAuthServerConfigurationFactory::getOAuthServerConfiguration)
                    .thenReturn(mockedOAuthServerConfiguration);
            setMockedOAuthServerConfiguration();
            assertEquals(EndpointUtil.getUserInfoRequestValidator(), USER_INFO_REQUEST_VALIDATOR);
            assertEquals(EndpointUtil.getAccessTokenValidator(), USER_INFO_TOKEN_VALIDATOR);
            assertEquals(EndpointUtil.getUserInfoResponseBuilder(), USER_INFO_RESPONSE_BUILDER);
            assertEquals(EndpointUtil.getUserInfoClaimRetriever(), USER_INFO_CLAIM_RETRIEVER);
            assertEquals(EndpointUtil.getUserInfoClaimDialect(), USER_INFO_CLAIM_DIALECT);
        }

    }

    @DataProvider(name = "provideState")
    public Object[][] provideState() {

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {"ACTIVE"},
                {"INACTIVE"},
                {null},
        });
    }

    @Test(dataProvider = "provideState")
    public void testValidateOauthApplication(String state, boolean diagnosticLogEnabled) {

        try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
             MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);) {
            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogEnabled);
            oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(mockedOAuth2Service);
            when(mockedOAuth2Service.getOauthApplicationState(anyString())).thenReturn(state);

            Response response;
            try {
                EndpointUtil.validateOauthApplication(clientId);
            } catch (InvalidApplicationClientException e) {
                InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                response = invalidRequestExceptionMapper.toResponse(e);
                final String responseBody = response.getEntity().toString();
                assertTrue(responseBody.contains(OAuth2ErrorCodes.INVALID_CLIENT), "Expected error code not found");
            }
        }
    }

    private void setMockedLog(boolean isDebugEnabled) throws Exception {

        Constructor<EndpointUtil> constructor = EndpointUtil.class.getDeclaredConstructor(new Class[0]);
        constructor.setAccessible(true);
        Object claimUtilObject = constructor.newInstance(new Object[0]);
        Field logField = claimUtilObject.getClass().getDeclaredField("log");

        Method getDeclaredFields0 = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
        getDeclaredFields0.setAccessible(true);
        Field[] fields = (Field[]) getDeclaredFields0.invoke(Field.class, false);
        Field modifiers = null;
        for (Field each : fields) {
            if ("modifiers".equals(each.getName())) {
                modifiers = each;
                break;
            }
        }
        modifiers.setAccessible(true);
        modifiers.setInt(logField, logField.getModifiers() & ~Modifier.FINAL);

        logField.setAccessible(true);
        logField.set(claimUtilObject, mockedLog);
        lenient().when(mockedLog.isDebugEnabled()).thenReturn(isDebugEnabled);
    }

    private void setMockedOAuthServerConfiguration() {

        when(mockedOAuthServerConfiguration.getOpenIDConnectUserInfoEndpointRequestValidator()).
                thenReturn(USER_INFO_REQUEST_VALIDATOR);
        when(mockedOAuthServerConfiguration.getOpenIDConnectUserInfoEndpointAccessTokenValidator()).
                thenReturn(USER_INFO_TOKEN_VALIDATOR);
        when(mockedOAuthServerConfiguration.getOpenIDConnectUserInfoEndpointResponseBuilder()).
                thenReturn(USER_INFO_RESPONSE_BUILDER);
        when(mockedOAuthServerConfiguration.getOpenIDConnectUserInfoEndpointClaimRetriever()).
                thenReturn(USER_INFO_CLAIM_RETRIEVER);
        when(mockedOAuthServerConfiguration.getOpenIDConnectUserInfoEndpointClaimDialect()).
                thenReturn(USER_INFO_CLAIM_DIALECT);
    }

    private Set<Scope> getScopeList() {
        Set<Scope> scopeList = new HashSet<>();
        // Add some sample scopes.
        scopeList.add(new Scope("internal_login", "Login", "description1"));
        scopeList.add(new Scope("internal_config_mgt_update", "Update Configs", "description2"));
        scopeList.add(new Scope("internal_config_mgt_update", "Update Email Configs",
                "description3"));
        scopeList.add(new Scope("internal_user_mgt_update", "Update Users", "description4"));
        scopeList.add(new Scope("internal_list_tenants", "List Tenant", "description5"));
        return scopeList;
    }

    @Test
    public void testIsExternalizedConsentPageEnabledForSP() throws Exception {

        assertTrue(EndpointUtil.isExternalConsentPageEnabledForSP(getServiceProvider()));
    }

    private ServiceProvider getServiceProvider() {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(EXTERNAL_CONSENTED_APP_NAME);
        serviceProvider.setTenantDomain("testTenantDomain");
        serviceProvider.setApplicationResourceId("sampleId");
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig = new
                LocalAndOutboundAuthenticationConfig();
        localAndOutboundAuthenticationConfig.setUseExternalConsentPage(true);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
        return serviceProvider;
    }

    private static Object[][] addDiagnosticLogStatusToExistingDataProvider(Object[][] existingData) {

        // Combine original values with diagnostic log status.
        Object[][] combinedValues = new Object[existingData.length * 2][];
        for (int i = 0; i < existingData.length; i++) {
            combinedValues[i * 2] = appendValue(existingData[i], true); // Enable diagnostic logs.
            combinedValues[i * 2 + 1] = appendValue(existingData[i], false); // Disable diagnostic logs.
        }
        return combinedValues;
    }

    private static Object[] appendValue(Object[] originalArray, Object value) {

        Object[] newArray = Arrays.copyOf(originalArray, originalArray.length + 1);
        newArray[originalArray.length] = value;
        return newArray;
    }

    @DataProvider(name = "provideResponseTypeAndMode")
    public Object[][] provideResponseTypeAndMode() {

        return new Object[][]{
                {"code", "form_post", false},
                {"code", "jwt", true},
                {"code id_token", null, true},
                {"code token", "jwt", false}
        };
    }

    @Test(dataProvider = "provideResponseTypeAndMode")
    public void testValidateFAPIAllowedResponseMode(String responseType, String responseMode, boolean shouldPass) {

        try {
            EndpointUtil.validateFAPIAllowedResponseTypeAndMode(responseType, responseMode);
        } catch (OAuthProblemException e) {
            Assert.assertFalse(shouldPass, "Expected exception not thrown");
        }
    }

    @Test(description = "Test the validateAppAccess method")
    public void testValidateAppAccess() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
            MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
            MockedStatic<LoggerUtils> loggerUtilsMockedStatic = mockStatic(LoggerUtils.class)) {
            loggerUtilsMockedStatic.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any()))
                    .thenAnswer(invocation -> null);
            ServiceProvider serviceProvider = mock(ServiceProvider.class);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getServiceProvider(anyString())).thenReturn(serviceProvider);
            identityTenantUtilMockedStatic.when(() ->
                    IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);

            // Test the application enabled state.
            when(serviceProvider.isApplicationEnabled()).thenReturn(true);
            EndpointUtil.validateAppAccess("test-consumer-key");

            // Test the application disabled state.
            when(serviceProvider.isApplicationEnabled()).thenReturn(false);
            assertThrows(() -> EndpointUtil.validateAppAccess("test-consumer-key"));

            loggerUtilsMockedStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

            // Test the application disabled state with diagnostic logs.
            when(serviceProvider.isApplicationEnabled()).thenReturn(false);
            assertThrows(() -> EndpointUtil.validateAppAccess("test-consumer-key"));

            // Test the application enabled state with diagnostic logs.
            when(serviceProvider.isApplicationEnabled()).thenReturn(true);
            EndpointUtil.validateAppAccess("test-consumer-key");

            // Test service provider resolving exception.
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getServiceProvider(anyString())).thenThrow(
                    IdentityOAuth2Exception.class);
            assertThrows(() -> EndpointUtil.validateAppAccess("test-consumer-key"));
        }
    }

    @DataProvider
    public Object[][] providePersistImpersonationInfoToSessionDataCache() {

        return new Object[][]{
                {"dummyImpersonator", true},
                {"", true},
                {null, false}
        };
    }

    @Test(dataProvider = "providePersistImpersonationInfoToSessionDataCache")
    public void testPersistImpersonationInfoToSessionDataCache(String impersonatingActor, boolean expected) {

        SessionDataCacheEntry sessionDataCacheEntry = new SessionDataCacheEntry();
        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        sessionDataCacheEntry.setAuthzReqMsgCtx(authzReqMsgCtx);
        OAuthMessage oAuthMessage = mock(OAuthMessage.class);
        Map<String, Object> properties = new HashMap<>();
        properties.put(IMPERSONATING_ACTOR, impersonatingActor);
        lenient().when(oAuthMessage.getProperties()).thenReturn(properties);

        EndpointUtil.persistImpersonationInfoToSessionDataCache(sessionDataCacheEntry, oAuthMessage);
        assertEquals(authzReqMsgCtx.isImpersonationRequest(), expected);
    }
}
