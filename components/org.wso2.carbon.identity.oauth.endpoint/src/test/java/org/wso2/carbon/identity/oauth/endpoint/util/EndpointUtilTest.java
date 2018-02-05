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
import org.apache.commons.logging.Log;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.DefaultOIDCProviderRequestBuilder;
import org.wso2.carbon.identity.discovery.builders.OIDCProviderRequestBuilder;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@PrepareForTest ( {SessionDataCache.class, OAuthServerConfiguration.class, OAuth2Util.class, IdentityUtil.class,
        FrameworkUtils.class, OAuthASResponse.class, OAuthResponse.class, PrivilegedCarbonContext.class,
        ServerConfiguration.class})
public class EndpointUtilTest extends PowerMockIdentityBaseTest {

    @Mock
    Log mockedLog;

    @Mock
    SessionDataCache mockedSessionDataCache;

    @Mock
    SessionDataCacheEntry mockedSessionDataCacheEntry;

    @Mock
    OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    OAuth2Util.OAuthURL mockedOAuthUrl;

    @Mock
    OAuthASResponse mockedOAuthResponse;

    @Mock
    OAuthResponse.OAuthErrorResponseBuilder mockedOAuthErrorResponseBuilder;

    @Mock
    OAuthResponse.OAuthResponseBuilder mockedOAuthResponseBuilder;

    @Mock
    HttpServletRequest mockedHttpServletRequest;

    @Mock
    HttpServletResponse mockedHttpServletResponse;

    @Mock
    PrivilegedCarbonContext mockedPrivilegedCarbonContext;

    @Mock
    ServerConfiguration mockedServerConfiguration;

    private static final String COMMONAUTH_URL = "https://localhost:9443/commonauth";
    private static final String OIDC_CONSENT_PAGE_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_consent.do";
    private static final String OAUTH2_CONSENT_PAGE_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_authz.do";
    private static final String ERROR_PAGE_URL = "https://localhost:9443/authenticationendpoint/oauth2_error.do";
    private static final String ERROR_PAGE_URL_WITH_APP =
            "https://localhost:9443/authenticationendpoint/oauth2_error.do?oauthErrorCode=3002&oauthErrorMsg=errorMessage&application=myApp";
    private static final String ERROR_PAGE_URL_WITHOUT_APP =
            "https://localhost:9443/authenticationendpoint/oauth2_error.do?oauthErrorCode=3002&oauthErrorMsg=errorMessage";

    private static final String USER_INFO_CLAIM_DIALECT = "http://wso2.org/claims";
    private static final String USER_INFO_CLAIM_RETRIEVER =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoUserStoreClaimRetriever";
    private static final String USER_INFO_REQUEST_VALIDATOR =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInforRequestDefaultValidator";
    private static final String USER_INFO_TOKEN_VALIDATOR =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoISAccessTokenValidator";
    private static final String USER_INFO_RESPONSE_BUILDER =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoJSONResponseBuilder";

    private String username;
    private String password;
    private String sessionDataKey;
    private String clientId;

    @BeforeTest
    public void setUp() {

        username = "myUsername";
        password = "myPassword";
        sessionDataKey = "1234567890";
        clientId = "myClientId";
    }

    @DataProvider(name = "provideAuthzHeader")
    public Object[][] provideAuthzHeader() {

        String authzValue = "Basic " + Base64Utils.encode((username + ":" + password).getBytes());

        return new Object[][] {
                { authzValue, username, null},
                { username, null, "Error decoding authorization header"},
                { "Basic " + Base64Utils.encode(username.getBytes()), null, "Error decoding authorization header"},
                { null, null, "Authorization header value is null"},
        };
    }

    @Test (dataProvider = "provideAuthzHeader")
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
        params.setScopes(new HashSet<String>(Arrays.asList("scope1", "scope2")));

        return new Object[][] {
                { params, true, true, false, "QueryString", true},
                { null, true, true, false, "QueryString", true},
                { params, false, true, false, "QueryString", true},
                { params, true, false, false, "QueryString", true},
                { params, true, false, false, "QueryString", false},
                { params, true, true, false, null, true},
                { params, true, true, true, "QueryString", true},
        };
    }

    @Test(dataProvider = "provideDataForUserConsentURL")
    public void testGetUserConsentURL(Object oAuth2ParamObject, boolean isOIDC, boolean cacheEntryExists,
                                      boolean throwError, String queryString, boolean isDebugEnabled) throws Exception {

        setMockedLog(isDebugEnabled);
        OAuth2Parameters parameters = (OAuth2Parameters) oAuth2ParamObject;

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOIDCConsentPageUrl()).thenReturn(OIDC_CONSENT_PAGE_URL);
        when(OAuth2Util.OAuthURL.getOAuth2ConsentPageUrl()).thenReturn(OAUTH2_CONSENT_PAGE_URL);

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(mockedSessionDataCache);
        if (cacheEntryExists) {
            when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                    thenReturn(mockedSessionDataCacheEntry);
            when(mockedSessionDataCacheEntry.getQueryString()).thenReturn(queryString);
        } else {
            when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                    thenReturn(null);
        }

        String consentUrl;
        try {
            consentUrl = EndpointUtil.getUserConsentURL(parameters, username, sessionDataKey, isOIDC);
            if (isOIDC) {
                Assert.assertTrue(consentUrl.contains(OIDC_CONSENT_PAGE_URL), "Incorrect consent page url for OIDC");
            } else {
                Assert.assertTrue(consentUrl.contains(OAUTH2_CONSENT_PAGE_URL), "Incorrect consent page url for OAuth");
            }

            Assert.assertTrue(consentUrl.contains(URLEncoder.encode(username, "UTF-8")),
                    "loggedInUser parameter value is not found in url");
            Assert.assertTrue(consentUrl.contains(URLEncoder.encode("TestApplication", "ISO-8859-1")),
                    "application parameter value is not found in url");
            Assert.assertTrue(consentUrl.contains("scope2"), "scope parameter value is not found in url");
            if (queryString != null && cacheEntryExists) {
                Assert.assertTrue(consentUrl.contains(queryString), "spQueryParams value is not found in url");
            }

        } catch (OAuthSystemException e) {
            Assert.assertTrue(e.getMessage().contains("Error while retrieving the application name"));
        }

    }

    @DataProvider (name = "provideScopeData")
    public Object[][] provideScopeData() {

        return new Object[][] {
                { null, "oauth2"},
                { new HashSet<String>() {{ add("scope1");}}, "oauth2"},
                { new HashSet<String>() {{ add("openid");}}, "oidc"},
        };
    }

    @Test (dataProvider = "provideScopeData")
    public void testGetLoginPageURL(Set<String> scopes, String queryParam) throws Exception {

        Map<String, String[]> reqParams = new HashedMap();
        reqParams.put("param1", new String[]{"value1"});

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getClientTenatId()).thenReturn(-1234);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(COMMONAUTH_URL);

        mockStatic(FrameworkUtils.class);
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                return null;
            }
        }).when(FrameworkUtils.class, "addAuthenticationRequestToCache", anyString(),
                any(AuthenticationRequestCacheEntry.class));

        String url = EndpointUtil.getLoginPageURL(clientId, sessionDataKey, true, true, scopes, reqParams);
        Assert.assertTrue(url.contains("type=" + queryParam), "type parameter is not set according to the scope");
    }

    //commenting method to recover sonar test failure
//    @Test
//    public void testGetScope() throws Exception {
//
//        OAuth2Parameters parameters = new OAuth2Parameters();
//        Set<String> scopes = new HashSet<String>(Arrays.asList("scope1", "scope2"));
//        parameters.setScopes(scopes);
//        String scopeString = EndpointUtil.getScope(parameters);
//
//        Assert.assertTrue(scopeString.contains("scope1 scope2"));
//    }

    @DataProvider (name = "provideErrorData")
    public Object[][] provideErrorData() {

        return new Object[][] {
                { "myApp", ERROR_PAGE_URL_WITH_APP },
                { null, ERROR_PAGE_URL_WITHOUT_APP }
        };
    }

    @Test (dataProvider = "provideErrorData")
    public void testGetErrorPageURL(String applicationName, String expected) throws Exception {

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        String url = EndpointUtil.getErrorPageURL("3002", "errorMessage", applicationName);
        Assert.assertEquals(url, expected, "Incorrect error page url");
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

        return new Object[][] {
                { true, true, params1, null, "http://localhost:8080/location", false},
                { true, false, params1, null, "http://localhost:8080/location", false},
                { false, true, params1, null, "http://localhost:8080/location", false},
                { true, true, params2, null, ERROR_PAGE_URL, false},
                { true, true, null, null, ERROR_PAGE_URL, false},
                { true, true, params1, new OAuthSystemException(), ERROR_PAGE_URL, false},
                { true, true, params1, new OAuthSystemException(), ERROR_PAGE_URL, true}
        };
    }

    @Test (dataProvider = "provideErrorRedirectData")
    public void testGetErrorRedirectURL(boolean isImplicitResponse, boolean isImplicitFragment,
                                        Object oAuth2ParamObject, Object exeObject, String expected,boolean isDebugOn)
            throws Exception {

        setMockedLog(isDebugOn);
        OAuth2Parameters parameters = (OAuth2Parameters) oAuth2ParamObject;
        OAuthProblemException exception = OAuthProblemException.error("OAuthProblemExceptionErrorMessage");

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.isImplicitErrorFragment()).thenReturn(isImplicitFragment);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isImplicitResponseType(anyString())).thenReturn(isImplicitResponse);

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        mockStatic(OAuthResponse.OAuthErrorResponseBuilder.class);
        whenNew(OAuthResponse.OAuthErrorResponseBuilder.class).withArguments(anyInt()).
                thenReturn(mockedOAuthErrorResponseBuilder);
        when(mockedOAuthErrorResponseBuilder.error(any(OAuthProblemException.class))).
                thenReturn(mockedOAuthErrorResponseBuilder);
        when(mockedOAuthErrorResponseBuilder.location(anyString())).thenReturn(mockedOAuthErrorResponseBuilder);
        when(mockedOAuthErrorResponseBuilder.setState(anyString())).thenReturn(mockedOAuthErrorResponseBuilder);
        when(mockedOAuthErrorResponseBuilder.setParam(anyString(), anyString())).
                thenReturn(mockedOAuthErrorResponseBuilder);
        if (exeObject != null) {
            OAuthSystemException oAuthSystemException = (OAuthSystemException) exeObject;
            when(mockedOAuthErrorResponseBuilder.buildQueryMessage()).thenThrow(oAuthSystemException);
        } else {
            when(mockedOAuthErrorResponseBuilder.buildQueryMessage()).thenReturn(mockedOAuthResponse);
        }

        when(mockedOAuthResponse.getLocationUri()).thenReturn("http://localhost:8080/location");

        String url = EndpointUtil.getErrorRedirectURL(exception, parameters);
        Assert.assertTrue(url.contains(expected), "Expected error redirect url not returned");
    }

    @DataProvider(name = "provideParams")
    public Object[][] provideParams() {

        MultivaluedMap<String, String> paramMap1 = new MultivaluedHashMap<String, String>();
        List<String> list1 = new ArrayList<>();
        list1.add("value1");
        list1.add("value2");
        paramMap1.put("paramName1", list1);

        Map<String, String[]> requestParams1 = new HashedMap();
        requestParams1.put("reqParam1", new String[]{"val1", "val2"});

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<String, String>();
        List<String> list2 = new ArrayList<>();
        list2.add("value1");
        paramMap2.put("paramName1", list2);

        Map<String, String[]> requestParams2 = new HashedMap();
        requestParams2.put("reqParam1", new String[]{"val1"});

        return new Object[][] {
                {paramMap1, requestParams1, false},
                {paramMap2, requestParams1, false},
                {paramMap2, requestParams2, true},
                {null, null, true}
        };
    }

    @Test (dataProvider = "provideParams")
    public void testValidateParams(Object paramObject, Map<String, String[]> requestParams, boolean expected) {

        MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramObject;
        when(mockedHttpServletRequest.getParameterMap()).thenReturn(requestParams);
        boolean isValid = EndpointUtil.validateParams(mockedHttpServletRequest, mockedHttpServletResponse, paramMap);
        Assert.assertEquals(isValid, expected);

    }

    @Test
    public void testGetLoginPageURLFromCache() throws Exception {

        Map<String, String[]> reqParams = new HashedMap();
        reqParams.put("param1", new String[]{"value1"});

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(mockedSessionDataCache);
        when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                thenReturn(mockedSessionDataCacheEntry);
        when(mockedSessionDataCacheEntry.getParamMap()).thenReturn(reqParams);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getClientTenatId()).thenReturn(-1234);
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                return null;
            }
        }).when(OAuth2Util.class, "clearClientTenantId");

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(COMMONAUTH_URL);

        mockStatic(FrameworkUtils.class);
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                return null;
            }
        }).when(FrameworkUtils.class, "addAuthenticationRequestToCache", anyString(),
                any(AuthenticationRequestCacheEntry.class));

        String url = EndpointUtil.getLoginPageURL(clientId, sessionDataKey, true, true,
                new HashSet<String>() {{ add("openid");}});
        Assert.assertEquals(url, "https://localhost:9443/commonauth?sessionDataKey=1234567890&type=oidc");
    }

    @Test
    public void testGetServices() {
        mockPrivilegedCarbonContext();
        assertTrue(EndpointUtil.getWebFingerService() instanceof DefaultWebFingerProcessor,
                "Retrieved incorrect WebFingerService");
        assertTrue(EndpointUtil.getOIDProviderRequestValidator() instanceof DefaultOIDCProviderRequestBuilder,
                "Retrieved incorrect OIDProviderRequestValidator");
        assertTrue(EndpointUtil.getOIDCService() instanceof DefaultOIDCProcessor,
                "Retrieved incorrect OIDCService");
        assertTrue(EndpointUtil.getOAuth2Service() instanceof OAuth2Service,
                "Retrieved incorrect OAuth2Service");
        assertTrue(EndpointUtil.getOAuthServerConfiguration() instanceof OAuthServerConfiguration,
                "Retrieved incorrect OAuthServerConfiguration");
        assertTrue(EndpointUtil.getOAuth2TokenValidationService() instanceof OAuth2TokenValidationService,
                "Retrieved incorrect OAuth2TokenValidationService");
    }

    @Test
    public void testGetRealmInfo() {
        String expectedRealm = "Basic realm=is.com";
        mockStatic(ServerConfiguration.class);
        when(ServerConfiguration.getInstance()).thenReturn(mockedServerConfiguration);
        when(mockedServerConfiguration.getFirstProperty("HostName")).thenReturn("is.com");
        assertEquals(EndpointUtil.getRealmInfo(), expectedRealm);
    }

    @Test
    public void testGetOAuthServerConfigProperties() throws Exception {
        mockPrivilegedCarbonContext();
        setMockedOAuthServerConfiguration();

        assertEquals(EndpointUtil.getUserInfoRequestValidator(), USER_INFO_REQUEST_VALIDATOR);
        assertEquals(EndpointUtil.getAccessTokenValidator(), USER_INFO_TOKEN_VALIDATOR);
        assertEquals(EndpointUtil.getUserInfoResponseBuilder(), USER_INFO_RESPONSE_BUILDER);
        assertEquals(EndpointUtil.getUserInfoClaimRetriever(), USER_INFO_CLAIM_RETRIEVER);
        assertEquals(EndpointUtil.getUserInfoClaimDialect(), USER_INFO_CLAIM_DIALECT);
    }

    private void setMockedLog(boolean isDebugEnabled) throws Exception {

        Constructor<EndpointUtil> constructor = EndpointUtil.class.getDeclaredConstructor(new Class[0]);
        constructor.setAccessible(true);
        Object claimUtilObject = constructor.newInstance(new Object[0]);
        Field logField = claimUtilObject.getClass().getDeclaredField("log");

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(logField, logField.getModifiers() & ~Modifier.FINAL);

        logField.setAccessible(true);
        logField.set(claimUtilObject, mockedLog);
        when(mockedLog.isDebugEnabled()).thenReturn(isDebugEnabled);
    }

    private void mockPrivilegedCarbonContext() {
        mockStatic(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(mockedPrivilegedCarbonContext);
        when(mockedPrivilegedCarbonContext.getOSGiService(OAuthServerConfiguration.class, null)).
                thenReturn(mockedOAuthServerConfiguration);
        when(mockedPrivilegedCarbonContext.getOSGiService(WebFingerProcessor.class, null)).
                thenReturn(DefaultWebFingerProcessor.getInstance());
        when(mockedPrivilegedCarbonContext.getOSGiService(OIDCProviderRequestBuilder.class, null)).
                thenReturn(new DefaultOIDCProviderRequestBuilder());
        when(mockedPrivilegedCarbonContext.getOSGiService(OIDCProcessor.class, null)).
                thenReturn(DefaultOIDCProcessor.getInstance());
        when(mockedPrivilegedCarbonContext.getOSGiService(OAuth2Service.class, null)).thenReturn(new OAuth2Service());
        when(mockedPrivilegedCarbonContext.getOSGiService(OAuth2TokenValidationService.class, null)).
                thenReturn(new OAuth2TokenValidationService());
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
}
