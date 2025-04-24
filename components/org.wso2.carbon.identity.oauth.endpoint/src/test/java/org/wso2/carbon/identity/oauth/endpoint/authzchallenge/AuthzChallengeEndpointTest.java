/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.authzChallenge.event.AuthzChallengeInterceptor;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;

import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class AuthzChallengeEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    OAuthAdminServiceImpl oAuthAdminService;

    @Mock
    OAuth2ScopeService oAuth2ScopeService;

    @Mock
    RequestObjectService requestObjectService;

    @Mock
    OpenIDConnectClaimFilterImpl openIDConnectClaimFilter;

    @Mock
    SSOConsentService mockedSSOConsentService;

    @Mock
    OAuth2TokenValidationService oAuth2TokenValidator;

    @Mock
    BundleContext bundleContext;

    MockedConstruction<ServiceTracker> mockedConstruction;

    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_NAME = "myApp";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String INACTIVE_APP_NAME = "inactiveApp";
    private static final String USERNAME = "user1";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String AUTH_SESSION = "auth_session";
    private static final String ATTR_AUTHZ_CHALLENGE = "isAuthzChallenge";

    private AuthzChallengeEndpoint authzChallengeEndpoint;
    private ServiceProvider dummySp;

    private KeyStore clientKeyStore;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        authzChallengeEndpoint = new AuthzChallengeEndpoint();

        initiateInMemoryH2();
        try {
            createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            throw new RuntimeException("OAuth app already exists", e);
        }
        try {
            createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME,
                    "INACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            // ignore
        }

        dummySp = new ServiceProvider();
        dummySp.setApplicationResourceId("sampleApp");
    }

    @BeforeMethod
    public void setUpMethod() {

        MockitoAnnotations.openMocks(this);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        mockDatabase(identityDatabaseUtil);
        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(OAuth2Service.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2Service});
                    }
                    if (argumentCaptor.getValue().contains(OpenIDConnectClaimFilterImpl.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{openIDConnectClaimFilter});
                    }
                    if (argumentCaptor.getValue().contains(SSOConsentService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{mockedSSOConsentService});
                    }
                    if (argumentCaptor.getValue().contains(RequestObjectService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{requestObjectService});
                    }
                    if (argumentCaptor.getValue().contains(OAuthAdminServiceImpl.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuthAdminService});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2ScopeService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2ScopeService});
                    }
                    if (argumentCaptor.getValue().contains(OAuthServerConfiguration.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{mockOAuthServerConfiguration});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2TokenValidationService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2TokenValidator});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDownMethod() {

        if (identityDatabaseUtil != null) {
            identityDatabaseUtil.close();
        }
        Mockito.reset(oAuth2ScopeService);
        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @AfterClass
    public void tearDown() throws Exception {

        super.cleanData();
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @DataProvider(name = "provideAuthzChallengePostData")
    public Object[][] provideAuthzChallengePostData() {

        // Valid parameters
        MultivaluedMap<String, String> validParams = new MultivaluedHashMap<>();
        validParams.add(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
        validParams.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        validParams.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);

        Map<String, String[]> validRequestParams = new HashMap<>();
        validRequestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.CODE.toString()});
        validRequestParams.put(OAuth.OAUTH_CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        validRequestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});

        // Missing required parameter - response_type
        MultivaluedMap<String, String> missingResponseTypeParams = new MultivaluedHashMap<>();
        missingResponseTypeParams.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        missingResponseTypeParams.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);

        Map<String, String[]> missingResponseTypeRequestParams = new HashMap<>();
        missingResponseTypeRequestParams.put(OAuth.OAUTH_CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        missingResponseTypeRequestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});

        // Missing required parameter - client_id
        MultivaluedMap<String, String> missingClientIdParams = new MultivaluedHashMap<>();
        missingClientIdParams.add(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
        missingClientIdParams.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);

        Map<String, String[]> missingClientIdRequestParams = new HashMap<>();
        missingClientIdRequestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.CODE.toString()});
        missingClientIdRequestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});

        // Missing required parameter - redirect_uri
        MultivaluedMap<String, String> missingRedirectUriParams = new MultivaluedHashMap<>();
        missingRedirectUriParams.add(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
        missingRedirectUriParams.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);

        Map<String, String[]> missingRedirectUriRequestParams = new HashMap<>();
        missingRedirectUriRequestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.CODE.toString()});
        missingRedirectUriRequestParams.put(OAuth.OAUTH_CLIENT_ID, new String[]{CLIENT_ID_VALUE});

        // Duplicate parameter - response_type
        MultivaluedMap<String, String> duplicateResponseTypeParams = new MultivaluedHashMap<>();
        duplicateResponseTypeParams.add(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
        duplicateResponseTypeParams.add(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
        duplicateResponseTypeParams.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        duplicateResponseTypeParams.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);

        Map<String, String[]> duplicateResponseTypeRequestParams = new HashMap<>();
        duplicateResponseTypeRequestParams.put(OAuth.OAUTH_RESPONSE_TYPE,
                new String[]{ResponseType.CODE.toString(), ResponseType.CODE.toString()});
        duplicateResponseTypeRequestParams.put(OAuth.OAUTH_CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        duplicateResponseTypeRequestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});

        // Duplicate parameter - client_id
        MultivaluedMap<String, String> duplicateClientIdParams = new MultivaluedHashMap<>();
        duplicateClientIdParams.add(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
        duplicateClientIdParams.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        duplicateClientIdParams.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        duplicateClientIdParams.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);

        Map<String, String[]> duplicateClientIdRequestParams = new HashMap<>();
        duplicateClientIdRequestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.CODE.toString()});
        duplicateClientIdRequestParams.put(OAuth.OAUTH_CLIENT_ID, new String[]{CLIENT_ID_VALUE, CLIENT_ID_VALUE});
        duplicateClientIdRequestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});

        // Return test cases with parameters, request params map, flags for missing required param and duplicate param
        return new Object[][] {
                {validParams, validRequestParams, false, false},
                {missingResponseTypeParams, missingResponseTypeRequestParams, true, false},
                {missingClientIdParams, missingClientIdRequestParams, true, false},
                {missingRedirectUriParams, missingRedirectUriRequestParams, true, false},
                {duplicateResponseTypeParams, duplicateResponseTypeRequestParams, false, true},
                {duplicateClientIdParams, duplicateClientIdRequestParams, false, true}
        };
    }

    @Test(dataProvider = "provideAuthzChallengePostData")
    public void testAuthorizeChallengeInitialPost(MultivaluedMap<String, String> paramMap,
                                                  Map<String, String[]> requestParams, boolean missingRequiredParam,
                                                  boolean duplicateParam) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class)) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);

            when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
            when(httpServletRequest.getParameterNames()).thenReturn(new Vector<>(requestParams.keySet()).elements());

            when(httpServletRequest.getAttribute(ATTR_AUTHZ_CHALLENGE)).thenReturn(true);

            OAuthClientAuthnContext authClientAuthnContext = new OAuthClientAuthnContext();
            authClientAuthnContext.setClientId(CLIENT_ID_VALUE);
            authClientAuthnContext.setAuthenticated(true);
            when(httpServletRequest.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT))
                    .thenReturn(authClientAuthnContext);

            AuthzChallengeEndpoint spyEndpoint = spy(authzChallengeEndpoint);
            Response mockResponse = Response.status(HttpServletResponse.SC_FORBIDDEN).entity("Mocked response").build();
            doReturn(mockResponse).when(spyEndpoint).handleInitialAuthzChallengeRequest(
                    any(HttpServletRequest.class), any(HttpServletResponse.class), anyBoolean());

            Response response = spyEndpoint.authorizeChallengeInitialPost(
                    httpServletRequest, httpServletResponse, paramMap);

            assertNotNull(response, "Response should not be null");

            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super"))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                    .thenReturn("carbon.super");

            if (missingRequiredParam || duplicateParam) {
                assertEquals(response.getStatus(), HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid requests should return BAD_REQUEST status");

                String responseBody = response.getEntity().toString();
                assertTrue(responseBody.contains("error"), "Response should contain error information");

                if (missingRequiredParam) {
                    assertTrue(responseBody.contains("invalid_request"),
                            "Response should indicate invalid request for missing parameters");
                }

                if (duplicateParam) {
                    assertTrue(responseBody.contains("invalid_request"),
                            "Response should indicate invalid request for duplicate parameters");
                }

                verify(spyEndpoint, never()).handleInitialAuthzChallengeRequest(
                        any(HttpServletRequest.class), any(HttpServletResponse.class), anyBoolean());
            } else {
                assertEquals(response.getStatus(), HttpServletResponse.SC_FORBIDDEN,
                        "Valid request should return the mocked response status");
                assertEquals(response.getEntity(), "Mocked response",
                        "Valid request should return the mocked response entity");

                verify(spyEndpoint, times(1)).handleInitialAuthzChallengeRequest(
                        any(HttpServletRequest.class), any(HttpServletResponse.class), anyBoolean());
            }
        }
    }

    @DataProvider(name = "subsequentAuthzChallengeRequestDataProvider")
    public Object[][] subsequentAuthzChallengeRequestDataProvider() {

        return new Object[][] {
                {
                        "{\"client_id\":\"some-client-id\"}",
                        HttpServletResponse.SC_BAD_REQUEST,
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                        "Should reject request with missing auth_session"
                },
                {
                        null,
                        HttpServletResponse.SC_BAD_REQUEST,
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code(),
                        "Should reject null payload"
                },
                {
                        "{" + AUTH_SESSION + ":\"valid-session-id\", " + AUTH_SESSION + ":\"another-session-id\"}",
                        HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Should reject payload with duplicated parameters"
                },
                {
                        "{"
                                + "\"auth_session\":\"valid-session-id\","
                                + "\"selectedAuthenticator\":{"
                                + "\"authenticatorId\":\"QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM\","
                                + "\"params\":{"
                                + "\"username\":\"testuser\","
                                + "\"password\":\"testpass\""
                                + "}"
                                + "}"
                                + "}",
                        HttpServletResponse.SC_ACCEPTED,
                        null,
                        "Should handle valid subsequent auth challenge request with authenticator"
                }

        };
    }


    @Test(dataProvider = "subsequentAuthzChallengeRequestDataProvider")
    public void testAuthorizeChallengeSubsequentPost(String payload, int expectedStatus, String expectedErrorCode,
                                                     String description) throws Exception {

        AuthzChallengeEndpoint authzChallengeEndpoint = new AuthzChallengeEndpoint();
        AuthzChallengeEndpoint spyAuthzChallengeEndpoint = spy(authzChallengeEndpoint);

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);

        String authSession = null;
        try {
            JsonObject payloadJson = JsonParser.parseString(payload).getAsJsonObject();
            if (payloadJson.has("auth_session")) {
                authSession = payloadJson.get("auth_session").getAsString();
            }
        } catch (Exception e) {
            // ignore
        }

        if (authSession != null) {
            try (MockedStatic<SessionDataCache> sessionDataCacheMock = mockStatic(SessionDataCache.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class)) {

                identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super"))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn("carbon.super");

                SessionDataCache mockSessionDataCache = mock(SessionDataCache.class);
                SessionDataCacheEntry mockSessionDataCacheEntry = expectedStatus == HttpServletResponse.SC_OK ?
                        mock(SessionDataCacheEntry.class) : null;

                sessionDataCacheMock.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                when(mockSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class)))
                        .thenReturn(mockSessionDataCacheEntry);

                if (expectedStatus == HttpServletResponse.SC_ACCEPTED) {
                    doReturn(Response.status(HttpServletResponse.SC_ACCEPTED).build())
                            .when(spyAuthzChallengeEndpoint).handleSubsequentAuthzChallengeRequest(
                                    eq(mockRequest), eq(mockResponse), anyString());
                }

                Response response = spyAuthzChallengeEndpoint.authorizeChallengeSubsequentPost(
                        mockRequest, mockResponse, payload);

                assertEquals(response.getStatus(), expectedStatus, description);

                if (expectedStatus == HttpServletResponse.SC_BAD_REQUEST && expectedErrorCode != null &&
                        response.getEntity() != null) {
                    String responseEntity = response.getEntity().toString();
                    assertTrue(responseEntity.contains(expectedErrorCode),
                            "Response should contain error code: " + expectedErrorCode);
                }
            }
        } else {
            try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class)) {
                identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super"))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn("carbon.super");

                Response response = spyAuthzChallengeEndpoint.authorizeChallengeSubsequentPost(
                        mockRequest, mockResponse, payload);

                assertEquals(response.getStatus(), expectedStatus, description);

                if (expectedStatus == HttpServletResponse.SC_BAD_REQUEST && expectedErrorCode != null &&
                        response.getEntity() != null) {
                    String responseEntity = response.getEntity().toString();
                    assertTrue(responseEntity.contains(expectedErrorCode),
                            "Response should contain error code: " + expectedErrorCode);
                }
            }
        }
    }

    @DataProvider(name = "requestHeadersData")
    public Object[][] getRequestHeadersData() {

        return new Object[][]{
                {
                        new String[]{"Authorization", "Content-Type", "Accept"},
                        new Vector[]{
                                new Vector<>(Collections.singletonList("Bearer token123")),
                                new Vector<>(Collections.singletonList("application/json")),
                                new Vector<>(Collections.singletonList("application/json"))
                        },
                        new HttpRequestHeader[]{
                                new HttpRequestHeader("Authorization", new String[]{"Bearer token123"}),
                                new HttpRequestHeader("Content-Type", new String[]{"application/json"}),
                                new HttpRequestHeader("Accept", new String[]{"application/json"})
                        }
                },
                { new String[]{"Accept"}, new Vector[]{
                        new Vector<>(java.util.Arrays.asList("application/json", "text/html"))},
                        new HttpRequestHeader[]{new HttpRequestHeader("Accept", new String[]{"application/json",
                                "text/html"})}
                },
                {new String[]{}, new Vector[]{}, null}
        };
    }

    @Test(dataProvider = "requestHeadersData")
    public void testExtractHeaders(String[] headerNames, Vector<String>[] headerValues,
                                   HttpRequestHeader[] expectedHeaders)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        Enumeration<String> headerNamesEnum = headerNames.length > 0 ?
                new Vector<>(java.util.Arrays.asList(headerNames)).elements() :
                Collections.emptyEnumeration();
        when(httpServletRequest.getHeaderNames()).thenReturn(headerNamesEnum);

        for (int i = 0; i < headerNames.length; i++) {
            when(httpServletRequest.getHeaders(headerNames[i])).thenReturn(headerValues[i].elements());
        }

        Method extractHeadersMethod = AuthzChallengeEndpoint.class.getDeclaredMethod(
                "extractHeaders", HttpServletRequest.class);
        extractHeadersMethod.setAccessible(true);

        HttpRequestHeader[] actualHeaders =
                (HttpRequestHeader[]) extractHeadersMethod.invoke(null, httpServletRequest);

        if (expectedHeaders == null) {
            Assert.assertNull(actualHeaders);
        } else {
            Assert.assertEquals(actualHeaders.length, expectedHeaders.length);
            for (int i = 0; i < expectedHeaders.length; i++) {
                Assert.assertEquals(actualHeaders[i].getName(), expectedHeaders[i].getName());
                Assert.assertEquals(actualHeaders[i].getValue(), expectedHeaders[i].getValue());
            }
        }
    }

    @DataProvider(name = "dpopProcessingData")
    public Object[][] dpopProcessingData() {

        return new Object[][]{
                {true, "sample-thumbprint", true},
                {true, null, false},
                {false, "ignored-thumbprint", false},
                {null, "ignored-thumbprint", false}
        };
    }

    @Test(dataProvider = "dpopProcessingData")
    public void testProcessDPoPHeader(Boolean interceptorEnabled, String returnedThumbprint,
                                      boolean expectThumbprintSet) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        OAuthMessage mockOAuthMessage = mock(OAuthMessage.class);

        AuthzChallengeInterceptor mockInterceptor = mock(AuthzChallengeInterceptor.class);
        if (interceptorEnabled != null) {
            when(mockInterceptor.isEnabled()).thenReturn(interceptorEnabled);
            when(mockInterceptor.handleAuthzChallengeReq(any())).thenReturn(returnedThumbprint);
        }

        OAuth2ServiceComponentHolder holderMock = mock(OAuth2ServiceComponentHolder.class);
        try (MockedStatic<OAuth2ServiceComponentHolder> staticHolder = mockStatic(OAuth2ServiceComponentHolder.class)) {
            staticHolder.when(OAuth2ServiceComponentHolder::getInstance).thenReturn(holderMock);

            when(holderMock.getAuthzChallengeInterceptors())
                    .thenReturn(interceptorEnabled != null ?
                            Collections.singletonList(mockInterceptor) :
                            Collections.emptyList());

            Method method = AuthzChallengeEndpoint.class.getDeclaredMethod("processDPoPHeader",
                    HttpServletRequest.class, OAuthMessage.class);
            method.setAccessible(true);
            method.invoke(new AuthzChallengeEndpoint(), mockRequest, mockOAuthMessage);

            if (expectThumbprintSet) {
                verify(mockOAuthMessage).setDPoPThumbprint(returnedThumbprint);
            } else {
                verify(mockOAuthMessage, never()).setDPoPThumbprint(any());
            }
        }
    }

    @DataProvider(name = "dpopThumbprintTestData")
    public Object[][] dpopThumbprintTestData() {

        return new Object[][] {

                {"validSession", "abc123", "abc123", true, null, null},
                {"validSession", null, "abc123", true, null, null},
                {"validSession", null, null, false, null, null},
                {null, null, null, false, AuthServiceClientException.class,
                        AuthServiceConstants.ErrorMessage.ERROR_AUTHENTICATION_CONTEXT_NULL.code()},
                {"validSession", "abc123", "xyz789", true, AuthServiceException.class,
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code()},
                {"validSession", "abc123", null, true, AuthServiceException.class,
                        AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST.code()}
        };
    }

    @Test(dataProvider = "dpopThumbprintTestData")
    public void testValidateDPoPThumbprint(String sessionDataKey,
                                           String cachedThumbprint,
                                           String currentThumbprint,
                                           boolean interceptorEnabled,
                                           Class<Exception> expectedException,
                                           String expectedErrorCode)
            throws IdentityOAuth2Exception {

        try (MockedStatic<OAuth2ServiceComponentHolder> mockedStaticHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
             MockedStatic<SessionDataCache> sessionDataCacheMockedStatic = mockStatic(SessionDataCache.class)) {

            OAuth2ServiceComponentHolder mockComponentHolder = mock(OAuth2ServiceComponentHolder.class);
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);
            Optional<String> optionalSessionDataKey = Optional.ofNullable(sessionDataKey);

            SessionDataCacheEntry mockCacheEntry = mock(SessionDataCacheEntry.class);
            SessionDataCache mockSessionDataCache = mock(SessionDataCache.class);
            when(mockCacheEntry.getDPoPThumbprint()).thenReturn(cachedThumbprint);

            sessionDataCacheMockedStatic.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
            if (sessionDataKey != null) {
                when(mockSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).thenReturn(mockCacheEntry);
            } else {
                when(mockSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).thenReturn(null);
            }

            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super"))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                    .thenReturn("carbon.super");

            AuthzChallengeInterceptor mockInterceptor = mock(AuthzChallengeInterceptor.class);
            when(mockInterceptor.isEnabled()).thenReturn(interceptorEnabled);
            if (interceptorEnabled && currentThumbprint != null) {
                when(mockInterceptor.handleAuthzChallengeReq(any(OAuth2AuthzChallengeReqDTO.class)))
                        .thenReturn(currentThumbprint);
            }

            List<AuthzChallengeInterceptor> interceptorList = Collections.singletonList(mockInterceptor);

            mockedStaticHolder.when(OAuth2ServiceComponentHolder::getInstance).thenReturn(mockComponentHolder);
            when(mockComponentHolder.getAuthzChallengeInterceptors()).thenReturn(interceptorList);

            AuthzChallengeEndpoint spyAuthzChallengeEndpoint = spy(AuthzChallengeEndpoint.class);
            OAuth2AuthzChallengeReqDTO mockDTO = mock(OAuth2AuthzChallengeReqDTO.class);
            when(spyAuthzChallengeEndpoint.buildAuthzChallengeReqDTO(mockRequest)).thenReturn(mockDTO);

            if (expectedException != null) {
                try {
                    Method method = AuthzChallengeEndpoint.class.getDeclaredMethod("validateDPoPThumbprint",
                            HttpServletRequest.class, Optional.class);
                    method.setAccessible(true);
                    method.invoke(spyAuthzChallengeEndpoint, mockRequest, optionalSessionDataKey);
                    fail("Expected exception was not thrown: " + expectedException.getName());
                } catch (Exception e) {
                    assertTrue(expectedException.isInstance(e.getCause()));
                    if (expectedErrorCode != null && e.getCause() instanceof AuthServiceException) {
                        assertEquals(((AuthServiceException) e.getCause()).getErrorCode(), expectedErrorCode);
                    }
                }
            } else {
                try {
                    Method method = AuthzChallengeEndpoint.class.getDeclaredMethod("validateDPoPThumbprint",
                            HttpServletRequest.class, Optional.class);
                    method.setAccessible(true);
                    method.invoke(spyAuthzChallengeEndpoint, mockRequest, optionalSessionDataKey);
                } catch (Exception e) {
                    fail("Unexpected exception: " + e.getMessage());
                }
            }
        }
    }

    @BeforeMethod
    public void setupKeystore() throws Exception {

        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
    }

    private static KeyStore getKeyStoreFromFile(String keystoreName, String password, String home) throws Exception {

        Path tenantKeystorePath = Paths.get(home, "repository", "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(mockOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
        when(mockOAuthServerConfiguration.getOAuthAuthzRequestClassName())
                .thenReturn("org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest");
    }
}
