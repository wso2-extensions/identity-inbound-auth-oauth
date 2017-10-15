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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.authz;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.collections.CollectionUtils;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.RequestCoordinator;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest({ OAuth2Util.class, SessionDataCache.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class,
        EndpointUtil.class, FrameworkUtils.class, EndpointUtil.class, OpenIDConnectUserRPStore.class,
        CarbonOAuthAuthzRequest.class, IdentityTenantUtil.class, OAuthResponse.class})
public class OAuth2AuthzEndpointTest extends TestOAthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    SessionDataCache sessionDataCache;

    @Mock
    SessionDataCacheEntry loginCacheEntry, consentCacheEntry;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    HttpSession httpSession;

    @Mock
    RequestCoordinator requestCoordinator;

    @Mock
    OpenIDConnectUserRPStore openIDConnectUserRPStore;

    @Mock
    OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO;

    private static final String ERROR_PAGE_URL = "https://localhost:9443/authenticationendpoint/oauth2_error.do";
    private static final String USER_CONSENT_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_authz.do";
    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String RESPONSE_MODE_FORM_POST = "form_post";
    private static final String SESSION_DATA_KEY_CONSENT_VALUE = "savedSessionDataKeyForConsent";
    private static final String SESSION_DATA_KEY_VALUE = "savedSessionDataKey";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_NAME = "myApp";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String INACTIVE_APP_NAME = "inactiveApp";
    private static final String USERNAME = "user1";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String APP_REDIRECT_URL_JSON = "{\"url\":\"http://localhost:8080/redirect\"}";

    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint;

    @BeforeTest
    public void setUp() throws Exception {
        Path path = Paths.get("src", "test", "resources", "carbon_home");
        System.setProperty(CarbonBaseConstants.CARBON_HOME, path.toString());

        oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();

        initiateInMemoryH2();
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME, "INACTIVE");
    }

    @AfterTest
    public void cleanData() throws Exception {
        super.cleanData();
    }

    @DataProvider(name = "providePostParams")
    public Object[][] providePostParams() {
        MultivaluedMap<String, String> paramMap1 = new MultivaluedHashMap<String, String>();
        List<String> list1 = new ArrayList<>();
        list1.add("value1");
        list1.add("value2");
        paramMap1.put("paramName1", list1);

        Map<String, String[]> requestParams1 = new HashMap();
        requestParams1.put("reqParam1", new String[]{"val1", "val2"});

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<String, String>();
        List<String> list2 = new ArrayList<>();
        list2.add("value1");
        paramMap2.put("paramName1", list2);

        Map<String, String[]> requestParams2 = new HashMap();
        requestParams2.put("reqParam1", new String[]{"val1"});

        return new Object[][] {
                {paramMap2, requestParams2, HttpServletResponse.SC_FOUND},
                {paramMap1, requestParams2, HttpServletResponse.SC_BAD_REQUEST},
        };
    }

    @Test (dataProvider = "providePostParams")
    public void testAuthorizePost(Object paramObject, Map<String, String[]> requestParams, int expected)
            throws Exception {
        MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramObject;
        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameterNames()).thenReturn(new Vector(requestParams.keySet()).elements());

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        Response response = oAuth2AuthzEndpoint.authorizePost(httpServletRequest, httpServletResponse, paramMap);
        assertEquals(response.getStatus(), expected, "Unexpected HTTP response status");
    }

    @DataProvider(name = "provideParams")
    public Object[][] provideParams() {
        initMocks(this);

        return new Object[][] {
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{"val1", "val2"},
                        SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1", SESSION_DATA_KEY_VALUE, null,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE},
                        SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1", SESSION_DATA_KEY_VALUE, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, null, null, "true", "scope1", null, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE},
                        SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1", "invalidSession", null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.ACCESS_DENIED },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, "invalidConsentCacheKey",
                        "true", "scope1", null, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.ACCESS_DENIED },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{"invalidId"}, "invalidConsentCacheKey",
                        "true", "scope1", SESSION_DATA_KEY_VALUE, null, HttpServletResponse.SC_UNAUTHORIZED,
                        OAuth2ErrorCodes.INVALID_CLIENT },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{INACTIVE_CLIENT_ID_VALUE}, "invalidConsentCacheKey",
                        "true", "scope1", SESSION_DATA_KEY_VALUE, null, HttpServletResponse.SC_UNAUTHORIZED,
                        OAuth2ErrorCodes.INVALID_CLIENT },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, "invalidConsentCacheKey",
                        "true", "scope1", SESSION_DATA_KEY_VALUE, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST },

                { null, new String[]{CLIENT_ID_VALUE}, SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1",
                        SESSION_DATA_KEY_VALUE, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },

                { null, new String[]{CLIENT_ID_VALUE}, SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1",
                        SESSION_DATA_KEY_VALUE, new IOException(), HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, OAuthProblemException.error("error"), HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, new IOException(), HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null },

                { null, new String[]{CLIENT_ID_VALUE}, null, "false", null, null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.INCOMPLETE, new String[]{CLIENT_ID_VALUE}, null, "false",
                        OAuthConstants.Scope.OPENID, null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.INCOMPLETE, null, null, "false", OAuthConstants.Scope.OPENID, null, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },
        };
    }

    @Test (dataProvider = "provideParams")
    public void testAuthorize(Object flowStatusObject, String[] clientId, String sessionDataKayConsent,
                              String toCommonAuth, String scope, String sessionDataKey, Exception e, int expectedStatus,
                              String expectedError) throws Exception {
        AuthenticatorFlowStatus flowStatus = (AuthenticatorFlowStatus) flowStatusObject;

        Map<String, String[]> requestParams = new HashMap();
        Map<String, Object> requestAttributes = new HashMap();

        if (clientId != null) {
            requestParams.put(CLIENT_ID, clientId);
        }
        requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{sessionDataKayConsent});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{toCommonAuth});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{scope});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, flowStatus);
        requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);

        if (e instanceof OAuthProblemException) {
            mockStatic(CarbonOAuthAuthzRequest.class);
            whenNew(CarbonOAuthAuthzRequest.class).withAnyArguments().thenThrow(e);
            requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
        }

        mockHttpRequest(requestParams, requestAttributes);

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_VALUE);
        SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
        when(sessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
        when(sessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);
        when(loginCacheEntry.getoAuth2Parameters()).thenReturn(setOAuth2Parameters(
                new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)), APP_NAME, null, null));

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockEndpointUtil();
        when(oAuth2Service.validateClientInfo(anyString(), anyString())).thenReturn(oAuth2ClientValidationResponseDTO);
        when(oAuth2ClientValidationResponseDTO.isValidClient()).thenReturn(true);

        final String[] redirectUrl = new String[1];
        if (e instanceof IOException) {
            doThrow(e).when(httpServletResponse).sendRedirect(anyString());
        } else {
            doAnswer(new Answer<Object>() {
                @Override
                public Object answer(InvocationOnMock invocation) throws Throwable {
                    String key = (String) invocation.getArguments()[0];
                    redirectUrl[0] = key;
                    return null;
                }
            }).when(httpServletResponse).sendRedirect(anyString());
        }

        Response response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        if (response != null) {
            assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");
            MultivaluedMap<String, Object> responseMetadata = response.getMetadata();

            assertNotNull(responseMetadata, "HTTP response metadata is null");

            if (expectedError != null) {
                List<Object> redirectPath = responseMetadata.get(HTTPConstants.HEADER_LOCATION);
                if (CollectionUtils.isNotEmpty(redirectPath)) {
                    String location = (String) redirectPath.get(0);
                    assertTrue(location.contains(expectedError), "Expected error code not found in URL");
                } else {
                    assertNotNull(response.getEntity(), "Response entity is null");
                    assertTrue(response.getEntity().toString().contains(expectedError),
                            "Expected error code not found response entity");
                }

            }
        } else {
            assertNotNull(redirectUrl[0]);
        }
    }

    @DataProvider(name = "provideAuthenticatedData")
    public Object[][] provideAuthenticatedData() {
        return new Object[][] {
                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {false, true, null, null, null, null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList("scope1")), "not_form_post",
                        APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL_JSON, HttpServletResponse.SC_OK},

                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList("scope1")),
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL_JSON, HttpServletResponse.SC_OK},

                {true, false, null, OAuth2ErrorCodes.INVALID_REQUEST, null, null, new HashSet<>(Arrays.asList("scope1")),
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {true, false, null, null, "Error!", null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {true, false, null, null, null, "http://localhost:8080/error",
                        new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)), RESPONSE_MODE_FORM_POST,
                        APP_REDIRECT_URL, HttpServletResponse.SC_FOUND}
        };
    }

    @Test(dataProvider = "provideAuthenticatedData")
    public void testAuthorizeForAuthenticationResponse(boolean isResultInRequest, boolean isAuthenticated,
                                                       Map<ClaimMapping, String> attributes, String errorCode,
                                                       String errorMsg, String errorUri, Set<String> scopes,
                                                       String responseMode, String redirectUri, int expected)
            throws Exception {
        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(this.SESSION_DATA_KEY_VALUE);
        when(sessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);

        AuthenticationResult result =
                setAuthenticationResult(isAuthenticated, attributes, errorCode, errorMsg, errorUri);

        AuthenticationResult resultInRequest = null;
        AuthenticationResultCacheEntry authResultCacheEntry = null;
        if (isResultInRequest) {
            resultInRequest = result;
        } else {
            authResultCacheEntry = new AuthenticationResultCacheEntry();
            authResultCacheEntry.setResult(result);
        }

        Map<String, String[]> requestParams = new HashMap();
        Map<String, Object> requestAttributes = new HashMap();

        requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
        requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
        requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, resultInRequest);

        mockHttpRequest(requestParams, requestAttributes);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getAuthenticationResultFromCache(anyString())).thenReturn(authResultCacheEntry);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(scopes, APP_NAME, responseMode, redirectUri);
        when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
        when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        when(openIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(), anyString())).
                thenReturn(true);

        mockEndpointUtil();

        Response response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        assertEquals(response.getStatus(), expected, "Unexpected HTTP response status");
    }

    @DataProvider(name = "provideConsentData")
    public Object[][] provideConsentData() {
        return new Object[][] {
                {null, APP_REDIRECT_URL, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST},

                {"deny", APP_REDIRECT_URL, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.ACCESS_DENIED},

                {"deny", APP_REDIRECT_URL, new HashSet<>(Arrays.asList("scope1")), HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.ACCESS_DENIED},

                {"approve", APP_REDIRECT_URL, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_FOUND, null},

                {"approve", APP_REDIRECT_URL, new HashSet<>(Arrays.asList("scope1")),
                        HttpServletResponse.SC_FOUND, null},

                {"approve", APP_REDIRECT_URL_JSON, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_OK, null},

                {"approve", APP_REDIRECT_URL_JSON, new HashSet<>(Arrays.asList("scope1")),
                        HttpServletResponse.SC_OK, null},
        };
    }

    @Test(dataProvider = "provideConsentData")
    public void testUserConsentResponse(String consent, String redirectUrl, Set<String> scopes,
                                        int expectedStatus, String expectedError) throws Exception {
        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(this.SESSION_DATA_KEY_CONSENT_VALUE);
        when(sessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);

        Map<String, String[]> requestParams = new HashMap();
        Map<String, Object> requestAttributes = new HashMap();

        requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{SESSION_DATA_KEY_CONSENT_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
        requestParams.put(OAuthConstants.Prompt.CONSENT, new String[]{consent});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);

        mockHttpRequest(requestParams, requestAttributes);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(scopes, APP_NAME, RESPONSE_MODE_FORM_POST, redirectUrl);

        when(consentCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
        when(consentCacheEntry.getLoggedInUser()).thenReturn(new AuthenticatedUser());

        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        doNothing().when(openIDConnectUserRPStore).putUserRPToStore(any(AuthenticatedUser.class),
                anyString(), anyBoolean(), anyString());

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        mockEndpointUtil();

        Response response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        if (response != null) {
            assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

            MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
            assertNotNull(responseMetadata);

            if (expectedError != null) {
                CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION));
                assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                        "Location header not found in the response");
                String location = (String) responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0);
                assertTrue(location.contains(expectedError), "Expected error code not found in URL");
            }
        }
    }

    private void mockHttpRequest(final Map<String, String[]> requestParams,
                                 final Map<String, Object> requestAttributes) {
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                String value = requestParams.get(key) != null ? requestParams.get(key)[0]: null ;
                return value;
            }
        }).when(httpServletRequest).getParameter(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                return requestAttributes.get(key);
            }
        }).when(httpServletRequest).getAttribute(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                Object value = invocation.getArguments()[1];
                requestAttributes.put(key, value);
                return null;
            }
        }).when(httpServletRequest).setAttribute(anyString(), Matchers.anyObject());

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getSession()).thenReturn(httpSession);
    }

    private void mockEndpointUtil() throws Exception {
        spy(EndpointUtil.class);
        doReturn(oAuth2Service).when(EndpointUtil.class, "getOAuth2Service");

        doReturn(oAuthServerConfiguration).when(EndpointUtil.class, "getOAuthServerConfiguration");
        doReturn(USER_CONSENT_URL).when(EndpointUtil.class, "getUserConsentURL", any(OAuth2Parameters.class),
                anyString(), anyString(), anyBoolean());
    }

    private AuthenticationResult setAuthenticationResult(boolean isAuthenticated, Map<ClaimMapping, String> attributes,
                                                         String errorCode, String errorMsg, String errorUri) {
        AuthenticationResult authResult = new AuthenticationResult();
        authResult.setAuthenticated(isAuthenticated);

        if (!isAuthenticated) {
            authResult.addProperty(FrameworkConstants.AUTH_ERROR_CODE, errorCode);
            authResult.addProperty(FrameworkConstants.AUTH_ERROR_MSG, errorMsg);
            authResult.addProperty(FrameworkConstants.AUTH_ERROR_URI, errorUri);
        }

        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setAuthenticatedSubjectIdentifier(USERNAME);
        subject.setUserName(USERNAME);
        subject.setUserAttributes(attributes);
        authResult.setSubject(subject);

        return authResult;
    }

    private OAuth2Parameters setOAuth2Parameters(Set<String> scopes, String appName, String responseMode,
                                                 String redirectUri) {
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setScopes(scopes);
        oAuth2Parameters.setResponseMode(responseMode);
        oAuth2Parameters.setRedirectURI(redirectUri);
        oAuth2Parameters.setApplicationName(appName);
        return oAuth2Parameters;
    }
}
