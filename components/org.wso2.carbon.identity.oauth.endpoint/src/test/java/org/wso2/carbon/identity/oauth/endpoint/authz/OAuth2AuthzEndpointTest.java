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

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.validator.CodeValidator;
import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
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
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.RequestCoordinator;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.expmapper.InvalidRequestExceptionMapper;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.CarbonUtils;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anySet;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.FileAssert.fail;

@PrepareForTest({ OAuth2Util.class, SessionDataCache.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class,
        EndpointUtil.class, FrameworkUtils.class, EndpointUtil.class, OpenIDConnectUserRPStore.class,
        CarbonOAuthAuthzRequest.class, IdentityTenantUtil.class, OAuthResponse.class, SignedJWT.class,
        OIDCSessionManagementUtil.class, CarbonUtils.class, SessionDataCache.class})
public class OAuth2AuthzEndpointTest extends TestOAuthEndpointBase {

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

    @Mock
    CarbonOAuthAuthzRequest carbonOAuthAuthzRequest;

    @Mock
    OAuthAuthzRequest oAuthAuthzRequest;

    @Mock
    SignedJWT signedJWT;

    @Mock
    ReadOnlyJWTClaimsSet readOnlyJWTClaimsSet;

    @Mock
    OIDCSessionManager oidcSessionManager;

    @Mock
    ApplicationManagementService applicationManagementService;

    @Mock
    OAuthMessage oAuthMessage;

    private static final String ERROR_PAGE_URL = "https://localhost:9443/authenticationendpoint/oauth2_error.do";
    private static final String LOGIN_PAGE_URL = "https://localhost:9443/authenticationendpoint/login.do";
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
    private static final String SP_DISPLAY_NAME = "DisplayName";
    private static final String SP_NAME = "Name";

    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint;
    private Object authzEndpointObject;

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();

        initiateInMemoryH2();
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME, "INACTIVE");

        Class<?> clazz = OAuth2AuthzEndpoint.class;
        authzEndpointObject = clazz.newInstance();
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

        Map<String, String[]> requestParams1 = new HashMap<>();
        requestParams1.put("reqParam1", new String[]{"val1", "val2"});

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<String, String>();
        List<String> list2 = new ArrayList<>();
        list2.add("value1");
        paramMap2.put("paramName1", list2);

        Map<String, String[]> requestParams2 = new HashMap<>();
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

        Response response;

        try {
            response = oAuth2AuthzEndpoint.authorizePost(httpServletRequest, httpServletResponse, paramMap);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

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
                        null, new IOException(), HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },

                { null, new String[]{CLIENT_ID_VALUE}, null, "false", null, null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.INCOMPLETE, new String[]{CLIENT_ID_VALUE}, null, "false",
                        OAuthConstants.Scope.OPENID, null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST },

                { AuthenticatorFlowStatus.INCOMPLETE, null, null, "false", OAuthConstants.Scope.OPENID, null, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST },
        };
    }

    @Test (dataProvider = "provideParams", groups = "testWithConnection")
    public void testAuthorize(Object flowStatusObject, String[] clientId, String sessionDataKayConsent,
                              String toCommonAuth, String scope, String sessionDataKey, Exception e, int expectedStatus,
                              String expectedError) throws Exception {
        AuthenticatorFlowStatus flowStatus = (AuthenticatorFlowStatus) flowStatusObject;

        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

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

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

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
                new HashSet<>(Collections.singletonList(OAuthConstants.Scope.OPENID)), APP_NAME, null, null));

        mockOAuthServerConfiguration();

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockEndpointUtil();
        when(oAuth2Service.validateClientInfo(anyString(), anyString())).thenReturn(oAuth2ClientValidationResponseDTO);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
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

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

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

    @Test(dataProvider = "provideAuthenticatedData", groups = "testWithConnection")
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

        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
        requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
        requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, resultInRequest);

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getAuthenticationResultFromCache(anyString())).thenReturn(authResultCacheEntry);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(scopes, APP_NAME, responseMode, redirectUri);
        when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
        when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());

        mockOAuthServerConfiguration();

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        when(openIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(), anyString())).
                thenReturn(true);

        mockEndpointUtil();
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

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

    @Test(dataProvider = "provideConsentData", groups = "testWithConnection")
    public void testUserConsentResponse(String consent, String redirectUrl, Set<String> scopes,
                                        int expectedStatus, String expectedError) throws Exception {
        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
        when(sessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);

        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{SESSION_DATA_KEY_CONSENT_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
        requestParams.put(OAuthConstants.Prompt.CONSENT, new String[]{consent});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(scopes, APP_NAME, RESPONSE_MODE_FORM_POST, redirectUrl);

        when(consentCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
        when(consentCacheEntry.getLoggedInUser()).thenReturn(new AuthenticatedUser());

        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        doNothing().when(openIDConnectUserRPStore).putUserRPToStore(any(AuthenticatedUser.class),
                anyString(), anyBoolean(), anyString());

        mockOAuthServerConfiguration();

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        mockEndpointUtil();
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

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

    @DataProvider(name = "provideAuthzRequestData")
    public Object[][] provideAuthzRequestData() {
        String validPKCEChallenge = "abcdef1234A46gfdhhjhnmvmu764745463565nnnvbnn6";
        return new Object[][] {
                // Authz request from Valid client, PKCE not enabled. request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, true, false, true, LOGIN_PAGE_URL},

                // Blank client ID is received. Redirected to error page with invalid_request error
                {"", APP_REDIRECT_URL, null, null, null, true, false, true, ERROR_PAGE_URL},

                // Valid client, ACR url null, PKCE not enabled. request sent to framework for authentication
                {CLIENT_ID_VALUE, null, null, null, null, true, false, true, LOGIN_PAGE_URL},

                // Valid client, ACR value is "null". Correctly considers it as a null ACR.
                // PKCE not enabled. Request sent to framework for authentication
                {CLIENT_ID_VALUE, "null", null, null, null, true, false, true, LOGIN_PAGE_URL},

                // Invalid client. Redirected to error page.
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, false, false, true, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled and mandatory, PKCE code is null.
                // Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, true, true, true, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, PKCE code is null.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, true, true, false, LOGIN_PAGE_URL},

                // Valid client, PKCE is enabled and mandatory, valid PKCE code, plain PKCE challenge method,
                // plain PKCE is supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, null,
                        true, true, true, LOGIN_PAGE_URL},

                // Valid client, PKCE is enabled and mandatory, invalid PKCE code, plain PKCE challenge method,
                // plain PKCE is supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, "dummmyPkceChallenge", OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE,
                        null, true, true, true, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, un supported PKCE challenge method,
                // plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, "invalidMethod", null, true, true, false,
                        ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, plain PKCE challenge method,
                // plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, null,
                        true, true, false, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, PKCE challenge method is null,
                // plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, null, null, true, true, false, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, PKCE challenge method is s256,
                // plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, null,
                        true, true, false, ERROR_PAGE_URL},

                // Valid client, prompt is "none", PKCE not supported. Request sent to framework for authentication
                // since user is not authenticated
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.NONE, true, false, true,
                        LOGIN_PAGE_URL},

                // Valid client, prompt is "consent" and "login", PKCE not supported.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.CONSENT + " " +
                        OAuthConstants.Prompt.LOGIN, true, false, true, LOGIN_PAGE_URL},

                // Valid client, prompt is "login", PKCE not supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.SELECT_ACCOUNT + " " +
                        OAuthConstants.Prompt.LOGIN, true, false, true, LOGIN_PAGE_URL},

                // Valid client, prompt is "consent" and "select_account", PKCE not supported.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.SELECT_ACCOUNT + " " +
                        OAuthConstants.Prompt.CONSENT, true, false, true, LOGIN_PAGE_URL},

                // Valid client, prompt is "none" and "login", PKCE not supported.
                // Redirected to application with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.NONE + " " +
                        OAuthConstants.Prompt.LOGIN, true, false, true, APP_REDIRECT_URL},

                // Valid client, unsupported prompt, PKCE not supported.
                // Redirected to application with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, "dummyPrompt", true, false, true, APP_REDIRECT_URL},

                // Valid client, prompt is "login", PKCE not supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.LOGIN, true, false, true,
                        LOGIN_PAGE_URL},

                // Valid client, prompt is "consent", PKCE not supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.CONSENT, true, false, true,
                        LOGIN_PAGE_URL},

                // Valid client, prompt is "select_account", PKCE not supported.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.SELECT_ACCOUNT, true, false, true,
                        LOGIN_PAGE_URL},

                // Special data manipulation. For this combination of inputs, EndpointUtil.getLoginPageURL() is set to
                // throw a IdentityOAuth2Exception.
                // Redirected to error page with invalid_request error because of the exception
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.NONE, true, false, true,
                        ERROR_PAGE_URL},
        };
    }

    /**
     *
     * Tests the scenario of authorization request from the client
     */
    @Test(dataProvider = "provideAuthzRequestData", groups = "testWithConnection")
    public void testHandleOAuthAuthorizationRequest(String clientId, String redirectUri, String pkceChallengeCode,
                                                     String pkceChallengeMethod, String prompt, boolean clientValid,
                                                     boolean pkceEnabled, boolean supportPlainPkce,
                                                     String expectedLocation) throws Exception {
        Map<String, String[]> requestParams = new HashMap();
        Map<String, Object> requestAttributes = new HashMap();

        requestParams.put(CLIENT_ID, new String[] {clientId});

        // No consent data is saved in the cache yet and client doesn't send cache key
        requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{null});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
        requestParams.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, new String[]{pkceChallengeCode});
        requestParams.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD, new String[]{pkceChallengeMethod});
        requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.TOKEN.toString()});
        if (redirectUri != null) {
            requestParams.put("acr_values", new String[]{redirectUri});
            requestParams.put("claims", new String[]{"essentialClaims"});
            requestParams.put(MultitenantConstants.TENANT_DOMAIN,
                    new String[]{MultitenantConstants.SUPER_TENANT_DOMAIN_NAME});
        }
        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
        // No authentication data is saved in the cache yet and client doesn't send cache key
        requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, null);

        if (prompt != null) {
            requestParams.put(OAuthConstants.OAuth20Params.PROMPT, new String[]{prompt});
        }

        boolean checkErrorCode = ERROR_PAGE_URL.equals(expectedLocation);
        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        mockOAuthServerConfiguration();

        Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> responseTypeValidators = new Hashtable<>();
        responseTypeValidators.put(ResponseType.CODE.toString(), CodeValidator.class);
        responseTypeValidators.put(ResponseType.TOKEN.toString(), TokenValidator.class);

        when(oAuthServerConfiguration.getSupportedResponseTypeValidators()).thenReturn(responseTypeValidators);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockEndpointUtil();
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
        when(oAuth2Service.isPKCESupportEnabled()).thenReturn(pkceEnabled);
        if (ERROR_PAGE_URL.equals(expectedLocation) && OAuthConstants.Prompt.NONE.equals(prompt)) {
            doThrow(new IdentityOAuth2Exception("error")).when(EndpointUtil.class, "getLoginPageURL", anyString(),
                    anyString(), anyBoolean(), anyBoolean(), anySet(), anyMap());
            checkErrorCode =false;
        }

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
        validationResponseDTO.setValidClient(clientValid);
        validationResponseDTO.setCallbackURL(APP_REDIRECT_URL);
        if (!clientValid) {
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
            validationResponseDTO.setErrorMsg("client is invalid");
        }
        validationResponseDTO.setPkceMandatory(supportPlainPkce);
        validationResponseDTO.setPkceSupportPlain(supportPlainPkce);
        when(oAuth2Service.validateClientInfo(anyString(), anyString())).thenReturn(validationResponseDTO);

        final String[] redirectUrl = new String[1];

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                redirectUrl[0] = key;
                return null;
            }
        }).when(httpServletResponse).sendRedirect(anyString());

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

        if (response != null) {
            assertEquals(response.getStatus(), HttpServletResponse.SC_FOUND, "Unexpected HTTP response status");

            MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
            assertNotNull(responseMetadata, "Response metadata is null");

            assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                    "Location header not found in the response");
            String location = (String) responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0);
            assertTrue(location.contains(expectedLocation), "Unexpected redirect url in the response");

            if (checkErrorCode) {
                assertTrue(location.contains(OAuth2ErrorCodes.INVALID_REQUEST), "Expected error code not found in URL");
            }
        } else {
            assertNotNull(redirectUrl[0], "Response not redirected to outside");
        }
    }

    @DataProvider(name = "provideUserConsentData")
    public Object[][] provideUserConsentData() {
        String authzCode = "67428657950009705658674645643";
        String accessToken = "56789876734982650746509776325";
        String idToken = "eyJzdWIiOiJQUklNQVJZXC9zdXJlc2hhdHQiLCJlbWFpbCI6InN1cmVzaGdlbXVudUBteW1haWwuY29tIiwibmFtZSI" +
                "6IlN1cmVzaCBBdHRhbmF5YWtlIiwiZmFtaWx5X25hbWUiOiJBdHRhbmF5YWtlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic3VyZXN" +
                "oZ2VtdW51IiwiZ2l2ZW5fbmFtZSI6IlN1cmVzaCJ9";

        // These values are provided to cover all the branches in handleUserConsent private method.
        return new Object[][] {
                { true, OAuthConstants.Consent.APPROVE_ALWAYS, false, OAuth2ErrorCodes.SERVER_ERROR, null, null, null,
                        null, null, null, null, HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                { false, OAuthConstants.Consent.APPROVE_ALWAYS, true, null, authzCode, null, null, null, null, "idp1",
                        null, HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                { false, OAuthConstants.Consent.APPROVE_ALWAYS, false, null, null, accessToken, null,
                        OAuthConstants.ACCESS_TOKEN, RESPONSE_MODE_FORM_POST, "idp1", "ACTIVE", HttpServletResponse.SC_OK, null},

                { false, OAuthConstants.Consent.APPROVE_ALWAYS, false, null, null, accessToken, idToken,
                        OAuthConstants.ID_TOKEN, RESPONSE_MODE_FORM_POST, null, "ACTIVE", HttpServletResponse.SC_OK, null},

                { false, OAuthConstants.Consent.APPROVE, false, null, null, accessToken, idToken,
                        OAuthConstants.NONE, RESPONSE_MODE_FORM_POST, "", "", HttpServletResponse.SC_OK, null},

                { false, OAuthConstants.Consent.APPROVE, false, null, null, accessToken, idToken,
                        OAuthConstants.ID_TOKEN, null, null, "ACTIVE", HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                { false, OAuthConstants.Consent.APPROVE, false, null, null, accessToken, null, OAuthConstants.ID_TOKEN,
                        null, null, "ACTIVE", HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                { false, OAuthConstants.Consent.APPROVE_ALWAYS, false, OAuth2ErrorCodes.INVALID_CLIENT, null, null,
                        null, null, null, null, null, HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

        };
    }

    @Test(dataProvider = "provideUserConsentData", groups = "testWithConnection")
    public void testHandleUserConsent(boolean isRespDTONull, String consent, boolean skipConsent, String errorCode,
                                      String authCode, String accessToken, String idToken, String responseType,
                                      String responseMode, String authenticatedIdps, String state, int expectedStatus,
                                      String expectedLocation) throws Exception {
        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{SESSION_DATA_KEY_CONSENT_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
        requestParams.put(OAuthConstants.Prompt.CONSENT, new String[]{consent});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
        when(sessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(new HashSet<String>(), APP_NAME, responseMode, APP_REDIRECT_URL);
        oAuth2Params.setResponseType(responseType);
        oAuth2Params.setState(state);

        when(consentCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
        when(consentCacheEntry.getLoggedInUser()).thenReturn(new AuthenticatedUser());
        when(consentCacheEntry.getAuthenticatedIdPs()).thenReturn(authenticatedIdps);

        OAuth2AuthorizeRespDTO authzRespDTO = null;
        if (!isRespDTONull) {
            authzRespDTO = new OAuth2AuthorizeRespDTO();
            authzRespDTO.setAuthorizationCode(authCode);
            authzRespDTO.setCallbackURI(APP_REDIRECT_URL);
            authzRespDTO.setAccessToken(accessToken);
            authzRespDTO.setIdToken(idToken);
            authzRespDTO.setErrorCode(errorCode);

            if (OAuthConstants.ID_TOKEN.equals(responseType) && idToken == null) {
                authzRespDTO.setCallbackURI(APP_REDIRECT_URL + "?");
            }
        }
        mockEndpointUtil();
        when(oAuth2Service.authorize(any(OAuth2AuthorizeReqDTO.class))).thenReturn(authzRespDTO);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        doNothing().when(openIDConnectUserRPStore).putUserRPToStore(any(AuthenticatedUser.class),
                anyString(), anyBoolean(), anyString());

        when(oAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(skipConsent);

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

        assertNotNull(response, "Authorization response is null");
        assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

        if (expectedLocation != null) {
            MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
            assertNotNull(responseMetadata, "Response metadata is null");

            assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                    "Location header not found in the response");
            String location = (String) responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0);
            assertTrue(location.contains(expectedLocation), "Unexpected redirect url in the response");

            if (errorCode != null) {
                assertTrue(location.contains(errorCode), "Expected error code not found in URL");
            }
        }
    }

    @DataProvider(name = "provideDataForUserAuthz")
    public Object[][] provideDataForUserAuthz() {
        String idTokenHint = "tokenHintString";

        // This object provides data to cover all branches in doUserAuthz() private method
        return new Object[][] {
                { OAuthConstants.Prompt.CONSENT, null, true, false, false, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.NONE, null, true, true, false, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.NONE, null, false, false, false, USERNAME, USERNAME,
                        OAuth2ErrorCodes.CONSENT_REQUIRED},
                { OAuthConstants.Prompt.NONE, null, false, true, false, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.NONE, idTokenHint, true, false, true, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.NONE, idTokenHint, true, false, false, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.NONE, idTokenHint, false, false, true, USERNAME, USERNAME,
                        OAuth2ErrorCodes.CONSENT_REQUIRED},
                { OAuthConstants.Prompt.NONE, "invalid", false, false, true, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.NONE, idTokenHint, false, false, true, "", USERNAME,
                        OAuth2ErrorCodes.LOGIN_REQUIRED},
                { OAuthConstants.Prompt.NONE, idTokenHint, true, false, true, USERNAME, "user2",
                        OAuth2ErrorCodes.LOGIN_REQUIRED},
                { OAuthConstants.Prompt.LOGIN, null, true, false, false, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.LOGIN, null, false, false, false, USERNAME, USERNAME, null},
                { "", null, false, true, false, USERNAME, USERNAME, null},
                { OAuthConstants.Prompt.SELECT_ACCOUNT, null, false, false, false, USERNAME, USERNAME, null},
        };
    }

    @Test(dataProvider = "provideDataForUserAuthz", groups = "testWithConnection")
    public void testDoUserAuthz(String prompt, String idTokenHint, boolean hasUserApproved, boolean skipConsent,
                                boolean idTokenHintValid, String loggedInUser, String idTokenHintSubject,
                                String errorCode) throws Exception {
        AuthenticationResult result = setAuthenticationResult(true, null, null, null, null);

        result.getSubject().setAuthenticatedSubjectIdentifier(loggedInUser);
        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
        requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
        requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, result);

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(new HashSet<String>(), APP_NAME, null, APP_REDIRECT_URL);
        oAuth2Params.setClientId(CLIENT_ID_VALUE);
        oAuth2Params.setPrompt(prompt);
        oAuth2Params.setIDTokenHint(idTokenHint);

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(this.SESSION_DATA_KEY_VALUE);
        when(sessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
        when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());
        when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);

        mockEndpointUtil();

        mockOAuthServerConfiguration();

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        when(openIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(), anyString())).
                thenReturn(hasUserApproved);

        spy(OAuth2Util.class);
        doReturn(idTokenHintValid).when(OAuth2Util.class, "validateIdToken", anyString());

        mockStatic(SignedJWT.class);
        if ("invalid".equals(idTokenHint)) {
            when(SignedJWT.parse(anyString())).thenThrow(new ParseException("error",1));
        } else {
            when(SignedJWT.parse(anyString())).thenReturn(signedJWT);
        }
        when(signedJWT.getJWTClaimsSet()).thenReturn(readOnlyJWTClaimsSet);
        when(readOnlyJWTClaimsSet.getSubject()).thenReturn(idTokenHintSubject);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

        assertNotNull(response, "Authorization response is null");
        assertEquals(response.getStatus(), HttpServletResponse.SC_FOUND, "Unexpected HTTP response status");

        if (errorCode != null) {
            MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
            assertNotNull(responseMetadata, "Response metadata is null");

            assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                    "Location header not found in the response");
            String location = (String) responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0);

            assertTrue(location.contains(errorCode), "Expected error code not found in URL");
        }

    }

    @DataProvider(name = "provideOidcSessionData")
    public Object[][] provideOidcSessionData() {
        Cookie opBrowserStateCookie = new Cookie("opbs", "2345678776gffdgdsfafa");
        OIDCSessionState previousSessionState1 = new OIDCSessionState();
        OIDCSessionState previousSessionState2 = new OIDCSessionState();

        previousSessionState1.setSessionParticipants(new HashSet<>(Arrays.asList(CLIENT_ID_VALUE)));
        previousSessionState2.setSessionParticipants(new HashSet<String>());

        String[] returnValues = new String[] {
                "http://localhost:8080/redirect?session_state=sessionStateValue",
                "<form method=\"post\" action=\"http://localhost:8080/redirect\">"
        };

        // This object provides values to cover the branches in ManageOIDCSessionState() private method
        return new Object[][] {
                { opBrowserStateCookie, previousSessionState1, APP_REDIRECT_URL, null,
                        HttpServletResponse.SC_FOUND, returnValues[0]},
                { opBrowserStateCookie, previousSessionState2, APP_REDIRECT_URL, RESPONSE_MODE_FORM_POST,
                        HttpServletResponse.SC_OK, returnValues[1]},
                { null, previousSessionState1, APP_REDIRECT_URL, null, HttpServletResponse.SC_FOUND, returnValues[0]},
                { null, previousSessionState1, APP_REDIRECT_URL, null, HttpServletResponse.SC_FOUND, returnValues[0]},
                { opBrowserStateCookie, null, APP_REDIRECT_URL, null, HttpServletResponse.SC_FOUND, returnValues[0]},
        };
    }

    @Test (dataProvider = "provideOidcSessionData", groups = "testWithConnection")
    public void testManageOIDCSessionState(Object cookieObject, Object sessionStateObject, String callbackUrl,
                                           String responseMode, int expectedStatus, String expectedResult)
            throws Exception {
        Cookie opBrowserStateCookie = (Cookie) cookieObject;
        Cookie newOpBrowserStateCookie = new Cookie("opbs", "f6454r678776gffdgdsfafa");
        OIDCSessionState previousSessionState = (OIDCSessionState) sessionStateObject;
        AuthenticationResult result = setAuthenticationResult(true, null, null, null, null);

        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
        requestParams.put(OAuthConstants.OAuth20Params.PROMPT, new String[]{OAuthConstants.Prompt.LOGIN});

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
        requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
        requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, result);

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        OAuth2Parameters oAuth2Params = setOAuth2Parameters(new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                APP_NAME, responseMode, APP_REDIRECT_URL);
        oAuth2Params.setClientId(CLIENT_ID_VALUE);
        oAuth2Params.setPrompt(OAuthConstants.Prompt.LOGIN);

        mockOAuthServerConfiguration();
        mockEndpointUtil();

        when(oAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);

        OAuth2AuthorizeRespDTO authzRespDTO = new OAuth2AuthorizeRespDTO();
        authzRespDTO.setCallbackURI(callbackUrl);
        when(oAuth2Service.authorize(any(OAuth2AuthorizeReqDTO.class))).thenReturn(authzRespDTO);

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        mockStatic(OIDCSessionManagementUtil.class);
        when(OIDCSessionManagementUtil.getOPBrowserStateCookie(any(HttpServletRequest.class))).thenReturn(opBrowserStateCookie);
        when(OIDCSessionManagementUtil.addOPBrowserStateCookie(any(HttpServletResponse.class))).thenReturn(newOpBrowserStateCookie);
        when(OIDCSessionManagementUtil.getSessionManager()).thenReturn(oidcSessionManager);
        when(oidcSessionManager.getOIDCSessionState(anyString())).thenReturn(previousSessionState);
        when(OIDCSessionManagementUtil.getSessionStateParam(anyString(), anyString(), anyString())).thenReturn("sessionStateValue");
        when(OIDCSessionManagementUtil.addSessionStateToURL(anyString(), anyString(), anyString())).thenCallRealMethod();

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(this.SESSION_DATA_KEY_VALUE);
        when(sessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
        when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
        when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(OpenIDConnectUserRPStore.class);
        when(OpenIDConnectUserRPStore.getInstance()).thenReturn(openIDConnectUserRPStore);
        when(openIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(), anyString())).
                thenReturn(true);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

        assertNotNull(response, "Authorization response is null");
        assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

        MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
        assertNotNull(responseMetadata, "Response metadata is null");

        if ( response.getStatus() != HttpServletResponse.SC_OK) {
            assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                    "Location header not found in the response");
            String location = (String) responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0);

            assertTrue(location.contains(expectedResult), "Expected redirect URL is not returned");
        } else {
            assertTrue(response.getEntity().toString().contains(expectedResult), "Expected redirect URL is not returned");
        }
    }

    @DataProvider(name = "providePathExistsData")
    public Object[][] providePathExistsData() {
        return new Object[][] {
                {System.getProperty(CarbonBaseConstants.CARBON_HOME), true},
                {"carbon_home", false}
        };
    }

    @Test(dataProvider = "providePathExistsData")
    public void testGetFormPostRedirectPage(String carbonHome, boolean fileExists) throws Exception {
        spy(CarbonUtils.class);
        doReturn(carbonHome).when(CarbonUtils.class, "getCarbonHome");

        Method getFormPostRedirectPage = authzEndpointObject.getClass().getDeclaredMethod("getFormPostRedirectPage");
        getFormPostRedirectPage.setAccessible(true);
        String value =  (String) getFormPostRedirectPage.invoke(authzEndpointObject);
        assertEquals((value != null), fileExists, "FormPostRedirectPage value is incorrect");

        Field formPostRedirectPage = authzEndpointObject.getClass().getDeclaredField("formPostRedirectPage");

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(formPostRedirectPage, formPostRedirectPage.getModifiers() & ~Modifier.FINAL);
        formPostRedirectPage.setAccessible(true);
        formPostRedirectPage.set(authzEndpointObject, value);

        Method createFormPage = authzEndpointObject.getClass().getDeclaredMethod("createFormPage", String.class,
                String.class, String.class, String.class);
        createFormPage.setAccessible(true);
        value =  (String) createFormPage.invoke(authzEndpointObject, APP_REDIRECT_URL_JSON, APP_REDIRECT_URL,
                StringUtils.EMPTY, "sessionDataValue");
        assertNotNull(value, "Form post page is null");
    }

    @DataProvider(name = "provideSendRequestToFrameworkData")
    public Object[][] provideSendRequestToFrameworkData() {
        return new Object[][] {
                {null},
                {AuthenticatorFlowStatus.SUCCESS_COMPLETED},
                {AuthenticatorFlowStatus.INCOMPLETE}
        };
    }

    @Test(dataProvider = "provideSendRequestToFrameworkData")
    public void testSendRequestToFramework(Object flowStatusObject) throws Exception {
        AuthenticatorFlowStatus flowStatus = (AuthenticatorFlowStatus) flowStatusObject;
        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, flowStatus);
        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        final String[] redirectUrl = new String[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                redirectUrl[0] = key;
                return null;
            }
        }).when(httpServletResponse).sendRedirect(anyString());

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getRequestCoordinator()).thenReturn(requestCoordinator);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return null;
            }
        }).when(requestCoordinator).handle(any(HttpServletRequest.class), any(HttpServletResponse.class));

        mockOAuthServerConfiguration();
        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        Method sendRequestToFramework = authzEndpointObject.getClass().getDeclaredMethod("handleAuthFlowThroughFramework",
                OAuthMessage.class, String.class);
        sendRequestToFramework.setAccessible(true);

        when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
        when(oAuthMessage.getResponse()).thenReturn(httpServletResponse);


        Response response;
        try {
            response =  (Response) sendRequestToFramework.invoke(authzEndpointObject, oAuthMessage, "type");
        } catch (Exception ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse((InvalidRequestParentException) ire.getCause());
        }

        assertNotNull(response, "Returned response is null");

        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, flowStatus);
        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
        when(oAuthMessage.getResponse()).thenReturn(httpServletResponse);

        Method sendRequestToFramework2 = authzEndpointObject.getClass().getDeclaredMethod("handleAuthFlowThroughFramework",
                OAuthMessage.class, String.class);
        sendRequestToFramework2.setAccessible(true);
        try {
            response =  (Response) sendRequestToFramework.invoke(authzEndpointObject, oAuthMessage, "type");
        } catch (Exception ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse((InvalidRequestParentException) ire.getCause());
        }
        assertNotNull(response, "Returned response is null");
    }

    @DataProvider(name = "provideAuthenticatedTimeFromCommonAuthData")
    public Object[][] provideAuthenticatedTimeFromCommonAuthData() {

        return new Object[][] {
                { new SessionContext(), 1479249799770L, 1479249798770L },
                { new SessionContext(), null, 1479249798770L },
                { null, null, 1479249798770L }
        };
    }

    @Test(dataProvider = "provideAuthenticatedTimeFromCommonAuthData")
    public void testGetAuthenticatedTimeFromCommonAuthCookie(Object sessionContextObject, Object updatedTimestamp,
                                                             Object createdTimeStamp) throws Exception {
        SessionContext sessionContext = (SessionContext) sessionContextObject;
        Cookie commonAuthCookie = new Cookie(FrameworkConstants.COMMONAUTH_COOKIE, "32414141346576");

        if (sessionContext != null) {
            sessionContext.addProperty(FrameworkConstants.UPDATED_TIMESTAMP, updatedTimestamp);
            sessionContext.addProperty(FrameworkConstants.CREATED_TIMESTAMP, createdTimeStamp);
        }

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getSessionContextFromCache(anyString())).thenReturn(sessionContext);

        Method getAuthenticatedTimeFromCommonAuthCookie = authzEndpointObject.getClass().
                getDeclaredMethod("getAuthenticatedTimeFromCommonAuthCookie", Cookie.class);
        getAuthenticatedTimeFromCommonAuthCookie.setAccessible(true);
        long timestamp = (long) getAuthenticatedTimeFromCommonAuthCookie.invoke(authzEndpointObject, commonAuthCookie);

        if (sessionContext == null) {
            assertEquals(timestamp, 0, "Authenticated time should be 0 when session context is null");
        } else if (updatedTimestamp != null) {
            assertEquals(timestamp, Long.parseLong(updatedTimestamp.toString()),
                    "session context updated time should be equal to the authenticated time");
        } else {
            assertEquals(timestamp, Long.parseLong(createdTimeStamp.toString()),
                    "session context created time should be equal to the authenticated time");
        }
    }

    @DataProvider(name = "provideGetServiceProviderData")
    public Object[][] provideGetServiceProviderData() {
        return new Object[][] {
                {CLIENT_ID_VALUE, null},
                {CLIENT_ID_VALUE, new IdentityOAuth2Exception("Error")},
                {"invalidId", null},
        };
    }

    @Test(dataProvider = "provideGetServiceProviderData", groups = "testWithConnection")
    public void testGetServiceProvider(String clientId, Exception e) throws Exception {
        Method getServiceProvider = authzEndpointObject.getClass().getDeclaredMethod(
                "getServiceProvider", String.class);
        getServiceProvider.setAccessible(true);

        ServiceProvider sp = new ServiceProvider();
        sp.setApplicationName(APP_NAME);
        mockOAuthServerConfiguration();
        mockEndpointUtil();
        doReturn(applicationManagementService).when(EndpointUtil.class, "getApplicationManagementService");
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(sp);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        if (e instanceof IdentityOAuth2Exception) {
            when(tokenPersistenceProcessor.getPreprocessedClientSecret(anyString())).thenThrow(e);
        }
        try {
            ServiceProvider result = (ServiceProvider) getServiceProvider.invoke(authzEndpointObject, clientId);
            assertEquals(result.getApplicationName(), APP_NAME);
        } catch (Exception e1) {
            if (e == null && CLIENT_ID_VALUE.equals(clientId)) {
                fail("Unexpected Exception");
            }
        }
    }

    @DataProvider(name = "provideHandleOAuthAuthorizationRequest1Data")
    public Object[][] provideHandleOAuthAuthorizationRequest1Data() {
        ServiceProvider sp1 = new ServiceProvider();
        ServiceProvider sp2 = new ServiceProvider();
        ServiceProvider sp3 = new ServiceProvider();
        ServiceProviderProperty property1 = new ServiceProviderProperty();
        property1.setName(SP_DISPLAY_NAME);
        property1.setValue("myApplication");
        ServiceProviderProperty property2 = new ServiceProviderProperty();
        property2.setName(SP_NAME);
        property2.setValue(APP_NAME);

        ServiceProviderProperty[] properties1 = new ServiceProviderProperty[]{property1, property2};
        sp1.setSpProperties(properties1);
        ServiceProviderProperty[] properties2 = new ServiceProviderProperty[]{property2};
        sp2.setSpProperties(properties2);

        return new Object[][] {
                { true, sp1, "myApplication"},
                { true, sp2, null},
                { true, sp3, null},
                { false, sp1, null},
        };
    }

    @Test(dataProvider = "provideHandleOAuthAuthorizationRequest1Data", groups = "testWithConnection")
    public void testHandleOAuthAuthorizationRequest1(boolean showDisplayName, Object spObj, String savedDisplayName)
            throws Exception {
        ServiceProvider sp = (ServiceProvider) spObj;
        sp.setApplicationName(APP_NAME);

        mockOAuthServerConfiguration();
        mockEndpointUtil();
        doReturn(applicationManagementService).when(EndpointUtil.class, "getApplicationManagementService");
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(sp);
        doReturn(applicationManagementService).when(EndpointUtil.class, "getApplicationManagementService");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        Map<String, String[]> requestParams = new HashMap();
        Map<String, Object> requestAttributes = new HashMap();

        requestParams.put(CLIENT_ID, new String[] {CLIENT_ID_VALUE});

        requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
        requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.TOKEN.toString()});

        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
        validationResponseDTO.setValidClient(true);
        validationResponseDTO.setCallbackURL(APP_REDIRECT_URL);
        when(oAuth2Service.validateClientInfo(anyString(), anyString())).thenReturn(validationResponseDTO);

        Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> responseTypeValidators = new Hashtable<>();
        responseTypeValidators.put(ResponseType.CODE.toString(), CodeValidator.class);
        responseTypeValidators.put(ResponseType.TOKEN.toString(), TokenValidator.class);

        when(oAuthServerConfiguration.getSupportedResponseTypeValidators()).thenReturn(responseTypeValidators);
        when(oAuthServerConfiguration.isShowDisplayNameInConsentPage()).thenReturn(showDisplayName);

        Method handleOAuthAuthorizationRequest = authzEndpointObject.getClass().getDeclaredMethod(
                "handleOAuthAuthorizationRequest", OAuthMessage.class);
        handleOAuthAuthorizationRequest.setAccessible(true);

        SessionDataCache sessionDataCache = mock(SessionDataCache.class);
        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        final SessionDataCacheEntry[] cacheEntry = new SessionDataCacheEntry[1];
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                cacheEntry[0] = (SessionDataCacheEntry) invocation.getArguments()[1];
                return null;
            }
        }).when(sessionDataCache).addToCache(any(SessionDataCacheKey.class), any(SessionDataCacheEntry.class));

        when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
        when(oAuthMessage.getClientId()).thenReturn(CLIENT_ID_VALUE);

        handleOAuthAuthorizationRequest.invoke(authzEndpointObject, oAuthMessage);
        assertNotNull(cacheEntry[0], "Parameters not saved in cache");
        assertEquals(cacheEntry[0].getoAuth2Parameters().getDisplayName(), savedDisplayName);
    }

    @Test(dependsOnGroups = "testWithConnection")
    public void testIdentityOAuthAdminException() throws Exception {

        //OAuthAdminException will not occur due to introduce a new Service to get the App State instead directly use
        // dao
        Map<String, String[]> requestParams = new HashMap<>();
        Map<String, Object> requestAttributes = new HashMap<>();

        requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
        requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
        requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

        mockOAuthServerConfiguration();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        connection.close(); // Closing connection to create SQLException
        mockEndpointUtil();
        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

        Response response;
        try {
            response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

        assertEquals(response.getStatus(), HttpServletResponse.SC_FOUND);
    }

    private void mockHttpRequest(final Map<String, String[]> requestParams,
                                 final Map<String, Object> requestAttributes, String method) {
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                return requestParams.get(key) != null ? requestParams.get(key)[0]: null;
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
        when(httpServletRequest.getMethod()).thenReturn(method);
        when(httpServletRequest.getContentType()).thenReturn(OAuth.ContentType.URL_ENCODED);

        String authHeader = "Basic Y2ExOWE1NDBmNTQ0Nzc3ODYwZTQ0ZTc1ZjYwNWQ5Mjc6ODduOWE1NDBmNTQ0Nzc3ODYwZTQ0ZTc1ZjYwNWQ0MzU=";
        when(httpServletRequest.getHeader("Authorization")).thenReturn(authHeader);
    }

    private void mockEndpointUtil() throws Exception {
        spy(EndpointUtil.class);
        doReturn(oAuth2Service).when(EndpointUtil.class, "getOAuth2Service");

        doReturn(oAuthServerConfiguration).when(EndpointUtil.class, "getOAuthServerConfiguration");
        doReturn(USER_CONSENT_URL).when(EndpointUtil.class, "getUserConsentURL", any(OAuth2Parameters.class),
                anyString(), anyString(), anyBoolean());
        doReturn(LOGIN_PAGE_URL).when(EndpointUtil.class, "getLoginPageURL", anyString(), anyString(), anyBoolean(),
                anyBoolean(), anySet(), anyMap());
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

    private void mockOAuthServerConfiguration() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });
    }
}
