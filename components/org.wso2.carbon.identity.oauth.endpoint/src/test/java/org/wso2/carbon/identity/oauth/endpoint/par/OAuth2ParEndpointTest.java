/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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
package org.wso2.carbon.identity.oauth.endpoint.par;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.oltu.oauth2.as.validator.CodeValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.par.core.ParAuthServiceImpl;
import org.wso2.carbon.identity.oauth.par.model.ParAuthData;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCRequestObjectUtil;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.doCallRealMethod;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for OAuth2ParEndpoint.
 */
@PrepareForTest({OAuthServerConfiguration.class, EndpointUtil.class, ServiceURL.class, ServiceURLBuilder.class,
        IdentityTenantUtil.class, LoggerUtils.class, IdentityDatabaseUtil.class, IdentityUtil.class,
        OIDCRequestObjectUtil.class, OAuth2Util.class})
public class OAuth2ParEndpointTest extends TestOAuthEndpointBase {

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    ParAuthServiceImpl parAuthService;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    private TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    private ParAuthData parAuthData;

    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_NAME = "myApp";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String INACTIVE_APP_NAME = "inactiveApp";
    private static final String USERNAME = "user1";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String RESPONSE_TYPE_CODE_ID_TOKEN = "code id_token";
    private static final String REQUEST_URI_REF = "c0143cb3-7ae0-43a3-a023-b7218c7182df";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:par:request_uri:c0143cb3-7ae0-43a3-a023" +
            "-b7218c7182df";
    private static final Long EXPIRY_TIME = 60L;
    private OAuth2ParEndpoint oAuth2ParEndpoint;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, Paths.get(System.getProperty("user.dir"),
                "src", "test", "resources").toString());

        oAuth2ParEndpoint = new OAuth2ParEndpoint();

        initiateInMemoryH2();
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME, "INACTIVE");
    }

    @AfterTest
    public void cleanData() throws Exception {

        super.cleanData();
    }

    @DataProvider(name = "testParDataProvider")
    public Object[][] testParDataProvider() {

        Map<String, String[]> requestParams1 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});

        Map<String, String[]> requestParams2 =
                createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                        new String[]{APP_REDIRECT_URL, APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});

        Map<String, String[]> requestParams3 = createRequestParamsMap(new String[]{INACTIVE_CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});

        Map<String, String[]> requestParams4 = createRequestParamsMap(new String[]{"invalidClientId"},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});

        Map<String, String[]> requestParams5 =
                createRequestParamsMap(null, new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});

        Map<String, String[]> requestParams6 =
                createRequestParamsMap(new String[]{CLIENT_ID_VALUE}, new String[]{APP_REDIRECT_URL},
                        new String[]{"invalidResponseType"});

        Map<String, String[]> requestParams7 =
                createRequestParamsMap(new String[]{CLIENT_ID_VALUE}, new String[]{"http://localhost:8080" +
                                "/invalid-redirect"}, new String[]{RESPONSE_TYPE_CODE});

        Map<String, String[]> requestParams8 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});
        requestParams8.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{"openid"});
        requestParams8.put(OAuthConstants.OAuth20Params.REQUEST, new String[]{"dummyRequest"});

        Map<String, String[]> requestParams9 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});
        requestParams9.put(OAuthConstants.OAuth20Params.RESPONSE_MODE,
                new String[]{OAuthConstants.ResponseModes.JWT});
        requestParams9.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, new String[]{"code-challenge-string"});
        requestParams9.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD,
                new String[]{OAuthConstants.OAUTH_PKCE_S256_CHALLENGE});

        Map<String, String[]> requestParams10 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});
        requestParams10.put(OAuthConstants.OAuth20Params.RESPONSE_MODE,
                new String[]{OAuthConstants.ResponseModes.QUERY_JWT});

        Map<String, String[]> requestParams11 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE_ID_TOKEN});
        requestParams11.put(OAuthConstants.OAuth20Params.RESPONSE_MODE,
                new String[]{OAuthConstants.ResponseModes.QUERY_JWT});
        requestParams11.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, new String[]{"code-challenge-string"});
        requestParams11.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD,
                new String[]{OAuthConstants.OAUTH_PKCE_S256_CHALLENGE});

        Map<String, String[]> requestParams12 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});
        requestParams12.put(OAuthConstants.OAuth20Params.RESPONSE_MODE,
                new String[]{OAuthConstants.ResponseModes.JWT});
        requestParams12.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, new String[]{"code-challenge-string"});

        Map<String, String[]> requestParams13 = createRequestParamsMap(new String[]{CLIENT_ID_VALUE},
                new String[]{APP_REDIRECT_URL}, new String[]{RESPONSE_TYPE_CODE});
        requestParams13.put(OAuthConstants.OAuth20Params.RESPONSE_MODE,
                new String[]{OAuthConstants.ResponseModes.JWT});
        requestParams13.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, new String[]{"code-challenge-string"});
        requestParams13.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD,
                new String[]{"Invalid-code-challenge-method"});

        MultivaluedMap<String, String> paramMap1 = new MultivaluedHashMap<>();
        paramMap1.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        paramMap1.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);
        paramMap1.add(OAuth.OAUTH_RESPONSE_TYPE, RESPONSE_TYPE_CODE);

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<>();
        paramMap2.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        paramMap2.add(OAuthConstants.OAuth20Params.REQUEST_URI, REQUEST_URI);

        MultivaluedMap<String, String> paramMap3 = new MultivaluedHashMap<>();
        paramMap3.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        paramMap3.add(OAuth.OAUTH_REDIRECT_URI, APP_REDIRECT_URL);
        paramMap3.add(OAuth.OAUTH_RESPONSE_TYPE, RESPONSE_TYPE_CODE);
        paramMap3.add(OAuthConstants.OAuth20Params.SCOPE, null);

        MultivaluedMap<String, String> paramMap4 = new MultivaluedHashMap<>();
        paramMap4.add(OAuth.OAUTH_CLIENT_ID, CLIENT_ID_VALUE);
        paramMap4.add(OAuth.OAUTH_RESPONSE_TYPE, RESPONSE_TYPE_CODE_ID_TOKEN);

        OAuthClientAuthnContext oAuthClientAuthnContext1 = new OAuthClientAuthnContext();
        oAuthClientAuthnContext1.setAuthenticated(true);

        OAuthClientAuthnContext oAuthClientAuthnContext2 = new OAuthClientAuthnContext();
        oAuthClientAuthnContext2.setAuthenticated(false);
        oAuthClientAuthnContext2.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);

        OAuthClientAuthnContext oAuthClientAuthnContext3 = new OAuthClientAuthnContext();
        oAuthClientAuthnContext3.setAuthenticated(false);
        oAuthClientAuthnContext3.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);

        OAuthClientAuthnContext oAuthClientAuthnContext4 = new OAuthClientAuthnContext();
        oAuthClientAuthnContext4.setAuthenticated(false);

        return new Object[][]{

                // Successful request
                {requestParams1, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_CREATED, "", false, false},
                // Request with repeated redirect_uri parameter. Will return bad request error
                {requestParams2, new MultivaluedHashMap<>(), oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request with inactive client id. Will return unauthorized error
                {requestParams3, new MultivaluedHashMap<>(), oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request from invalid client. Will return unauthorized error
                {requestParams4, new MultivaluedHashMap<>(), oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request without client id. Will return bad request error
                {requestParams5, new MultivaluedHashMap<>(), oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request with unsupported response type. Will return bad request error
                {requestParams6, new MultivaluedHashMap<>(), oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request with invalid redirect uri. Will return bad request error
                {requestParams7, new MultivaluedHashMap<>(), oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_CALLBACK, false, false},
                // Request with request uri provided. Will return bad request error
                {requestParams1, paramMap2, oAuthClientAuthnContext1,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request with server error in client authentication context. Will return internal server error
                {requestParams1, new MultivaluedHashMap<>(), oAuthClientAuthnContext2,
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, OAuth2ErrorCodes.SERVER_ERROR, false, false},
                // Request with client error in client authentication context. Will return unauthorized error
                {requestParams1, new MultivaluedHashMap<>(), oAuthClientAuthnContext3,
                        HttpServletResponse.SC_UNAUTHORIZED, OAuth2ErrorCodes.INVALID_CLIENT, false, false},
                // Request with other error in client authentication context. Will return bad request error
                {requestParams1, new MultivaluedHashMap<>(), oAuthClientAuthnContext4,
                        HttpServletResponse.SC_BAD_REQUEST, "", false, false},
                // Request with no client authentication context. Will return bad request error
                {requestParams1, new MultivaluedHashMap<>(), null,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, false, false},
                // Request that returns OAuthSystemException. Will return internal server error
                {requestParams1, paramMap1, oAuthClientAuthnContext1,
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, OAuth2ErrorCodes.SERVER_ERROR, true, false},
                // Request that contains form param with empty value. Will ignore the empty value and return success.
                {requestParams1, paramMap3, oAuthClientAuthnContext1, HttpServletResponse.SC_CREATED, "", false, false},
                // Request with request object. Will return success.
                {requestParams8, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_CREATED, "", false, false},
                // Successful FAPI request with response type code, response mode jwt.
                {requestParams9, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_CREATED, "", false, true},
                // FAPI request with response type code, response mode query.jwt. Will return bad request error.
                {requestParams10, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorCodes.INVALID_REQUEST, false, true},
                // FAPI request with response type code id_token, response mode query.jwt. Will return success
                {requestParams11, paramMap4, oAuthClientAuthnContext1, HttpServletResponse.SC_CREATED, "", false, true},
                // FAPI request without code challenge. Will return bad request error.
                {requestParams11, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorCodes.INVALID_REQUEST, false, true},
                // FAPI request without code challenge method. Will return bad request error.
                {requestParams12, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorCodes.INVALID_REQUEST, false, true},
                // FAPI request with invalid code challenge method. Will return bad request error.
                {requestParams13, paramMap1, oAuthClientAuthnContext1, HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorCodes.INVALID_REQUEST, false, true}
        };
    }

    @Test(dataProvider = "testParDataProvider", groups = "testWithConnection")
    public void testPar(Object requestParamsObj, Object paramMapObj, Object oAuthClientAuthnContextObj,
                        int expectedStatus, String expectedErrorCode, boolean testOAuthSystemException,
                        boolean isFAPITest)
            throws Exception {

        MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramMapObj;
        Map<String, String[]> requestParams = (Map<String, String[]>) requestParamsObj;
        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;

        mockOAuthServerConfiguration(paramMap);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getLoginTenantId()).thenReturn(-1234);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(getConnection());

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);

        HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<>());

        // Set authenticated client context
        request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT, oAuthClientAuthnContext);

        spy(EndpointUtil.class);
        doReturn(oAuth2Service).when(EndpointUtil.class, "getOAuth2Service");
        doCallRealMethod().when(oAuth2Service).validateInputParameters(request);
        doCallRealMethod().when(oAuth2Service).validateClientInfo(request);
        doReturn(parAuthService).when(EndpointUtil.class, "getParAuthService");
        if (testOAuthSystemException) {
            doThrow(new OAuthSystemException()).when(EndpointUtil.class, "getOAuthAuthzRequest", any());
        }
        when(parAuthService.handleParAuthRequest(any())).thenReturn(parAuthData);
        when(parAuthData.getrequestURIReference()).thenReturn(REQUEST_URI_REF);
        when(parAuthData.getExpiryTime()).thenReturn(EXPIRY_TIME);

        mockStatic(OIDCRequestObjectUtil.class);
        if (!isFAPITest && requestParams.containsKey(OAuthConstants.OAuth20Params.REQUEST)) {
            RequestObject requestObject = new RequestObject();
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            jwtClaimsSetBuilder.claim(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, "code-challenge-string");
            jwtClaimsSetBuilder.claim(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD, "S256");
            requestObject.setClaimSet(jwtClaimsSetBuilder.build());
            when(OIDCRequestObjectUtil.buildRequestObject(any(), any())).thenReturn(requestObject);
        } else {
            when(OIDCRequestObjectUtil.buildRequestObject(any(), any())).thenReturn(new RequestObject());
        }

        spy(OAuth2Util.class);
        doReturn(isFAPITest).when(OAuth2Util.class, "isFapiConformantApp", any());

        Response response;
        response = oAuth2ParEndpoint.par(request, httpServletResponse, paramMap);

        assertNotNull(response, "Par response is null");
        assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");
        assertNotNull(response.getEntity(), "Response entity is null");

        final String responseBody = response.getEntity().toString();

        if (expectedErrorCode != null) {
            assertTrue(responseBody.contains(expectedErrorCode), "Expected error code not found");
        }
        if (HttpServletResponse.SC_CREATED == expectedStatus) {
            assertTrue(responseBody.contains(REQUEST_URI),
                    "Successful response should contain request uri");
            assertTrue(responseBody.contains(String.valueOf(EXPIRY_TIME)),
                    "Successful response should contain expiry time");
        }
    }

    private Map<String, String[]> createRequestParamsMap(String[] clientIds, String[] redirectUris,
                                                         String[] responseTypes) {

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(OAuth.OAUTH_CLIENT_ID, clientIds);
        requestParams.put(OAuth.OAUTH_REDIRECT_URI, redirectUris);
        requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, responseTypes);

        return requestParams;
    }

    private HttpServletRequest mockHttpRequest(final Map<String, String[]> requestParams,
                                               final Map<String, Object> requestAttributes) {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        doAnswer(invocation -> {

            String key = (String) invocation.getArguments()[0];
            return requestParams.get(key) != null ? requestParams.get(key)[0] : null;
        }).when(httpServletRequest).getParameter(anyString());

        doAnswer(invocation -> {
            String key = (String) invocation.getArguments()[0];
            return requestAttributes.get(key);
        }).when(httpServletRequest).getAttribute(anyString());

        doAnswer(invocation -> {
            String key = (String) invocation.getArguments()[0];
            Object value = invocation.getArguments()[1];
            requestAttributes.put(key, value);
            return null;
        }).when(httpServletRequest).setAttribute(anyString(), any());

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameterNames()).thenReturn(Collections.enumeration(requestParams.keySet()));
        when(httpServletRequest.getMethod()).thenReturn(HttpMethod.POST);
        when(httpServletRequest.getContentType()).thenReturn(OAuth.ContentType.URL_ENCODED);

        return httpServletRequest;
    }

    private void mockOAuthServerConfiguration(MultivaluedMap<String, String> paramMap) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getSupportedResponseTypeValidators()).thenReturn(
                new HashMap<String, Class<? extends OAuthValidator<HttpServletRequest>>>() {{
                    put(paramMap.getFirst(OAuth.OAUTH_RESPONSE_TYPE), CodeValidator.class);
                }});

        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
        when(oAuthServerConfiguration.getOAuthAuthzRequestClassName())
                .thenReturn("org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest");
    }
}
