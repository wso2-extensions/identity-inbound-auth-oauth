/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.token;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.apache.oltu.oauth2.as.validator.AuthorizationCodeValidator;
import org.apache.oltu.oauth2.as.validator.ClientCredentialValidator;
import org.apache.oltu.oauth2.as.validator.PasswordValidator;
import org.apache.oltu.oauth2.as.validator.RefreshTokenValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.NTLMAuthenticationValidator;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.SAML2GrantValidator;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.expmapper.InvalidRequestExceptionMapper;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthTokenRequest;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@Listeners(MockitoTestNGListener.class)
public class OAuth2TokenEndpointTest extends TestOAuthEndpointBase {

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO;

    private static final String SQL_ERROR = "sql_error";
    private static final String TOKEN_ERROR = "token_error";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_NAME = "myApp";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String INACTIVE_APP_NAME = "inactiveApp";
    private static final String USERNAME = "user1";
    private static final String PASSWORD = "password";
    private static final String REALM = "Basic realm=is.com";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String ACCESS_TOKEN = "1234-542230-45220-54245";
    private static final String REFRESH_TOKEN = "1234-542230-45220-54245";
    private static final String AUTHORIZATION_HEADER =
            "Basic " + Base64Utils.encode((CLIENT_ID_VALUE + ":" + SECRET).getBytes());

    private OAuth2TokenEndpoint oAuth2TokenEndpoint;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        PrivilegedCarbonContext.startTenantFlow();
        oAuth2TokenEndpoint = new OAuth2TokenEndpoint();

        initiateInMemoryH2();

        try {
            createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            // Ignore
        }
        try {
            createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME, "INACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            // Ignore
        }
    }

    @AfterClass
    public void clear() throws Exception {

        super.cleanData();
    }

    @BeforeMethod
    public void setUpBeforeMethod() {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        mockDatabase(identityDatabaseUtil);
    }

    @AfterMethod
    public void tearDownAfterMethod() {

        identityDatabaseUtil.close();
    }

    @DataProvider(name = "testIssueAccessTokenDataProvider")
    public Object[][] testIssueAccessTokenDataProvider() {

        MultivaluedMap<String, String> mapWithCredentials = new MultivaluedHashMap<String, String>();
        List<String> clientId = new ArrayList<>();
        clientId.add(CLIENT_ID_VALUE);
        List<String> secret = new ArrayList<>();
        secret.add(SECRET);

        mapWithCredentials.put(OAuth.OAUTH_CLIENT_ID, clientId);
        mapWithCredentials.put(OAuth.OAUTH_CLIENT_SECRET, secret);

        MultivaluedMap<String, String> mapWithClientId = new MultivaluedHashMap<>();
        mapWithClientId.put(OAuth.OAUTH_CLIENT_ID, clientId);

        String inactiveClientHeader =
                "Basic " + Base64Utils.encode((INACTIVE_CLIENT_ID_VALUE + ":dummySecret").getBytes());
        String invalidClientHeader = "Basic " + Base64Utils.encode(("invalidId:dummySecret").getBytes());
        String inCorrectAuthzHeader = "Basic value1 value2";

        ResponseHeader contentType = new ResponseHeader();
        contentType.setKey(OAuth.HeaderType.CONTENT_TYPE);
        contentType.setValue(OAuth.ContentType.URL_ENCODED);

        ResponseHeader[] headers1 = new ResponseHeader[]{contentType};
        ResponseHeader[] headers2 = new ResponseHeader[]{null};
        ResponseHeader[] headers3 = new ResponseHeader[0];

        Map<String, String> customResponseParamMap = new HashMap<>();
        customResponseParamMap.put("param_key_1", "param_value_1");
        customResponseParamMap.put("param_key_2", "param_value_2");

        return new Object[][]{
                // Request with multivalued client_id parameter. Will return bad request error
                {CLIENT_ID_VALUE + ",clientId2", null, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), null, null, null, null, HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes
                        .INVALID_REQUEST},

                // Request with invalid authorization header. Will return bad request error
                {CLIENT_ID_VALUE, inCorrectAuthzHeader, mapWithClientId, GrantType.PASSWORD.toString(), null, null,
                        null, null, HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST},

                // Request from inactive client. Will give correct response, inactive client state should be handled
                // in access token issuer
                {INACTIVE_CLIENT_ID_VALUE, inactiveClientHeader, new MultivaluedHashMap<String, String>(), GrantType
                        .PASSWORD.toString(), null, null, null, null, HttpServletResponse.SC_OK, ""},

                // Request from invalid client. Will give correct response, invalid-id is handles in access token issuer
                {"invalidId", invalidClientHeader, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), null, null, null, null, HttpServletResponse.SC_OK, ""},

                // Request without client id and authz header. Will give bad request error
                {null, null, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD.toString(), null, null,
                        null, null, HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST},

                // Request with client id but no authz header. Will give bad request error
                {CLIENT_ID_VALUE, null, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD.toString(),
                        null, null, null, null, HttpServletResponse.SC_BAD_REQUEST, null},

                // Request with unsupported grant type. Will give bad request error
                {CLIENT_ID_VALUE, AUTHORIZATION_HEADER, new MultivaluedHashMap<String, String>(), "dummyGrant", null,
                        null, null, null, HttpServletResponse.SC_BAD_REQUEST, null},

                // Successful request without id token request. No headers
                {CLIENT_ID_VALUE, AUTHORIZATION_HEADER, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), null, null, null, null, HttpServletResponse.SC_OK, null},

                // Successful request with id token request. With header values
                {CLIENT_ID_VALUE, AUTHORIZATION_HEADER, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), "idTokenValue", headers1, null, null, HttpServletResponse.SC_OK, null},

                // Successful request with id token request. With header which contains null values
                {CLIENT_ID_VALUE, AUTHORIZATION_HEADER, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), "idTokenValue", headers2, null, null, HttpServletResponse.SC_OK, null},

                // Successful request with id token request. With empty header array
                {CLIENT_ID_VALUE, AUTHORIZATION_HEADER, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), "idTokenValue", headers3, null, null, HttpServletResponse.SC_OK, null},

                // Successful token request that will return custom response parameters in response.
                {CLIENT_ID_VALUE, AUTHORIZATION_HEADER, new MultivaluedHashMap<String, String>(), GrantType.PASSWORD
                        .toString(), null, null, customResponseParamMap, null, HttpServletResponse.SC_OK, null}
        };
    }

    @Test(dataProvider = "testIssueAccessTokenDataProvider", groups = "testWithConnection")
    public void testIssueAccessToken(String clientId, String authzHeader, Object paramMapObj, String grantType,
                                     String idToken, Object headerObj, Object customResponseParamObj, Exception e,
                                     int expectedStatus, String expectedErrorCode) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);) {
            MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramMapObj;
            ResponseHeader[] responseHeaders = (ResponseHeader[]) headerObj;
            Map<String, String> customResponseParameters = (Map<String, String>) customResponseParamObj;

            Map<String, String[]> requestParams = new HashMap<>();

            if (clientId != null) {
                requestParams.put(OAuth.OAUTH_CLIENT_ID, clientId.split(","));
            }
            requestParams.put(OAuth.OAUTH_GRANT_TYPE, new String[]{grantType});
            requestParams.put(OAuth.OAUTH_SCOPE, new String[]{"scope1"});
            requestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});
            requestParams.put(OAuth.OAUTH_USERNAME, new String[]{USERNAME});
            requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{PASSWORD});

            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(true);

            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<>());

            request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT, oAuthClientAuthnContext);

            lenient().when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn(authzHeader);
            lenient().when(request.getHeaderNames()).thenReturn(
                    Collections.enumeration(new ArrayList<String>() {{
                        add(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);
                    }}));

            endpointUtil.when(EndpointUtil::getRealmInfo).thenReturn(REALM);
            endpointUtil.when(EndpointUtil::getOAuth2Service).thenReturn(oAuth2Service);

            lenient().when(oAuth2Service.issueAccessToken(any(OAuth2AccessTokenReqDTO.class))).thenReturn(
                    oAuth2AccessTokenRespDTO);
            lenient().when(oAuth2AccessTokenRespDTO.getAccessToken()).thenReturn(ACCESS_TOKEN);
            lenient().when(oAuth2AccessTokenRespDTO.getRefreshToken()).thenReturn(REFRESH_TOKEN);
            lenient().when(oAuth2AccessTokenRespDTO.getExpiresIn()).thenReturn(3600L);
            lenient().when(oAuth2AccessTokenRespDTO.getAuthorizedScopes()).thenReturn("scope1");
            lenient().when(oAuth2AccessTokenRespDTO.getIDToken()).thenReturn(idToken);
            lenient().when(oAuth2AccessTokenRespDTO.getResponseHeaders()).thenReturn(responseHeaders);
            lenient().when(oAuth2AccessTokenRespDTO.getParameters()).thenReturn(customResponseParameters);

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
            grantTypeValidators.put(GrantType.PASSWORD.toString(), PasswordValidator.class);

            lenient().when(mockOAuthServerConfiguration.getSupportedGrantTypeValidators())
                    .thenReturn(grantTypeValidators);
            lenient().when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

            Response response;
            HttpServletResponse httpServletResponse = mock(HttpServletResponse.class);
            HttpServletResponseWrapper httpServletResponseWrapper = mock(HttpServletResponseWrapper.class);
            endpointUtil.when(() -> EndpointUtil.getHttpServletResponseWrapper(any()))
                    .thenReturn(httpServletResponseWrapper);
            try {
                response = oAuth2TokenEndpoint.issueAccessToken(request, httpServletResponse, paramMap);
            } catch (InvalidRequestParentException ire) {
                InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                response = invalidRequestExceptionMapper.toResponse(ire);
            }

            assertNotNull(response, "Token response is null");
            assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

            assertNotNull(response.getEntity(), "Response entity is null");

            final String responseBody = response.getEntity().toString();
            if (customResponseParameters != null) {
                customResponseParameters.forEach((key, value) -> assertTrue(responseBody.contains(key) && responseBody
                                .contains(value),
                        "Expected custom response parameter: " + key + " not found in token response."));
            }

            if (expectedErrorCode != null) {
                assertTrue(responseBody.contains(expectedErrorCode), "Expected error code not found");
            } else if (HttpServletResponse.SC_OK == expectedStatus) {
                assertTrue(responseBody.contains(ACCESS_TOKEN),
                        "Successful response should contain access token");
            }
        }
    }

    @DataProvider(name = "testTokenErrorResponseDataProvider")
    public Object[][] testTokenErrorResponseDataProvider() {

        ResponseHeader contentType = new ResponseHeader();
        contentType.setKey(OAuth.HeaderType.CONTENT_TYPE);
        contentType.setValue(OAuth.ContentType.URL_ENCODED);

        ResponseHeader[] headers1 = new ResponseHeader[]{contentType};
        ResponseHeader[] headers2 = new ResponseHeader[]{null};
        ResponseHeader[] headers3 = new ResponseHeader[0];

        // This object provides data to cover all the scenarios with token error response
        return new Object[][]{
                {OAuth2ErrorCodes.INVALID_CLIENT, null, HttpServletResponse.SC_UNAUTHORIZED,
                        OAuth2ErrorCodes.INVALID_CLIENT},
                {OAuth2ErrorCodes.SERVER_ERROR, null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        OAuth2ErrorCodes.SERVER_ERROR},
                {OAuth2ErrorCodes.ACCESS_DENIED, null, HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorCodes.ACCESS_DENIED},
                {SQL_ERROR, null, HttpServletResponse.SC_BAD_GATEWAY, OAuth2ErrorCodes.SERVER_ERROR},
                {TOKEN_ERROR, null, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR},
                {TOKEN_ERROR, headers1, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR},
                {TOKEN_ERROR, headers2, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR},
                {TOKEN_ERROR, headers3, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR},
        };
    }

    @Test(dataProvider = "testTokenErrorResponseDataProvider", groups = "testWithConnection")
    public void testTokenErrorResponse(String errorCode, Object headerObj, int expectedStatus,
                                       String expectedErrorCode) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);) {
            ResponseHeader[] responseHeaders = (ResponseHeader[]) headerObj;

            Map<String, String[]> requestParams = new HashMap<>();
            requestParams.put(OAuth.OAUTH_GRANT_TYPE, new String[]{GrantType.PASSWORD.toString()});
            requestParams.put(OAuth.OAUTH_USERNAME, new String[]{USERNAME});
            requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{PASSWORD});

            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(true);

            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<>());
            request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT, oAuthClientAuthnContext);
            when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn(AUTHORIZATION_HEADER);
            when(request.getHeaderNames()).thenReturn(
                    Collections.enumeration(new ArrayList<String>() {{
                        add(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);
                    }}));

            endpointUtil.when(EndpointUtil::getRealmInfo).thenReturn(REALM);
            endpointUtil.when(EndpointUtil::getOAuth2Service).thenReturn(oAuth2Service);

            when(oAuth2Service.issueAccessToken(any(OAuth2AccessTokenReqDTO.class))).thenReturn(
                    oAuth2AccessTokenRespDTO);
            when(oAuth2AccessTokenRespDTO.getErrorMsg()).thenReturn("Token Response error");
            when(oAuth2AccessTokenRespDTO.getErrorCode()).thenReturn(errorCode);
            lenient().when(oAuth2AccessTokenRespDTO.getResponseHeaders()).thenReturn(responseHeaders);

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
            grantTypeValidators.put(GrantType.PASSWORD.toString(), PasswordValidator.class);

            when(mockOAuthServerConfiguration.getSupportedGrantTypeValidators()).thenReturn(grantTypeValidators);
            lenient().when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

            Response response;
            HttpServletResponse httpServletResponse = mock(HttpServletResponse.class);
            HttpServletResponseWrapper httpServletResponseWrapper = mock(HttpServletResponseWrapper.class);
            endpointUtil.when(() -> EndpointUtil.getHttpServletResponseWrapper(any()))
                    .thenReturn(httpServletResponseWrapper);
            try {
                response = oAuth2TokenEndpoint.issueAccessToken(request, httpServletResponse,
                        new MultivaluedHashMap<>());
            } catch (InvalidRequestParentException ire) {
                InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                response = invalidRequestExceptionMapper.toResponse(ire);
            }

            assertNotNull(response, "Token response is null");
            assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");
            assertNotNull(response.getEntity(), "Response entity is null");
            assertTrue(response.getEntity().toString().contains(expectedErrorCode), "Expected error code not found");
        }
    }

    @Test()
    public void testIssueAccessTokenWithInvalidClientSecret() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);) {
            ResponseHeader[] responseHeaders = new ResponseHeader[]{null};
            Map<String, String[]> requestParams = new HashMap<>();
            requestParams.put(OAuth.OAUTH_GRANT_TYPE, new String[]{GrantType.CLIENT_CREDENTIALS.toString()});
            requestParams.put(OAuth.OAUTH_USERNAME, new String[]{USERNAME});
            requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{PASSWORD});
            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<String, Object>());
            request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT, oAuthClientAuthnContext);

            when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn("Basic " +
                    Base64Utils.encode((CLIENT_ID_VALUE + ":" + SECRET.substring(0, SECRET.length() - 5)).getBytes()));
            when(request.getHeaderNames()).thenReturn(
                    Collections.enumeration(new ArrayList<String>() {{
                        add(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);
                    }}));

            endpointUtil.when(EndpointUtil::getRealmInfo).thenReturn(REALM);
            endpointUtil.when(EndpointUtil::getOAuth2Service).thenReturn(oAuth2Service);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
            grantTypeValidators.put(GrantType.CLIENT_CREDENTIALS.toString(), PasswordValidator.class);
            when(mockOAuthServerConfiguration.getSupportedGrantTypeValidators()).thenReturn(grantTypeValidators);

            Response response;
            HttpServletResponse httpServletResponse = mock(HttpServletResponse.class);
            HttpServletResponseWrapper httpServletResponseWrapper = mock(HttpServletResponseWrapper.class);
            endpointUtil.when(() -> EndpointUtil.getHttpServletResponseWrapper(any()))
                    .thenReturn(httpServletResponseWrapper);
            try {
                response = oAuth2TokenEndpoint.issueAccessToken(request, httpServletResponse,
                        new MultivaluedHashMap<>());
            } catch (InvalidRequestParentException ire) {
                InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                response = invalidRequestExceptionMapper.toResponse(ire);
            }

            assertNotNull(response, "Token response is null");
            assertEquals(response.getStatus(), 401, "Unexpected HTTP response status");
            assertNotNull(response.getEntity(), "Response entity is null");
            assertTrue(response.getEntity().toString().contains(OAuth2ErrorCodes.INVALID_CLIENT),
                    "Expected error code not found");
            assertTrue(response.getMetadata().containsKey(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE),
                    "Missing WWW-Authenticate header");
        }
    }

    @DataProvider(name = "testGetAccessTokenDataProvider")
    public Object[][] testGetAccessTokenDataProvider() {

        return new Object[][]{
                {GrantType.AUTHORIZATION_CODE.toString(), OAuth.OAUTH_CODE},
                {GrantType.PASSWORD.toString(), OAuth.OAUTH_USERNAME + "," + OAuth.OAUTH_PASSWORD},
                {GrantType.REFRESH_TOKEN.toString(), OAuth.OAUTH_REFRESH_TOKEN},
                {org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString(), OAuth.OAUTH_ASSERTION},
                {org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString(), OAuthConstants.WINDOWS_TOKEN},
                {GrantType.CLIENT_CREDENTIALS.toString(), OAuth.OAUTH_GRANT_TYPE},
        };
    }

    @Test(dataProvider = "testGetAccessTokenDataProvider")
    public void testGetAccessToken(String grantType, String additionalParameters) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);) {
            Map<String, String[]> requestParams = new HashMap<>();
            requestParams.put(OAuth.OAUTH_CLIENT_ID, new String[]{CLIENT_ID_VALUE});
            requestParams.put(OAuth.OAUTH_GRANT_TYPE, new String[]{grantType});
            requestParams.put(OAuth.OAUTH_SCOPE, new String[]{"scope1"});

            // Required params for authorization_code grant type
            requestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});
            requestParams.put(OAuth.OAUTH_CODE, new String[]{"auth_code"});

            // Required params for password grant type
            requestParams.put(OAuth.OAUTH_USERNAME, new String[]{USERNAME});
            requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{PASSWORD});

            // Required params for refresh token grant type
            requestParams.put(OAuth.OAUTH_REFRESH_TOKEN, new String[]{REFRESH_TOKEN});

            // Required params for saml2 bearer grant type
            requestParams.put(OAuth.OAUTH_ASSERTION, new String[]{"dummyAssertion"});

            // Required params for IWA_NLTM grant type
            requestParams.put(OAuthConstants.WINDOWS_TOKEN, new String[]{"dummyWindowsToken"});

            HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<String, Object>());
            when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn(AUTHORIZATION_HEADER);
            when(request.getHeaderNames()).thenReturn(
                    Collections.enumeration(new ArrayList<String>() {{
                        add(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);
                    }}));

            Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
            grantTypeValidators.put(GrantType.PASSWORD.toString(), PasswordValidator.class);
            grantTypeValidators.put(GrantType.CLIENT_CREDENTIALS.toString(), ClientCredentialValidator.class);
            grantTypeValidators.put(GrantType.AUTHORIZATION_CODE.toString(), AuthorizationCodeValidator.class);
            grantTypeValidators.put(GrantType.REFRESH_TOKEN.toString(), RefreshTokenValidator.class);
            grantTypeValidators.put(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString(),
                    NTLMAuthenticationValidator.class);
            grantTypeValidators.put(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString(),
                    SAML2GrantValidator.class);

            mockOAuthServerConfiguration(oAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getSupportedGrantTypeValidators()).thenReturn(grantTypeValidators);

            endpointUtil.when(EndpointUtil::getOAuth2Service).thenReturn(oAuth2Service);
            final Map<String, String> parametersSetToRequest = new HashMap<>();
            doAnswer(new Answer<Object>() {
                @Override
                public Object answer(InvocationOnMock invocation) throws Throwable {

                    OAuth2AccessTokenReqDTO request = (OAuth2AccessTokenReqDTO) invocation.getArguments()[0];
                    parametersSetToRequest.put(OAuth.OAUTH_CODE, request.getAuthorizationCode());
                    parametersSetToRequest.put(OAuth.OAUTH_USERNAME, request.getResourceOwnerUsername());
                    parametersSetToRequest.put(OAuth.OAUTH_PASSWORD, request.getResourceOwnerPassword());
                    parametersSetToRequest.put(OAuth.OAUTH_REFRESH_TOKEN, request.getRefreshToken());
                    parametersSetToRequest.put(OAuth.OAUTH_ASSERTION, request.getAssertion());
                    parametersSetToRequest.put(OAuthConstants.WINDOWS_TOKEN, request.getWindowsToken());
                    parametersSetToRequest.put(OAuth.OAUTH_GRANT_TYPE, request.getGrantType());
                    OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
                    return tokenRespDTO;
                }
            }).when(oAuth2Service).issueAccessToken(any(OAuth2AccessTokenReqDTO.class));

            CarbonOAuthTokenRequest oauthRequest = new CarbonOAuthTokenRequest(request);
            HttpServletRequestWrapper httpServletRequestWrapper = new HttpServletRequestWrapper(request);

            Class<?> clazz = OAuth2TokenEndpoint.class;
            Object tokenEndpointObj = clazz.newInstance();
            Method getAccessToken = tokenEndpointObj.getClass().
                    getDeclaredMethod("issueAccessToken", CarbonOAuthTokenRequest.class,
                            HttpServletRequestWrapper.class, HttpServletResponseWrapper.class);
            getAccessToken.setAccessible(true);
            HttpServletResponse httpServletResponse = mock(HttpServletResponse.class);
            HttpServletResponseWrapper httpServletResponseWrapper = mock(HttpServletResponseWrapper.class);
            endpointUtil.when(() -> EndpointUtil.getHttpServletResponseWrapper(any()))
                    .thenReturn(httpServletResponseWrapper);
            OAuth2AccessTokenRespDTO tokenRespDTO = (OAuth2AccessTokenRespDTO)
                    getAccessToken.invoke(tokenEndpointObj, oauthRequest, httpServletRequestWrapper,
                            new HttpServletResponseWrapper(httpServletResponse));

            assertNotNull(tokenRespDTO, "ResponseDTO is null");
            String[] paramsToCheck = additionalParameters.split(",");
            for (String param : paramsToCheck) {
                assertNotNull(parametersSetToRequest.get(param), "Required parameter " + param + " is not set for " +
                        grantType + "grant type");
            }
        }
    }

    private HttpServletRequest mockHttpRequest(final Map<String, String[]> requestParams,
                                               final Map<String, Object> requestAttributes) {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        lenient().doAnswer((Answer<Object>) invocation -> {

            String key = (String) invocation.getArguments()[0];
            return requestParams.get(key) != null ? requestParams.get(key)[0] : null;
        }).when(httpServletRequest).getParameter(anyString());

        doAnswer((Answer<Object>) invocation -> {

            String key = (String) invocation.getArguments()[0];
            return requestAttributes.get(key);
        }).when(httpServletRequest).getAttribute(anyString());

        lenient().doAnswer((Answer<Object>) invocation -> {

            String key = (String) invocation.getArguments()[0];
            Object value = invocation.getArguments()[1];
            requestAttributes.put(key, value);
            return null;
        }).when(httpServletRequest).setAttribute(anyString(), any());

        lenient().when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        lenient().when(httpServletRequest.getParameterNames()).thenReturn(
                new IteratorEnumeration(requestParams.keySet().iterator()));
        lenient().when(httpServletRequest.getMethod()).thenReturn(HttpMethod.POST);
        lenient().when(httpServletRequest.getContentType()).thenReturn(OAuth.ContentType.URL_ENCODED);

        return httpServletRequest;
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
    }
}
