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
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
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
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest({EndpointUtil.class, IdentityDatabaseUtil.class, OAuthServerConfiguration.class,
        CarbonOAuthTokenRequest.class})
public class OAuth2TokenEndpointTest extends TestOAuthEndpointBase {

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO;

    @Mock
    CarbonOAuthTokenRequest carbonOAuthTokenRequest;

    private static final String SQL_ERROR = "sql_error";
    private static final String TOKEN_ERROR = "token_error";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_NAME = "myApp";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String INACTIVE_APP_NAME = "inactiveApp";
    private static final String USERNAME = "user1";
    private static final String REALM = "Basic realm=is.com";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String ACCESS_TOKEN = "1234-542230-45220-54245";
    private static final String REFRESH_TOKEN = "1234-542230-45220-54245";
    private static final String AUTHORIZATION_HEADER =
        "Basic " + Base64Utils.encode((CLIENT_ID_VALUE + ":" + SECRET).getBytes());

    private OAuth2TokenEndpoint oAuth2TokenEndpoint;

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        oAuth2TokenEndpoint = new OAuth2TokenEndpoint();

        initiateInMemoryH2();
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME, "INACTIVE");
    }

    @AfterTest
    public void clear() throws Exception {
        super.cleanData();
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

        return new Object[][] {
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
        requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{"password"});

        HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<String, Object>());
        when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn(authzHeader);
        when(request.getHeaderNames()).thenReturn(
                Collections.enumeration(new ArrayList<String>(){{ add(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);}}));

        spy(EndpointUtil.class);
        doReturn(REALM).when(EndpointUtil.class, "getRealmInfo");
        doReturn(oAuth2Service).when(EndpointUtil.class, "getOAuth2Service");

        when(oAuth2Service.issueAccessToken(any(OAuth2AccessTokenReqDTO.class))).thenReturn(oAuth2AccessTokenRespDTO);
        when(oAuth2AccessTokenRespDTO.getAccessToken()).thenReturn(ACCESS_TOKEN);
        when(oAuth2AccessTokenRespDTO.getRefreshToken()).thenReturn(REFRESH_TOKEN);
        when(oAuth2AccessTokenRespDTO.getExpiresIn()).thenReturn(3600L);
        when(oAuth2AccessTokenRespDTO.getAuthorizedScopes()).thenReturn("scope1");
        when(oAuth2AccessTokenRespDTO.getIDToken()).thenReturn(idToken);
        when(oAuth2AccessTokenRespDTO.getResponseHeaders()).thenReturn(responseHeaders);
        when(oAuth2AccessTokenRespDTO.getParameters()).thenReturn(customResponseParameters);

        mockOAuthServerConfiguration();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
        grantTypeValidators.put(GrantType.PASSWORD.toString(), PasswordValidator.class);

        when(oAuthServerConfiguration.getSupportedGrantTypeValidators()).thenReturn(grantTypeValidators);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

        Response response;
        try {
            response = oAuth2TokenEndpoint.issueAccessToken(request, paramMap);
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
                    .contains(value), "Expected custom response parameter: " + key + " not found in token response."));
        }

        if (expectedErrorCode != null) {
            assertTrue(responseBody.contains(expectedErrorCode), "Expected error code not found");
        } else if (HttpServletResponse.SC_OK == expectedStatus) {
            assertTrue(responseBody.contains(ACCESS_TOKEN),
                    "Successful response should contain access token");
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
        return new Object[][] {
                { OAuth2ErrorCodes.INVALID_CLIENT, null, HttpServletResponse.SC_UNAUTHORIZED,
                        OAuth2ErrorCodes.INVALID_CLIENT },
                { OAuth2ErrorCodes.SERVER_ERROR, null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        OAuth2ErrorCodes.SERVER_ERROR },
                { SQL_ERROR, null, HttpServletResponse.SC_BAD_GATEWAY, OAuth2ErrorCodes.SERVER_ERROR },
                { TOKEN_ERROR, null, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR },
                { TOKEN_ERROR, headers1, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR },
                { TOKEN_ERROR, headers2, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR },
                { TOKEN_ERROR, headers3, HttpServletResponse.SC_BAD_REQUEST, TOKEN_ERROR },
        };
    }

    @Test(dataProvider = "testTokenErrorResponseDataProvider", groups = "testWithConnection")
    public void testTokenErrorResponse(String errorCode, Object headerObj, int expectedStatus,
                                       String expectedErrorCode) throws Exception {
        ResponseHeader[] responseHeaders = (ResponseHeader[]) headerObj;

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(OAuth.OAUTH_GRANT_TYPE, new String[]{GrantType.PASSWORD.toString()});
        requestParams.put(OAuth.OAUTH_USERNAME, new String[]{USERNAME});
        requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{"password"});

        HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<String, Object>());
        when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn(AUTHORIZATION_HEADER);
        when(request.getHeaderNames()).thenReturn(
                Collections.enumeration(new ArrayList<String>(){{ add (OAuthConstants.HTTP_REQ_HEADER_AUTHZ);}}));

        spy(EndpointUtil.class);
        doReturn(REALM).when(EndpointUtil.class, "getRealmInfo");
        doReturn(oAuth2Service).when(EndpointUtil.class, "getOAuth2Service");

        when(oAuth2Service.issueAccessToken(any(OAuth2AccessTokenReqDTO.class))).thenReturn(oAuth2AccessTokenRespDTO);
        when(oAuth2AccessTokenRespDTO.getErrorMsg()).thenReturn("Token Response error");
        when(oAuth2AccessTokenRespDTO.getErrorCode()).thenReturn(errorCode);
        when(oAuth2AccessTokenRespDTO.getResponseHeaders()).thenReturn(responseHeaders);

        mockOAuthServerConfiguration();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
        grantTypeValidators.put(GrantType.PASSWORD.toString(), PasswordValidator.class);

        when(oAuthServerConfiguration.getSupportedGrantTypeValidators()).thenReturn(grantTypeValidators);
        when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

        Response response;
        try {
            response = oAuth2TokenEndpoint.issueAccessToken(request, new MultivaluedHashMap<String, String>());
        } catch (InvalidRequestParentException ire) {
            InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
            response = invalidRequestExceptionMapper.toResponse(ire);
        }

        assertNotNull(response, "Token response is null");
        assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");
        assertNotNull(response.getEntity(), "Response entity is null");
        assertTrue(response.getEntity().toString().contains(expectedErrorCode), "Expected error code not found");
    }

    @DataProvider(name = "testGetAccessTokenDataProvider")
    public Object[][] testGetAccessTokenDataProvider() {
        return new Object[][] {
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
        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(OAuth.OAUTH_CLIENT_ID, new String[] {CLIENT_ID_VALUE});
        requestParams.put(OAuth.OAUTH_GRANT_TYPE, new String[]{grantType});
        requestParams.put(OAuth.OAUTH_SCOPE, new String[]{"scope1"});

        // Required params for authorization_code grant type
        requestParams.put(OAuth.OAUTH_REDIRECT_URI, new String[]{APP_REDIRECT_URL});
        requestParams.put(OAuth.OAUTH_CODE, new String[]{"auth_code"});

        // Required params for password grant type
        requestParams.put(OAuth.OAUTH_USERNAME, new String[]{USERNAME});
        requestParams.put(OAuth.OAUTH_PASSWORD, new String[]{"password"});

        // Required params for refresh token grant type
        requestParams.put(OAuth.OAUTH_REFRESH_TOKEN, new String[]{REFRESH_TOKEN});

        // Required params for saml2 bearer grant type
        requestParams.put(OAuth.OAUTH_ASSERTION, new String[]{"dummyAssertion"});

        // Required params for IWA_NLTM grant type
        requestParams.put(OAuthConstants.WINDOWS_TOKEN, new String[]{"dummyWindowsToken"});

        HttpServletRequest request = mockHttpRequest(requestParams, new HashMap<String, Object>());
        when(request.getHeader(OAuthConstants.HTTP_REQ_HEADER_AUTHZ)).thenReturn(AUTHORIZATION_HEADER);
        when(request.getHeaderNames()).thenReturn(
                Collections.enumeration(new ArrayList<String>(){{ add(OAuthConstants.HTTP_REQ_HEADER_AUTHZ);}}));

        Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> grantTypeValidators = new Hashtable<>();
        grantTypeValidators.put(GrantType.PASSWORD.toString(), PasswordValidator.class);
        grantTypeValidators.put(GrantType.CLIENT_CREDENTIALS.toString(), ClientCredentialValidator.class);
        grantTypeValidators.put(GrantType.AUTHORIZATION_CODE.toString(), AuthorizationCodeValidator.class);
        grantTypeValidators.put(GrantType.REFRESH_TOKEN.toString(), RefreshTokenValidator.class);
        grantTypeValidators.put(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString(),
                NTLMAuthenticationValidator.class);
        grantTypeValidators.put(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString(),
                SAML2GrantValidator.class);

        mockOAuthServerConfiguration();
        when(oAuthServerConfiguration.getSupportedGrantTypeValidators()).thenReturn(grantTypeValidators);

        spy(EndpointUtil.class);
        doReturn(oAuth2Service).when(EndpointUtil.class, "getOAuth2Service");
        final Map<String, String> parametersSetToRequest = new HashMap<>();
        doAnswer(new Answer<Object>(){
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

        Class<?> clazz = OAuth2TokenEndpoint.class;
        Object tokenEndpointObj = clazz.newInstance();
        Method getAccessToken = tokenEndpointObj.getClass().
                getDeclaredMethod("issueAccessToken", CarbonOAuthTokenRequest.class);
        getAccessToken.setAccessible(true);
        OAuth2AccessTokenRespDTO tokenRespDTO = (OAuth2AccessTokenRespDTO)
                getAccessToken.invoke(tokenEndpointObj, oauthRequest);

        assertNotNull(tokenRespDTO, "ResponseDTO is null");
        String[] paramsToCheck = additionalParameters.split(",");
        for(String param : paramsToCheck) {
            assertNotNull(parametersSetToRequest.get(param), "Required parameter " + param + " is not set for " +
                    grantType + "grant type");
        }
    }

    private HttpServletRequest mockHttpRequest(final Map<String, String[]> requestParams,
                                               final Map<String, Object> requestAttributes) {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
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
        when(httpServletRequest.getParameterNames()).thenReturn(
                new IteratorEnumeration(requestParams.keySet().iterator()));
        when(httpServletRequest.getMethod()).thenReturn(HttpMethod.POST);
        when(httpServletRequest.getContentType()).thenReturn(OAuth.ContentType.URL_ENCODED);

        return httpServletRequest;
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
