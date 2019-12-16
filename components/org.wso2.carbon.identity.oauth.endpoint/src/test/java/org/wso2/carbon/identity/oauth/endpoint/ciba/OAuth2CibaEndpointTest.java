/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, EndpointUtil.class})
public class OAuth2CibaEndpointTest extends PowerMockTestCase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    CibaAuthServiceImpl authService;

    @Mock
    OAuth2AuthzEndpoint oAuth2AuthzEndpoint;

    @Mock
    Response response;

    private OAuth2CibaEndpoint oAuth2CibaEndpoint;

    private static final String request = "eyJhbGciOiJIUzUxMiJ9" +
            ".eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6IjE5MDgxOTk1IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGVuaWQgc21zIiwiaWF0IjoxNTczMDk5NDEzLCJleHAiOjE1NzMxNDQzNzEsIm5iZiI6MTU3MzA5OTQxMywianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwicmVxdWVzdGVkX2V4cGlyeSI6MzcwMH0.dcyX4dNaI-u0maButJ4h3q383OnDXCPMzgHzpU3ZHxsjlGIC_I-B_3QApMnQCav8-cSaYv62FWTqoUOF9wf4yw";

    private static final String REQUEST_ATTRIBUTE = "request";

    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    CibaAuthCodeResponse authCodeResponse = new CibaAuthCodeResponse();
    String[] scopes = new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID};

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        oAuth2CibaEndpoint = new OAuth2CibaEndpoint();

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        authCodeResponse.setAuthReqId("2201e5aa-1c5f-4a17-90c9-1956a3540b19");
        authCodeResponse.setBindingMessage("Binding message for CIBA");
        authCodeResponse.setCallBackUrl("https://localhost:8000/callback");
        authCodeResponse.setClientId(CONSUMER_KEY);
        authCodeResponse.setExpiresIn(1000L);
        authCodeResponse.setScopes(scopes);
        authCodeResponse.setTransactionDetails("{random value}");
        authCodeResponse.setUserHint("user@wso2.com");

    }

    @DataProvider(name = "provideRequestParamsForBadRequest")
    public Object[][] provideRequestParamsForBadRequest() {

        String requestWithImproperClient =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi9jaWJhIiwiYmluZGluZ19tZXNzYWdlIjoidHJ5IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGVuaWQgc2NvcGUxIHNjb3BleCIsImlhdCI6MTU3NDk2OTU3NiwiZXhwIjo5NzYwODU1NTksIm5iZiI6MTU3NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.kFmduZ6Uq3fKNEPz1vYz7VtY0vWMSqVx85um8SZazKY";

        String requestWithWrongIAT =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjMyNTMyOTk2MTU5LCJleHAiOjE1NzU1Mjc1NzYsIm5iZiI6MTU3NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.ddpoZ2V34qoKh-NzPHK_lfs0xxPiOWfwFDMGaJzEpNk";

        String requestWithWrongNBF =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjE1NzQ5Njk1NzYsImV4cCI6MTU3NTUyNzU3NiwibmJmIjozMjUzMjk5NjE1OSwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.PF1clOqVCEWCjT8Z6jsJBlYnwtOvRaJsXn3OXzrm8p0";

        String requestWithWrongEXP =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjE1NzQ5Njk1NzYsImV4cCI6OTc2MDg1NTU5LCJuYmYiOjE1NzQ5Njk1NzYsImFjciI6IjU3ODg4Nzg4IiwianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.46v5geegF72oFWMTbJ2t84NfYOjHzC1ThaGPq0fbrdI";

        String requestwithnojti =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjE1NzQ5Njk1NzYsImV4cCI6OTc2MDg1NTU5LCJuYmYiOjE1NzQ5Njk1NzYsImFjciI6IjU3ODg4Nzg4IiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.fDNjJbpLHHNTm4crh0eMO3gc-rdDVtjYC_JXGqxx9ik";

        String requestWithNoScope =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsImlhdCI6MTU3NDk2OTU3NiwiZXhwIjo5NzYwODU1NTksIm5iZiI6MTU3NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.xbr7unhGmMm9auurwYGvEGAy9sJSxom1kWmciZdUJbQ";

        String requestWithBlankLoginHint =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiIiLCJzY29wZSI6Im9wZW5pZCBzY29wZTEgc2NvcGV4IiwiaWF0IjoxNTc0OTY5NTc2LCJleHAiOjk3NjA4NTU1OSwibmJmIjoxNTc0OTY5NTc2LCJhY3IiOiI1Nzg4ODc4OCIsImp0aSI6IjlmZjg0NWI5LTIwYmYtNDAzMy05ZWQzLTNjY2M2M2Y1MjA0YyIsInRyYW5zYWN0aW9uX2NvbnRleHQiOnsidXNlciI6InVzZXIiLCJhbW91bnQiOjEwMDAsInNob3AiOiJXU08yIENJQkEgREVNTyBDT05TT0xFIiwiYXBwbGljYXRpb24iOiJQYXlIZXJlIn19.w6T8VDlzcTz8tEbkXvXYoMaZ9yp4VW-z7U4qf-KmC6A";

        String requestWithBadIDToken = "   String requestWithBlankLoginHint =" +
                "                eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiIiLCJzY29wZSI6Im9wZW5pZCBzY29wZTEgc2NvcGV4IiwiaWF0IjoxNTc0OTY5NTc2LCJleHAiOjk3NjA4NTU1OSwibmJmIjoxNTc0OTY5NTc2LCJhY3IiOiI1Nzg4ODc4OCIsImp0aSI6IjlmZjg0NWI5LTIwYmYtNDAzMy05ZWQzLTNjY2M2M2Y1MjA0YyIsInRyYW5zYWN0aW9uX2NvbnRleHQiOnsidXNlciI6InVzZXIiLCJhbW91bnQiOjEwMDAsInNob3AiOiJXU08yIENJQkEgREVNTyBDT05TT0xFIiwiYXBwbGljYXRpb24iOiJQYXlIZXJlIn19.w6T8VDlzcTz8tEbkXvXYoMaZ9yp4VW-z7U4qf-KmC6A";
        return new Object[][]{
                {REQUEST_ATTRIBUTE, request, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithImproperClient, HttpServletResponse.SC_UNAUTHORIZED},
                {REQUEST_ATTRIBUTE, requestWithBlankLoginHint, HttpServletResponse.SC_UNAUTHORIZED},
                {REQUEST_ATTRIBUTE, requestwithnojti, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithNoScope, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithWrongEXP, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithWrongNBF, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithWrongIAT, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, request + "frsgtg.ftetryyru", HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, "eftaeg", HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, "etfcra.cesavr", HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, "vrsgyb.waygersh.reygsrab", HttpServletResponse.SC_BAD_REQUEST},
                {"", "", HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithBadIDToken, HttpServletResponse.SC_BAD_REQUEST}
        };
    }

    @Test(dataProvider = "provideRequestParamsForBadRequest")
    public void testCibaForBadRequest(String parameter, String paramValue, int expectedStatus) throws Exception {

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(parameter, new String[]{paramValue});

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameter(REQUEST_ATTRIBUTE)).thenReturn(paramValue);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(CONSUMER_KEY)).thenReturn(oAuthAppDO);

        when(oAuthAppDO.getGrantTypes()).thenReturn(CibaConstants.OAUTH_CIBA_GRANT_TYPE);

        OAuth2CibaEndpoint cibaEndpoint = new OAuth2CibaEndpoint();
        Response response = cibaEndpoint.ciba(httpServletRequest, httpServletResponse);
        Assert.assertEquals(response.getStatus(), expectedStatus);
    }

    @Test
    public void testCibaForProperRequest() throws Exception {

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(REQUEST_ATTRIBUTE, new String[]{
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjk3NjA4NTU1OSwiZXhwIjozMjUzMjk5NjE1OSwibmJmIjo5NzYwODU1NTksImFjciI6IjU3ODg4Nzg4IiwianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.LaOFJFtR74mNmG8ggfz9FTNZqRb3LINmtA3dudM-Irw"});

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameter(REQUEST_ATTRIBUTE)).thenReturn(
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjk3NjA4NTU1OSwiZXhwIjozMjUzMjk5NjE1OSwibmJmIjo5NzYwODU1NTksImFjciI6IjU3ODg4Nzg4IiwianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.LaOFJFtR74mNmG8ggfz9FTNZqRb3LINmtA3dudM-Irw");
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(CONSUMER_KEY)).thenReturn(oAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn("super");
        when(OAuth2Util.getIdTokenIssuer("super")).thenReturn("https://localhost:9443/oauth2/ciba");
        when(OAuth2Util.buildScopeString(any())).thenReturn("scope1 scope2 openid");
        when(oAuthAppDO.getGrantTypes()).thenReturn(CibaConstants.OAUTH_CIBA_GRANT_TYPE);

        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getCibaAuthService()).thenReturn(authService);

        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getCibaAuthService()).thenReturn(authService);
        when(authService.generateAuthCodeResponse(any())).thenReturn(authCodeResponse);

        CibaAuthzHandler cibaAuthzHandler = new CibaAuthzHandler();

        WhiteboxImpl.setInternalState(oAuth2CibaEndpoint, "cibaAuthzHandler", cibaAuthzHandler);
        WhiteboxImpl.setInternalState(cibaAuthzHandler, "authzEndPoint", oAuth2AuthzEndpoint);

        when(oAuth2AuthzEndpoint.authorize(any(), any())).thenReturn(response);

        Response response = oAuth2CibaEndpoint.ciba(httpServletRequest, httpServletResponse);
        Assert.assertEquals(response.getStatus(), 200);
    }

}
