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

import org.junit.Assert;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CIBARequestObjectValidatorImpl;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidator;
import org.wso2.carbon.identity.openidconnect.RequestParamRequestObjectBuilder;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, EndpointUtil.class, ServiceURL.class,
        ServiceURLBuilder.class, IdentityTenantUtil.class,
        LoggerUtils.class})
public class OAuth2CibaEndpointTest extends PowerMockTestCase {

    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";

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

    @Mock
    CIBARequestObjectValidatorImpl cibaRequestObjectValidator;

    private OAuth2CibaEndpoint oAuth2CibaEndpoint;

    private static final String request = "eyJhbGciOiJIUzUxMiJ9" +
            ".eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aD" +
            "IvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6IjE5MDgxOTk1IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGVuaWQgc" +
            "21zIiwiaWF0IjoxNTczMDk5NDEzLCJleHAiOjE1NzMxNDQzNzEsIm5iZiI6MTU3MzA5OTQxMywianRpIjoiOWZmODQ1YjktMjBi" +
            "Zi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwicmVxdWVzdGVkX2V4cGlyeSI6MzcwMH0.dcyX4dNaI-u0maButJ4h3q383OnDXCP" +
            "MzgHzpU3ZHxsjlGIC_I-B_3QApMnQCav8-cSaYv62FWTqoUOF9wf4yw";

    private static final String REQUEST_ATTRIBUTE = "request";

    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    CibaAuthCodeResponse authCodeResponse = new CibaAuthCodeResponse();
    String[] scopes = new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID};

    @BeforeClass
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
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi9jaWJ" +
                        "hIiwiYmluZGluZ19tZXNzYWdlIjoidHJ5IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGVuaW" +
                        "Qgc2NvcGUxIHNjb3BleCIsImlhdCI6MTU3NDk2OTU3NiwiZXhwIjo5NzYwODU1NTksIm5iZiI6MTU3NDk2O" +
                        "TU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2NjNjNmNTIw" +
                        "NGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjo" +
                        "iV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.kFmduZ6Uq3fKNEP" +
                        "z1vYz7VtY0vWMSqVx85um8SZazKY";

        String requestWithWrongIAT =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2Nhb" +
                        "Ghvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlay" +
                        "IsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjMyNTMyOTk2MTU5LCJleHAiOjE1NzU1Mjc1NzYs" +
                        "Im5iZiI6MTU3NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2N" +
                        "jNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjo" +
                        "iV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.ddpoZ2V34qoKh-NzPHK_lfs" +
                        "0xxPiOWfwFDMGaJzEpNk";

        String requestWithWrongNBF =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb" +
                        "2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ" +
                        "2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjE1NzQ5Njk1NzYsImV4cCI6MTU3N" +
                        "TUyNzU3NiwibmJmIjozMjUzMjk5NjE1OSwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQ" +
                        "wMzMtOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW" +
                        "50IjoxMDAwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9" +
                        "fQ.PF1clOqVCEWCjT8Z6jsJBlYnwtOvRaJsXn3OXzrm8p0";

        String requestWithWrongEXP =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0" +
                        "cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIs" +
                        "ImxvZ2luX2hpbnQiOiJ2aXZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQi" +
                        "OjE1NzQ5Njk1NzYsImV4cCI6OTc2MDg1NTU5LCJuYmYiOjE1NzQ5Njk1NzYsImFjciI6IjU3ODg4N" +
                        "zg4IiwianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwidHJhbnNhY3" +
                        "Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0l" +
                        "CQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.46v5geegF72oFWMTbJ2t8" +
                        "4NfYOjHzC1ThaGPq0fbrdI";

        String requestwithnojti =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2" +
                        "NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2a" +
                        "XZlayIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjE1NzQ5Njk1NzYsImV4cCI6OTc2MDg1" +
                        "NTU5LCJuYmYiOjE1NzQ5Njk1NzYsImFjciI6IjU3ODg4Nzg4IiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2V" +
                        "yIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdG" +
                        "lvbiI6IlBheUhlcmUifX0.fDNjJbpLHHNTm4crh0eMO3gc-rdDVtjYC_JXGqxx9ik";

        String requestWithNoScope =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cH" +
                        "M6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ" +
                        "2luX2hpbnQiOiJ2aXZlayIsImlhdCI6MTU3NDk2OTU3NiwiZXhwIjo5NzYwODU1NTksIm5iZiI6MTU3" +
                        "NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2N" +
                        "jNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMD" +
                        "AwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ" +
                        ".xbr7unhGmMm9auurwYGvEGAy9sJSxom1kWmciZdUJbQ";

        String requestWithBlankLoginHint =
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9" +
                        "sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQ" +
                        "iOiIiLCJzY29wZSI6Im9wZW5pZCBzY29wZTEgc2NvcGV4IiwiaWF0IjoxNTc0OTY5NTc2LCJleHAiOjk3NjA" +
                        "4NTU1OSwibmJmIjoxNTc0OTY5NTc2LCJhY3IiOiI1Nzg4ODc4OCIsImp0aSI6IjlmZjg0NWI5LTIwYmYtNDA" +
                        "zMy05ZWQzLTNjY2M2M2Y1MjA0YyIsInRyYW5zYWN0aW9uX2NvbnRleHQiOnsidXNlciI6InVzZXIiLCJhbW9" +
                        "1bnQiOjEwMDAsInNob3AiOiJXU08yIENJQkEgREVNTyBDT05TT0xFIiwiYXBwbGljYXRpb24iOiJQYXlIZXJ" +
                        "lIn19.w6T8VDlzcTz8tEbkXvXYoMaZ9yp4VW-z7U4qf-KmC6A";

        String requestWithBadIDToken = "   String requestWithBlankLoginHint =" +
                "                eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkI" +
                "joiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2h" +
                "pbnQiOiIiLCJzY29wZSI6Im9wZW5pZCBzY29wZTEgc2NvcGV4IiwiaWF0IjoxNTc0OTY5NTc2LCJleHAiOjk3NjA4NTU1O" +
                "SwibmJmIjoxNTc0OTY5NTc2LCJhY3IiOiI1Nzg4ODc4OCIsImp0aSI6IjlmZjg0NWI5LTIwYmYtNDAzMy05ZWQzLTNjY2M2" +
                "M2Y1MjA0YyIsInRyYW5zYWN0aW9uX2NvbnRleHQiOnsidXNlciI6InVzZXIiLCJhbW91bnQiOjEwMDAsInNob3AiOiJXU08" +
                "yIENJQkEgREVNTyBDT05TT0xFIiwiYXBwbGljYXRpb24iOiJQYXlIZXJlIn19.w6T8VDlzcTz8tEbkXvXYoMaZ9yp4VW-z7" +
                "U4qf-KmC6A";

        String requestWithIdTokenHint = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYX" +
                "VkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImlkX3Rva2VuX" +
                "2hpbnQiOiJkdW1teSIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjE1NzQ5Njk1NzYsImV4cCI6OTc2MDg1" +
                "NTU5LCJuYmYiOjE1NzQ5Njk1NzYsImFjciI6IjU3ODg4Nzg4IiwianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzY" +
                "zZjUyMDRjIiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImFtb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0" +
                "lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.4R3QsdgP_HR7skswDt8hBKCliKsak7wtS8V40MQWUuU";

        String requestWithIDtokenHintAndLoginHint = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5" +
                "OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsIml" +
                "kX3Rva2VuX2hpbnQiOiJkdW1teSIsImxvZ2luX2hpbnQiOiJkdW1teSIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJ" +
                "pYXQiOjE1NzQ5Njk1NzYsImV4cCI6OTc2MDg1NTU5LCJuYmYiOjE1NzQ5Njk1NzYsImFjciI6IjU3ODg4Nzg4IiwianRpIjoiOWZ" +
                "mODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwidHJhbnNhY3Rpb25fY29udGV4dCI6eyJ1c2VyIjoidXNlciIsImF" +
                "tb3VudCI6MTAwMCwic2hvcCI6IldTTzIgQ0lCQSBERU1PIENPTlNPTEUiLCJhcHBsaWNhdGlvbiI6IlBheUhlcmUifX0.fWm9M-z" +
                "qUI7KHMyexZNk-o3vautQPfrvK7ZYqLMbTaw";

        String requestWithEmptyAudience = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwi" +
                "YXVkIjoiIiwiYmluZGluZ19tZXNzYWdlIjoidHJ5IiwibG9naW5faGludCI6ImR1bW15Iiwic2NvcGUiOiJvcGVuaWQgc2NvcGUx" +
                "IHNjb3BleCIsImlhdCI6MTU3NDk2OTU3NiwiZXhwIjo5NzYwODU1NTksIm5iZiI6MTU3NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgi" +
                "LCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzMtOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIi" +
                "OiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVy" +
                "ZSJ9fQ.g88B9ztNS5gaP1RvqfsuhBnIr5GMKV4O0o6DKPNlZXw";

        String requestWithNoHints = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjo" +
                "iIiwiYmluZGluZ19tZXNzYWdlIjoidHJ5Iiwic2NvcGUiOiJvcGVuaWQgc2NvcGUxIHNjb3BleCIsImlhdCI6MTU3NDk2OTU3Niw" +
                "iZXhwIjo5NzYwODU1NTksIm5iZiI6MTU3NDk2OTU3NiwiYWNyIjoiNTc4ODg3ODgiLCJqdGkiOiI5ZmY4NDViOS0yMGJmLTQwMzM" +
                "tOWVkMy0zY2NjNjNmNTIwNGMiLCJ0cmFuc2FjdGlvbl9jb250ZXh0Ijp7InVzZXIiOiJ1c2VyIiwiYW1vdW50IjoxMDAwLCJzaG9" +
                "wIjoiV1NPMiBDSUJBIERFTU8gQ09OU09MRSIsImFwcGxpY2F0aW9uIjoiUGF5SGVyZSJ9fQ.Ist7f4VUiEth3T5e7bno5Pl1DzxC" +
                "bkhSZQmXd_B72Ic";

        return new Object[][]{
                {REQUEST_ATTRIBUTE, request, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithImproperClient, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithBlankLoginHint, HttpServletResponse.SC_BAD_REQUEST},
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
                {REQUEST_ATTRIBUTE, requestWithBadIDToken, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithIdTokenHint, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithIDtokenHintAndLoginHint, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithEmptyAudience, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE, requestWithNoHints, HttpServletResponse.SC_BAD_REQUEST}
        };
    }

    @Test(dataProvider = "provideRequestParamsForBadRequest")
    public void testCibaForBadRequest(String parameter, String paramValue, int expectedStatus) throws Exception {

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(parameter, new String[]{paramValue});

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameter(REQUEST_ATTRIBUTE)).thenReturn(paramValue);
        when(httpServletRequest.getParameterNames()).thenReturn(Collections.enumeration(requestParams.keySet()));
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setClientId("ZzxmDqqK8YYfjtlOh9vw85qnNVoa");
        when(httpServletRequest.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT)).thenReturn(oAuthClientAuthnContext);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(CONSUMER_KEY)).thenReturn(oAuthAppDO);

        when(oAuthAppDO.getGrantTypes()).thenReturn(CibaConstants.OAUTH_CIBA_GRANT_TYPE);

        mockServiceURLBuilder();
        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getIssuerIdentifierFromClientId(any())).thenReturn("https://localhost:9443/oauth2/token");

        OAuth2CibaEndpoint cibaEndpoint = new OAuth2CibaEndpoint();
        Response response = cibaEndpoint.ciba(httpServletRequest, httpServletResponse, new MultivaluedHashMap());
        Assert.assertEquals(expectedStatus, response.getStatus());
    }

    @Test
    public void testCibaForProperRequest() throws Exception {

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(REQUEST_ATTRIBUTE, new String[]{
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2Nhb" +
                        "Ghvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayI" +
                        "sInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjExMjg3MTQyMTksImV4cCI6OTYyODcxNDIxOSwib" +
                        "mJmIjoxMTI4NzE0MjE5LCJhY3IiOiI1Nzg4ODc4OCIsImp0aSI6IjlmZjg0NWI5LTIwYmYtNDAzMy05ZWQzLTNjY2M" +
                        "2M2Y1MjA0YyIsInRyYW5zYWN0aW9uX2NvbnRleHQiOnsidXNlciI6InVzZXIiLCJhbW91bnQiOjEwMDAsInNob3AiO" +
                        "iJXU08yIENJQkEgREVNTyBDT05TT0xFIiwiYXBwbGljYXRpb24iOiJQYXlIZXJlIn19.Sx_MjjautinmOV9vvP8yhu" +
                        "suBggOdBCjn1NyprpJoEg"});

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameterNames()).thenReturn(Collections.enumeration(requestParams.keySet()));
        when(httpServletRequest.getParameter(REQUEST_ATTRIBUTE)).thenReturn(
                "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2Nhb" +
                        "Ghvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6InRyeSIsImxvZ2luX2hpbnQiOiJ2aXZlayI" +
                        "sInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZXgiLCJpYXQiOjExMjg3MTQyMTksImV4cCI6OTYyODcxNDIxOSwib" +
                        "mJmIjoxMTI4NzE0MjE5LCJhY3IiOiI1Nzg4ODc4OCIsImp0aSI6IjlmZjg0NWI5LTIwYmYtNDAzMy05ZWQzLTNjY2M" +
                        "2M2Y1MjA0YyIsInRyYW5zYWN0aW9uX2NvbnRleHQiOnsidXNlciI6InVzZXIiLCJhbW91bnQiOjEwMDAsInNob3AiO" +
                        "iJXU08yIENJQkEgREVNTyBDT05TT0xFIiwiYXBwbGljYXRpb24iOiJQYXlIZXJlIn19.Sx_MjjautinmOV9vvP8yhu" +
                        "suBggOdBCjn1NyprpJoEg");
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setClientId("ZzxmDqqK8YYfjtlOh9vw85qnNVoa");
        when(httpServletRequest.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT)).thenReturn(oAuthClientAuthnContext);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(CONSUMER_KEY)).thenReturn(oAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn("super");
        when(OAuth2Util.getIdTokenIssuer("super")).thenReturn("https://localhost:9443/oauth2/ciba");
        when(OAuth2Util.buildScopeString(any())).thenReturn("scope1 scope2 openid");
        when(oAuthAppDO.getGrantTypes()).thenReturn(CibaConstants.OAUTH_CIBA_GRANT_TYPE);

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        RequestObjectValidator requestObjectValidator = PowerMockito.spy(new CIBARequestObjectValidatorImpl());
        when(oauthServerConfigurationMock.getCIBARequestObjectValidator()).thenReturn(requestObjectValidator);
        doReturn(true).when(requestObjectValidator).validateSignature(any(), any());

        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
        Map<String, RequestObjectBuilder> requestObjectBuilderMap = new HashMap<>();
        requestObjectBuilderMap.put(REQUEST_PARAM_VALUE_BUILDER, requestParamRequestObjectBuilder);
        when((oauthServerConfigurationMock.getRequestObjectBuilders())).thenReturn(requestObjectBuilderMap);

        mockServiceURLBuilder();

        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getIssuerIdentifierFromClientId(any())).thenReturn("https://localhost:9443/oauth2/token");
        when(EndpointUtil.getCibaAuthService()).thenReturn(authService);

        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getCibaAuthService()).thenReturn(authService);
        when(authService.generateAuthCodeResponse(any())).thenReturn(authCodeResponse);

        CibaAuthzHandler cibaAuthzHandler = new CibaAuthzHandler();

        WhiteboxImpl.setInternalState(oAuth2CibaEndpoint, "cibaAuthzHandler", cibaAuthzHandler);
        WhiteboxImpl.setInternalState(cibaAuthzHandler, "authzEndPoint", oAuth2AuthzEndpoint);

        when(oAuth2AuthzEndpoint.authorize(any(), any())).thenReturn(response);

        Response response = oAuth2CibaEndpoint.ciba(httpServletRequest, httpServletResponse,  new MultivaluedHashMap());
        Assert.assertEquals(200, response.getStatus());
    }

    private void mockServiceURLBuilder() throws URLBuilderException {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";
            @Override
            public ServiceURLBuilder addPath(String... strings) {

                path = "";
                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() throws URLBuilderException {

                ServiceURL serviceURL = PowerMockito.mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(builder);
    }

}
