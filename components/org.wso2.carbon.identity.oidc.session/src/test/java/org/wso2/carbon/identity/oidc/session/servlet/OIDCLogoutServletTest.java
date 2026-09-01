/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oidc.session.servlet;

import org.apache.commons.lang.StringUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigOrgUsageScopeUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheKey;
import org.wso2.carbon.identity.oidc.session.internal.OIDCSessionManagementComponentServiceHolder;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/*
  Unit test coverage for OIDCLogoutServlet class.
 */
@Listeners(MockitoTestNGListener.class)
public class OIDCLogoutServletTest extends TestOIDCSessionBase {

    @Mock
    OIDCSessionManager oidcSessionManager;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    CommonAuthenticationHandler commonAuthenticationHandler;

    @Mock
    HttpSession httpSession;

    @Mock
    IdentityConfigParser mockIdentityConfigParser;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    KeyStore keyStore;

    @Mock
    OIDCSessionDataCache mockOidcSessionDataCache;

    @Mock
    OIDCSessionDataCacheEntry opbsCacheEntry, sessionIdCacheEntry;

    private static final String CLIENT_ID_VALUE = "3T9l2uUf8AzNOfmGS9lPEIsdrR8a";
    private static final String CLIENT_ID_WITH_REGEX_CALLBACK = "cG1H52zfnkFEh3ULT0yTi14bZRUa";
    private static final String CLIENT_ID_FOR_REALM_TEST = "5GxhmSL89OVpWef4wzioRs1aDYIa";
    private static final String APP_NAME = "myApp";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String USERNAME = "user1";
    private static final String CALLBACK_URL = "http://localhost:8080/playground2/oauth2client";
    private static final String OPBROWSER_STATE = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final int TENANT_ID = -1234;
    private static final String SUPER_TENANT_DOMAIN_NAME = "carbon.super";
    private static final String INVALID_CALLBACK_URL = "http://localhost:8080/playground2/auth";
    private static final String REGEX_CALLBACK_URL = "regexp=http://localhost:8080/playground2/oauth2client";

    private OIDCLogoutServlet logoutServlet;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtil;
    private MockedStatic<IdentityConfigParser> identityConfigParser;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;
    private MockedStatic<OAuth2Util> oAuth2Util;


    @BeforeClass
    public void setupBeforeClass() throws Exception {
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);

        initiateInMemoryH2(identityDatabaseUtil);
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE", CALLBACK_URL);
        createOAuthApp(CLIENT_ID_WITH_REGEX_CALLBACK, SECRET, USERNAME, APP_NAME, "ACTIVE",
                REGEX_CALLBACK_URL);
        createOAuthApp(CLIENT_ID_FOR_REALM_TEST, SECRET, USERNAME, APP_NAME, "ACTIVE", CALLBACK_URL);
        mockKeystores();
    }

    @AfterClass
    public void tearDownAfterClass() throws Exception {

        identityDatabaseUtil.close();
        identityKeyStoreResolverMockedStatic.close();
        super.cleanData();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        logoutServlet = new OIDCLogoutServlet();

        oidcSessionManagementUtil = mockStatic(OIDCSessionManagementUtil.class);
        identityConfigParser = mockStatic(IdentityConfigParser.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);

        // When the OAuth2Util is mocked, OAuthServerConfiguration should have an instance
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        oAuth2Util = mockStatic(OAuth2Util.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        oidcSessionManagementUtil.close();
        identityConfigParser.close();
        oAuthServerConfiguration.close();
        identityTenantUtil.close();
        oAuth2Util.close();
    }

    @DataProvider(name = "provideDataForTestDoGet")
    public Object[][] provideDataForTestDoGet() {

        Cookie opbsCookie = new Cookie("opbs", OPBROWSER_STATE);

        String idTokenHint =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJr" +
                        "aWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEi" +
                        "LCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6WyIzVDlsMnVVZjhBek5PZm1HUzlsUEV" +
                        "Jc2RyUjhhIl0sImF6cCI6IjNUOWwydVVmOEF6Tk9mbUdTOWxQRUlzZHJSOGEiLCJhdXRoX3RpbWUiOjE" +
                        "1MDcwMDk0MDQsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV" +
                        "4cCI6MTUwNzAxMzAwNSwibm9uY2UiOiJDcXNVOXdabFFJWUdVQjg2IiwiaWF0IjoxNTA3MDA5NDA1fQ." +
                        "ivgnkuW-EFT7m55Mr1pyit1yALwVxrHjVqmgSley1lUhZNAlJMxefs6kjSbGStQg-mqEv0VQ7NJkZu0w" +
                        "1kYYD_76-KkjI1skP1zEqSXMhTyE8UtQ-CpR1w8bnTU7D50v-537z8vTf7PnTTA-wxpTuoYmv4ya2z0R" +
                        "v-gFTM4KPdxsc7j6yFuQcfWg5SyP9lYpJdt-s-Ow9FY1rlUVvNbtF1u2Fruc1kj9jkjSbvFgSONRhizR" +
                        "H6P_25v0LpgNZrOpiLZF92CtkCBbAGQChWACN6RWDpy5Fj2JuQMNcCvkxlvOVcx-7biH16qVnY9UFs4D" +
                        "xZo2cGzyWbXuH8sDTkzQBg";

        String invalidIdToken =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJr" +
                        "aWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEi" +
                        "LCJhbGciOiJSUzI1NiJ9.ivgnkuW-EFT7m55Mr1pyit1yALwVxrHjVqmgSley1lUhZNAlJMxefs6kjSbGStQg" +
                        "-mqEv0VQ7NJkZu0w1kYYD_76-KkjI1skP1zEqSXMhTyE8UtQ-CpR1w8bnTU7D50v-537z8vTf7PnTTA-wxpTu" +
                        "oYmv4ya2z0Rv-gFTM4KPdxsc7j6yFuQcfWg5SyP9lYpJdt-s-Ow9FY1rlUVvNbtF1u2Fruc1kj9jkjSbvFgSO" +
                        "NRhizRH6P_25v0LpgNZrOpiLZF92CtkCBbAGQChWACN6RWDpy5Fj2JuQMNcCvkxlvOVcx-7biH16qVnY9UFs4" +
                        "DxZo2cGzyWbXuH8sDTkzQBg";

        String[] redirectUrl = {
                "?oauthErrorCode=access_denied&oauthErrorMsg=opbs+cookie+not+received.+Missing+session+state.",
                "?oauthErrorCode=access_denied&oauthErrorMsg=No+valid+session+found+for+the+received+session+state.",
                "?oauthErrorCode=server_error&oauthErrorMsg=User+logout+failed",
                "?oauthErrorCode=access_denied&oauthErrorMsg=End+User+denied+the+logout+request",
                "https://localhost:8080/playground/oauth2client",
                "https://localhost:9443/authenticationendpoint/oauth2_logout_consent.do",
                "?oauthErrorCode=access_denied&oauthErrorMsg=ID+token+signature+validation+failed.",
                "?oauthErrorCode=access_denied&oauthErrorMsg=Post+logout+URI+does+not+match+with+registered+callback" +
                        "+URI.",
                "?oauthErrorCode=access_denied&oauthErrorMsg=Error+occurred+while+getting+application+information.+C" +
                        "lient+id+not+found",
                "/authenticationendpoint/retry.do"
        };

        String idTokenNotAddedToDB =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF" +
                        "4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.e" +
                        "yJzdWIiOiJhZG1pbiIsImF1ZCI6WyJ1NUZJZkc1eHpMdkJHaWFtb0FZenpjcXBCcWdhIl0sImF6cCI6InU1RklmRzV4" +
                        "ekx2QkdpYW1vQVl6emNxcEJxZ2EiLCJhdXRoX3RpbWUiOjE1MDY1NzYwODAsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGh" +
                        "vc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUwNjU3OTY4NCwibm9uY2UiOiIwZWQ4ZjFiMy1lODNmLTQ2Yz" +
                        "AtOGQ1Mi1mMGQyZTc5MjVmOTgiLCJpYXQiOjE1MDY1NzYwODQsInNpZCI6Ijg3MDZmNWRhLTU0ZmMtNGZiMC1iNGUxL" +
                        "TY5MDZmYTRiMDRjMiJ9.HopPYFs4lInXvGztNEkJKh8Kdy52eCGbzYy6PiVuM_BlCcGff3SHOoZxDH7JbIkPpKBe0cn" +
                        "YQWBxfHuGTUWhvnu629ek6v2YLkaHlb_Lm04xLD9FNxuZUNQFw83pQtDVpoX5r1V-F0DdUc7gA1RKN3xMVYgRyfslRD" +
                        "veGYplxVVNQ1LU3lrZhgaTfcMEsC6rdbd1HjdzG71EPS4674HCSAUelOisNKGa2NgORpldDQsj376QD0G9Mhc8WtWog" +
                        "uftrCCGjBy1kKT4VqFLOqlA-8wUhOj_rZT9SUIBQRDPu0RZobvsskqYo40GEZrUoabrhbwv_QpDTf6-7-nrEjT7WA";

        String idTokenWithRegexCallBack =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF" +
                        "4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.e" +
                        "yJzdWIiOiJhZG1pbiIsImF1ZCI6WyJjRzFINTJ6Zm5rRkVoM1VMVDB5VGkxNGJaUlVhIl0sImF6cCI6ImNHMUg1Mnpm" +
                        "bmtGRWgzVUxUMHlUaTE0YlpSVWEiLCJhdXRoX3RpbWUiOjE1MDg0MDcyOTYsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGh" +
                        "vc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUwODQxMDg5OCwibm9uY2UiOiJDcXNVOXdabFFJWUdVQjg2Ii" +
                        "wiaWF0IjoxNTA4NDA3Mjk4LCJzaWQiOiI3YjI1YzJjOC01YjVlLTQ0YzAtYWVjZS02MDE4ZDgyZTY4MDIifQ.DS9bTh" +
                        "wHV3Ecp_ziYw52B_zpza6sxMqLaVTvH5Qrxxbd9l2iPo56HuSzmT_ul0nzYYHcaQGbuO1LLe6kcSk7wwbbCG7vacjyB" +
                        "nJ4nT8SHGOtTOOjt1srQuNiZlgibi2LbQU0RUFaNq1_3e0PtAQyWOvqugYFbdZc-SgrJSGHet7RxMHTcQxp785hnz8J" +
                        "-lUv5jCrMAuCOJprLzL9EEvX8tHYpmZfyj3UWR8YskLnDmVDnNhqDGtbuZ0Ebn3ppKSsJwsm0ITitQ4uXfYdgEx_EH4" +
                        "gniRThFD2X9rzfP-SXW0eaYHcrRO0zgZr6CIZQNmLQdgc7p5K_AAbPiycod82tg";

        String idTokenHintWithRealm =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF" +
                        "4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.e" +
                        "yJhdF9oYXNoIjoiazBvdFlvRV84b21WTnd3ZEJCYWJsdyIsImF1ZCI6IjVHeGhtU0w4OU9WcFdlZjR3emlvUnMxYURZ" +
                        "SWEiLCJjX2hhc2giOiI2Y25ZZ25ZNFBVemNRTHNOSldsX1lBIiwic3ViIjoiYWRtaW4iLCJuYmYiOjE1NTQ0Nzc0MTM" +
                        "sImF6cCI6IjVHeGhtU0w4OU9WcFdlZjR3emlvUnMxYURZSWEiLCJhbXIiOlsiQmFzaWNBdXRoZW50aWNhdG9yIl0sIm" +
                        "lzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsInJlYWxtIjp7InVzZXJzdG9yZSI6I" +
                        "lBSSU1BUlkiLCJ0ZW5hbnQiOiJjYXJib24uc3VwZXIifSwiZXhwIjoxNTU0NDgxMDEzLCJpYXQiOjE1NTQ0Nzc0MTMs" +
                        "InNpZCI6ImJjM2IzOTRjLTRjOWQtNGRlOS1iN2MzLTI0YWIwOGNiMmQzZiJ9.KTrYVZ8QrcQFKCL7TIvSZsvLl3VEKx" +
                        "GRXiREg04ej5AEAteSNZZaC6druoymc9z9-9PQMRFknNIh5EUpdT6Z2MuiRJC5_jy2ufFQflUe6ppi5fpvxAGHDK794" +
                        "Rta2jktK1FOdj10Seg0wysMiJ0MqXv52g847wHXnOCHX-LpfFO-paT3R-M8hrcEUiIo4NqW_0tEuY5A2TwBNKnKsKRI" +
                        "NgwwgYcMyX--XZEZVzq-Op41izLehua7Yh88skbRns-v2ViNiVhocgWWc8KjzIip5zeLFuea4Uo2ncMdGw9pUybFa7t" +
                        "RquP67RTvimdKmFv9YzhkdA2RpJFw0k5Ly7BZCA";

        return new Object[][]{
                // opbs cookie is null.
                {null, true, redirectUrl[0], "cookie", "", null, false, "", false, "", null, ""},
                // opbs cookie is existing and there is no any existing sessions.
                {opbsCookie, false, redirectUrl[1], "valid", "", null, false, "", false, "", null, ""},
                // opbs cookie and a previous session are existing and userConsent="Approve".
                {opbsCookie, true, redirectUrl[2], "failed", "approve", null, false, "", false, "", null, ""},
                // opbs cookie and previous session are existing, but the userConsent!="Approve".
                {opbsCookie, true, redirectUrl[3], "denied", "no", null, false, "", false, "", null, ""},
                // opbs cookie and previous session are existing, but user consent is empty and sessionDataKey is
                // empty.
                {opbsCookie, true, redirectUrl[4], "oauth2client", " ", null, true, "", false, "", null, ""},
                // opbs cookie and previous session are existing, user consent is empty and there is a value for
                // sessionDataKey and skipUserConsent=false.
                {opbsCookie, true, redirectUrl[2], "failed", " ", "090907ce-eab0-40d2-a46d", false, "", false, "",
                        null, ""},
                // opbs cookie and previous session are existing, user consent is empty, there is a value for
                // sessionDataKey, skipUserConsent=true and an invalid idTokenHint.
                {opbsCookie, true, redirectUrl[2], "failed", " ", "090907ce-eab0-40d2-a46d", true,
                        "7893-090907ce-eab0-40d2", false, "", null, ""},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=true and an invalid idTokenHint.
                {opbsCookie, true, redirectUrl[2], "failed", " ", null, true,
                        "7893-090907ce-eab0-40d2", false, "", null, ""},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=false and a valid idTokenHint.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, false,
                        idTokenHint, false, "", null, ""},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=true and a valid idTokenHint.
                {opbsCookie, true, redirectUrl[5], "", " ", null, true,
                        idTokenHint, false, "", null, ""},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid idTokenHint, and an invalid postLogoutUri.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        idTokenHint, false, INVALID_CALLBACK_URL, null, ""},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid idTokenHint, and valid postLogoutUri.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        idTokenHint, false, CALLBACK_URL, null, ""},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid idTokenHint, isJWTSignedWithSPKey= true.
                {opbsCookie, true, redirectUrl[6], "signature", " ", null, true,
                        idTokenHint, true, "", null, ""},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=false,idTokenHint=null, isJWTSignedWithSPKey= true.
                {opbsCookie, true, redirectUrl[4], "oauth2client", " ", null, false,
                        null, true, "", null, ""},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=false,a valid idTokenHint, isJWTSignedWithSPKey=false, postLogoutUri is invalid.
                {opbsCookie, true, redirectUrl[7], "Post", " ", null, false,
                        idTokenHint, false, INVALID_CALLBACK_URL, null, ""},
                // Idtoken does not have three parts. So throws parse exception.
                {opbsCookie, true, redirectUrl[7], "Post", " ", null, false,
                        invalidIdToken, false, INVALID_CALLBACK_URL, null, ""},
                // Thorws IdentityOAuth2Exception since the id token is not added to DB
                {opbsCookie, true, redirectUrl[8], "application", " ", null, false,
                        idTokenNotAddedToDB, false, INVALID_CALLBACK_URL, null, ""},
                // AuthenticatorFlowStatus = SUCCESS_COMPLETED
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        idTokenHint, false, CALLBACK_URL, AuthenticatorFlowStatus.SUCCESS_COMPLETED, ""},
                // AuthenticatorFlowStatus = INCOMPLETE
                {opbsCookie, true, redirectUrl[9], "retry", " ", null, true,
                        idTokenHint, false, CALLBACK_URL, AuthenticatorFlowStatus.INCOMPLETE, ""},
                // CallBackUrl is a regex one.
                {opbsCookie, true, CALLBACK_URL, "oauth2client", "", null, true, idTokenWithRegexCallBack, false,
                        REGEX_CALLBACK_URL, null, ""},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid idTokenHint with tenant domain in realm, and valid postLogoutUri.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        idTokenHintWithRealm, false, CALLBACK_URL, null, ""},
                // opbs cookie and previous session are existing, user consent is empty, there is a value for
                // sessionDataKey, skipUserConsent=true and an invalid clientId.
                {opbsCookie, true, redirectUrl[2], "failed", " ", "090907ce-eab0-40d2-a46d", true,
                        "", false, "", null, "invalid_client_id"},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=true and an invalid clientId.
                {opbsCookie, true, redirectUrl[2], "failed", " ", null, true,
                        "invalid_client_id", false, "", null, ""},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=false and a valid clientId.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, false,
                        "", false, "", null, CLIENT_ID_VALUE},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=true and a valid clientId.
                {opbsCookie, true, redirectUrl[5], "", " ", null, true,
                        "", false, "", null, CLIENT_ID_VALUE},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid clientId, and an invalid postLogoutUri.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        "", false, INVALID_CALLBACK_URL, null, CLIENT_ID_VALUE},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid clientId, and valid postLogoutUri.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        "", false, CALLBACK_URL, null, CLIENT_ID_VALUE},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=true, a valid clientId, isJWTSignedWithSPKey= true.
                {opbsCookie, true, redirectUrl[6], "signature", " ", null, true,
                        "", true, "", null, CLIENT_ID_VALUE},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=false,clientId=null, isJWTSignedWithSPKey= true.
                {opbsCookie, true, redirectUrl[4], "oauth2client", " ", null, false,
                        "", true, "", null, null},
                // opbs cookie and previous sessions are existing, userConsent is empty, sessionDataKey = null,
                // skipUserConsent=false,a valid clientId, isJWTSignedWithSPKey=false, postLogoutUri is invalid.
                {opbsCookie, true, redirectUrl[7], "Post", " ", null, false,
                        "", false, INVALID_CALLBACK_URL, null, CLIENT_ID_VALUE},
                // AuthenticatorFlowStatus = SUCCESS_COMPLETED
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        "", false, CALLBACK_URL, AuthenticatorFlowStatus.SUCCESS_COMPLETED, CLIENT_ID_VALUE},
                // AuthenticatorFlowStatus = INCOMPLETE
                {opbsCookie, true, redirectUrl[9], "retry", " ", null, true,
                        "", false, CALLBACK_URL, AuthenticatorFlowStatus.INCOMPLETE, CLIENT_ID_VALUE},

        };
    }

    @Test(dataProvider = "provideDataForTestDoGet")
    public void testDoGet(Object cookie, boolean sessionExists, String redirectUrl, String expected, String consent,
                          String sessionDataKey, boolean skipUserConsent, String idTokenHint,
                          boolean isJWTSignedWithSPKey, String postLogoutUrl, Object flowStatus,
                          String clientId) throws Exception {

        try (MockedStatic<OIDCSessionDataCache> oidcSessionDataCache = mockStatic(OIDCSessionDataCache.class);
             MockedStatic<OIDCSessionManagementComponentServiceHolder>
                     oidcSessionManagementComponentServiceHolder =
                     mockStatic(OIDCSessionManagementComponentServiceHolder.class);
             MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);) {

            TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            oidcSessionManagementUtil.when(
                    OIDCSessionManagementUtil::handleAlreadyLoggedOutSessionsGracefully).thenReturn(false);
            oidcSessionManagementUtil.when(() -> OIDCSessionManagementUtil.getOPBrowserStateCookie(request))
                    .thenReturn((Cookie) cookie);
            oidcSessionManagementUtil.when(() -> OIDCSessionManagementUtil.getErrorPageURL(anyString(), anyString()))
                    .thenReturn(redirectUrl);

            oidcSessionManagementUtil.when(OIDCSessionManagementUtil::getSessionManager).thenReturn(oidcSessionManager);
            lenient().when(
                    oidcSessionManager.sessionExists(OPBROWSER_STATE, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                    .thenReturn(sessionExists);

            lenient().when(request.getParameter("consent")).thenReturn(consent);
            lenient().when(request.getHeaderNames())
                    .thenReturn(Collections.enumeration(Arrays.asList(new String[]{"cookie"})));
            lenient().when(request.getHeader("COOKIE")).thenReturn("opbs");
            when(request.getHeader("referer")).thenReturn(null);
            lenient().when(request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS)).thenReturn(flowStatus);
            lenient().when(request.getAttribute("sp")).thenReturn(null);

            lenient().doThrow(new ServletException()).when(commonAuthenticationHandler).doPost(request, response);

            lenient().when(request.getSession()).thenReturn(httpSession);
            lenient().when(httpSession.getMaxInactiveInterval()).thenReturn(2);

            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(mockIdentityConfigParser);

            lenient().when(request.getParameter("sessionDataKey")).thenReturn(sessionDataKey);

            lenient().when(mockOAuthServerConfiguration.getOpenIDConnectSkipLogoutConsentConfig())
                    .thenReturn(skipUserConsent);

            lenient().when(request.getParameter("id_token_hint")).thenReturn(idTokenHint);
            lenient().when(request.getParameter("client_id")).thenReturn(clientId);

            oidcSessionManagementUtil.when(() -> OIDCSessionManagementUtil
                            .removeOPBrowserStateCookie(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                    .thenReturn((Cookie) cookie);

            oidcSessionManagementUtil.when(OIDCSessionManagementUtil::getOIDCLogoutConsentURL).thenReturn(redirectUrl);
            oidcSessionManagementUtil.when(OIDCSessionManagementUtil::getOIDCLogoutURL).thenReturn(redirectUrl);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(TENANT_ID);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                    .thenReturn(SUPER_TENANT_DOMAIN_NAME);

            lenient().when(mockOAuthServerConfiguration.isJWTSignedWithSPKey()).thenReturn(isJWTSignedWithSPKey);

            oidcSessionManagementComponentServiceHolder.when(
                            OIDCSessionManagementComponentServiceHolder::getApplicationMgtService)
                    .thenReturn(mockedApplicationManagementService);
            lenient().when(mockedApplicationManagementService.getServiceProviderNameByClientId(
                    anyString(), anyString(), anyString())).thenReturn("SP1");

            lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(mockOAuthServerConfiguration.getClientSecretPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString()))
                    .thenAnswer(invocation -> invocation.getArguments()[0]);
            lenient().when(request.getParameter("post_logout_redirect_uri")).thenReturn(postLogoutUrl);

            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenCallRealMethod();
            oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(anyString())).thenReturn("wso2.com");
            oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(any(oAuthAppDO.getClass())))
                    .thenReturn("wso2.com");

            mockServiceURLBuilder(OIDCSessionConstants.OIDCEndpoints.OIDC_LOGOUT_ENDPOINT, serviceURLBuilder);

            ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

            oidcSessionDataCache.when(OIDCSessionDataCache::getInstance).thenReturn(mockOidcSessionDataCache);
            OIDCSessionDataCacheKey opbsKey = mock(OIDCSessionDataCacheKey.class);
            OIDCSessionDataCacheKey sessionIdKey = mock(OIDCSessionDataCacheKey.class);
            lenient().when(opbsKey.getSessionDataId()).thenReturn(OPBROWSER_STATE);
            lenient().when(sessionIdKey.getSessionDataId()).thenReturn(sessionDataKey);
            lenient().when(mockOidcSessionDataCache.getValueFromCache(opbsKey)).thenReturn(opbsCacheEntry);
            lenient().when(mockOidcSessionDataCache.getValueFromCache(sessionIdKey)).thenReturn(sessionIdCacheEntry);
            ConcurrentMap<String, String> paramMap = new ConcurrentHashMap<>();
            paramMap.put(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM, CLIENT_ID_VALUE);
            paramMap.put(OIDCSessionConstants.OIDC_CACHE_TENANT_DOMAIN_PARAM, SUPER_TENANT_DOMAIN_NAME);
            lenient().when(opbsCacheEntry.getParamMap()).thenReturn(paramMap);
            lenient().when(sessionIdCacheEntry.getParamMap()).thenReturn(paramMap);

            logoutServlet.doGet(request, response);
            verify(response).sendRedirect(captor.capture());
            assertTrue(captor.getValue().contains(expected));
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @DataProvider(name = "provideDataForTestHandleMissingSessionStateGracefully")
    public Object[][] provideDataForTestHandleMissingSessionStateGracefully() {

        Cookie opbsCookie = new Cookie("opbs", OPBROWSER_STATE);

        String idTokenHint =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF" +
                        "4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.e" +
                        "yJzdWIiOiJhZG1pbiIsImF1ZCI6WyIzVDlsMnVVZjhBek5PZm1HUzlsUEVJc2RyUjhhIl0sImF6cCI6IjNUOWwydVVm" +
                        "OEF6Tk9mbUdTOWxQRUlzZHJSOGEiLCJhdXRoX3RpbWUiOjE1MDcwMDk0MDQsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGh" +
                        "vc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUwNzAxMzAwNSwibm9uY2UiOiJDcXNVOXdabFFJWUdVQjg2Ii" +
                        "wiaWF0IjoxNTA3MDA5NDA1fQ.ivgnkuW-EFT7m55Mr1pyit1yALwVxrHjVqmgSley1lUhZNAlJMxefs6kjSbGStQg-m" +
                        "qEv0VQ7NJkZu0w1kYYD_76-KkjI1skP1zEqSXMhTyE8UtQ-CpR1w8bnTU7D50v-537z8vTf7PnTTA-wxpTuoYmv4ya2" +
                        "z0Rv-gFTM4KPdxsc7j6yFuQcfWg5SyP9lYpJdt-s-Ow9FY1rlUVvNbtF1u2Fruc1kj9jkjSbvFgSONRhizRH6P_25v0" +
                        "LpgNZrOpiLZF92CtkCBbAGQChWACN6RWDpy5Fj2JuQMNcCvkxlvOVcx-7biH16qVnY9UFs4DxZo2cGzyWbXuH8sDTkz" +
                        "QBg";

        String idTokenHintWithRealm =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF" +
                        "4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.e" +
                        "yJhdF9oYXNoIjoiazBvdFlvRV84b21WTnd3ZEJCYWJsdyIsImF1ZCI6IjVHeGhtU0w4OU9WcFdlZjR3emlvUnMxYURZ" +
                        "SWEiLCJjX2hhc2giOiI2Y25ZZ25ZNFBVemNRTHNOSldsX1lBIiwic3ViIjoiYWRtaW4iLCJuYmYiOjE1NTQ0Nzc0MTM" +
                        "sImF6cCI6IjVHeGhtU0w4OU9WcFdlZjR3emlvUnMxYURZSWEiLCJhbXIiOlsiQmFzaWNBdXRoZW50aWNhdG9yIl0sIm" +
                        "lzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsInJlYWxtIjp7InVzZXJzdG9yZSI6I" +
                        "lBSSU1BUlkiLCJ0ZW5hbnQiOiJjYXJib24uc3VwZXIifSwiZXhwIjoxNTU0NDgxMDEzLCJpYXQiOjE1NTQ0Nzc0MTMs" +
                        "InNpZCI6ImJjM2IzOTRjLTRjOWQtNGRlOS1iN2MzLTI0YWIwOGNiMmQzZiJ9.KTrYVZ8QrcQFKCL7TIvSZsvLl3VEKx" +
                        "GRXiREg04ej5AEAteSNZZaC6druoymc9z9-9PQMRFknNIh5EUpdT6Z2MuiRJC5_jy2ufFQflUe6ppi5fpvxAGHDK794" +
                        "Rta2jktK1FOdj10Seg0wysMiJ0MqXv52g847wHXnOCHX-LpfFO-paT3R-M8hrcEUiIo4NqW_0tEuY5A2TwBNKnKsKRI" +
                        "NgwwgYcMyX--XZEZVzq-Op41izLehua7Yh88skbRns-v2ViNiVhocgWWc8KjzIip5zeLFuea4Uo2ncMdGw9pUybFa7t" +
                        "RquP67RTvimdKmFv9YzhkdA2RpJFw0k5Ly7BZCA";

        String[] postLogoutUrl = {
                "http://localhost:8080/playground2/oauth2client",
                "http://localhost:8080/playground/oauth2client"
        };

        return new Object[][]{
                // No id_token_hint or client_id
                {null, null, null, false, false, "oauth2_logout.do", null},
                // No post_logout_redirect_uri.
                {null, idTokenHint, null, false, false, "oauth2_logout.do", null},
                // Valid id_token_hint and valid post_logout_redirect_uri.
                {null, idTokenHint, postLogoutUrl[0], false, false, "playground2/oauth2client", null},
                // Invalid id_token_hint.
                {null, idTokenHint, postLogoutUrl[0], true, false, "?oauthErrorCode=access_denied", null},
                // Invalid post_logout_redirect_uri.
                {null, idTokenHint, postLogoutUrl[1], false, false, "?oauthErrorCode=access_denied", null},
                // Invalid session state.
                {opbsCookie, null, null, false, false, "oauth2_logout.do", null},
                // Valid id_token_hint with tenant domain in realm and a valid post_logout_redirect_uri.
                {null, idTokenHintWithRealm, postLogoutUrl[0], false, false, "playground2/oauth2client", null},
                // Valid client_id and valid post_logout_redirect_uri.
                {null, null, postLogoutUrl[0], false, false, "playground2/oauth2client", CLIENT_ID_VALUE},
                // Invalid client_id.
                {null, null, postLogoutUrl[0], true, false, "?oauthErrorCode=access_denied", "invalid_client_id"},

        };
    }

    @Test(dataProvider = "provideDataForTestHandleMissingSessionStateGracefully")
    public void testHandleMissingSessionStateGracefully(
            Object cookie, String idTokenHint, String postLogoutUrl, boolean isJWTSignedWithSPKey,
            boolean sessionExists, String expected, String clientId) throws Exception {

        String errorPageURL = "?oauthErrorCode=access_denied&oauthErrorMsg=any.";
        String oidcLogoutURL = "https://localhost:9443/authenticationendpoint/oauth2_logout.do";

        try {
            TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            oidcSessionManagementUtil.when(() -> OIDCSessionManagementUtil.getOPBrowserStateCookie(request))
                    .thenReturn((Cookie) cookie);
            oidcSessionManagementUtil.when(
                    OIDCSessionManagementUtil::handleAlreadyLoggedOutSessionsGracefully).thenReturn(true);
            oidcSessionManagementUtil.when(() -> OIDCSessionManagementUtil.getErrorPageURL(anyString(), anyString()))
                    .thenReturn(errorPageURL);
            oidcSessionManagementUtil.when(OIDCSessionManagementUtil::getOIDCLogoutURL).thenReturn(oidcLogoutURL);
            oidcSessionManagementUtil.when(OIDCSessionManagementUtil::getSessionManager).thenReturn(oidcSessionManager);

            lenient().when(mockOAuthServerConfiguration.isJWTSignedWithSPKey()).thenReturn(isJWTSignedWithSPKey);
            lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(mockOAuthServerConfiguration.getClientSecretPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                    invocation -> invocation.getArguments()[0]);

            oAuth2Util.when(OAuth2Util::getLoginTenant).thenReturn("wso2.com");

            OAuthAppDO oAuthAppDOWithCallback = new OAuthAppDO();
            oAuthAppDOWithCallback.setCallbackUrl(CALLBACK_URL);
            if (StringUtils.equals(clientId, "invalid_client_id")) {
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenCallRealMethod();
            } else {
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(oAuthAppDOWithCallback);
            }
            oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(any(oAuthAppDO.getClass())))
                    .thenReturn("wso2.com");

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(TENANT_ID);
            identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(TENANT_ID);

            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(mockIdentityConfigParser);

            when(request.getParameter("id_token_hint")).thenReturn(idTokenHint);
            when(request.getParameter("client_id")).thenReturn(clientId);
            when(request.getParameter("post_logout_redirect_uri")).thenReturn(postLogoutUrl);
            lenient().when(request.getParameter("sessionDataKey")).thenReturn(null);

            ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
            logoutServlet.doGet(request, response);
            verify(response).sendRedirect(captor.capture());
            assertTrue(captor.getValue().contains(expected));
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @DataProvider(name = "provideDataForStateParamTest")
    public Object[][] provideDataForStateParamTest() {

        String postLogoutUrlWithQueryParam = "http://localhost:8080/playground2/oauth2client?x=y";
        String postLogoutUrlWithoutQueryParam = "http://localhost:8080/playground2/oauth2client";
        String stateParam = "n6556";

        return new Object[][]{
                {postLogoutUrlWithQueryParam, stateParam,
                        "http://localhost:8080/playground2/oauth2client?x=y&state=n6556"},
                {postLogoutUrlWithQueryParam, "", "http://localhost:8080/playground2/oauth2client?x=y"},
                {postLogoutUrlWithoutQueryParam, stateParam, "http://localhost:8080/playground2/oauth2client?state" +
                        "=n6556"},
                {postLogoutUrlWithoutQueryParam, "", "http://localhost:8080/playground2/oauth2client"},
        };
    }

    @Test(dataProvider = "provideDataForStateParamTest")
    public void testStateParam(String postLogoutUrl, String stateParam, String outputRedirectUrl) throws Exception {

        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        Object expected = invokePrivateMethod(logoutServlet, "appendStateQueryParam",
                postLogoutUrl, stateParam);
        assertEquals(expected, outputRedirectUrl);
    }


    private static final String SUB_ORG_TENANT = "sub-org-tenant";
    private static final String SUB_ORG_ID = "9476b110-131d-4c74-89b6-b2a8f1a877d0";
    private static final String ROOT_ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String ROOT_ISSUER = "https://localhost:9443/oauth2/token";
    private static final String SUB_ORG_ISSUER =
            "https://localhost:9443/t/carbon.super/o/9476b110-131d-4c74-89b6-b2a8f1a877d0/oauth2/token";
    private static final String ORG_QUALIFIED_ISSUER =
            "https://localhost:9443/o/9476b110-131d-4c74-89b6-b2a8f1a877d0/oauth2/token";
    private static final String TENANT_QUALIFIED_ISSUER =
            "https://localhost:9443/t/sub-org-tenant/oauth2/token";
    private static final String ROOT_TENANT_QUALIFIED_ISSUER =
            "https://localhost:9443/t/carbon.super/oauth2/token";

    /**
     * Build an unsigned id token carrying the given issuer and azp. Only the claims are read by the
     * tenant resolution, so the signature is irrelevant here.
     */
    private String idTokenWithIssuer(String issuer) {

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8));
        String claims = issuer == null
                ? "{\"azp\":\"" + CLIENT_ID_VALUE + "\",\"aud\":[\"" + CLIENT_ID_VALUE + "\"]}"
                : "{\"azp\":\"" + CLIENT_ID_VALUE + "\",\"aud\":[\"" + CLIENT_ID_VALUE
                        + "\"],\"iss\":\"" + issuer + "\"}";
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(claims.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".c2ln";
    }

    /**
     * Wire an application owned by the sub organization whose configured token issuer is the given
     * tenant, and make the issuer of each tenant resolvable. The application is resolvable both by
     * client id alone and within its own tenant, which are the two lookups the servlet uses.
     */
    private void mockApplicationWithIssuer(MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils,
                                           String issuerTenantDomain) throws Exception {

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        if (issuerTenantDomain != null) {
            IssuerDetails issuerDetails = new IssuerDetails();
            issuerDetails.setIssuerTenantDomain(issuerTenantDomain);
            oAuthAppDO.setIssuerDetails(issuerDetails);
        }
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_VALUE)).thenReturn(oAuthAppDO);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_VALUE, SUB_ORG_TENANT))
                .thenReturn(oAuthAppDO);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(SUB_ORG_TENANT);
        lenient().when(mockOAuthServerConfiguration.isJWTSignedWithSPKey()).thenReturn(true);
        issuerUtils.when(() -> OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(SUB_ORG_TENANT))
                .thenReturn(SUB_ORG_ISSUER);
        issuerUtils.when(() -> OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(ROOT_ISSUER);
    }

    /**
     * Wire the organization manager used while resolving the signing tenant, and put the request in the
     * tenant qualified organization context, which is where the issuer of the token is consulted. Without
     * an accessing organization the request is served in the tenant that owns the application and the
     * issuer is not consulted at all, which is covered separately.
     */
    private OrganizationManager mockAccessingOrganization() throws Exception {

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        lenient().when(organizationManager.resolveTenantDomain(SUB_ORG_ID)).thenReturn(SUB_ORG_TENANT);
        /*
         The application's own organization and the root of its hierarchy, used when the application has
         no token issuer configured, which is the state of an application migrated from before the
         setting existed.
        */
        lenient().when(organizationManager.resolveOrganizationId(SUB_ORG_TENANT)).thenReturn(SUB_ORG_ID);
        lenient().when(organizationManager.getPrimaryOrganizationId(SUB_ORG_ID)).thenReturn(ROOT_ORG_ID);
        lenient().when(organizationManager.resolveTenantDomain(ROOT_ORG_ID))
                .thenReturn(SUPER_TENANT_DOMAIN_NAME);
        OIDCSessionManagementComponentServiceHolder.getInstance().setOrganizationManager(organizationManager);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setApplicationResidentOrganizationId(SUB_ORG_ID);
        return organizationManager;
    }

    private void clearAccessingOrganization() {

        PrivilegedCarbonContext.endTenantFlow();
        OIDCSessionManagementComponentServiceHolder.getInstance().setOrganizationManager(null);
    }

    @DataProvider(name = "signingTenantResolutionDataProvider")
    public Object[][] signingTenantResolutionDataProvider() {

        return new Object[][]{
                // issuer claim, application token issuer tenant, expected tenant used for validation.
                // The application owner tenant issued the token.
                {SUB_ORG_ISSUER, SUB_ORG_TENANT, SUB_ORG_TENANT},
                // The application is configured to issue from the root organization, so the root key signed it.
                {ROOT_ISSUER, SUPER_TENANT_DOMAIN_NAME, SUPER_TENANT_DOMAIN_NAME},
                // The root issuer must not be selected when the application issues from the sub organization.
                {ROOT_ISSUER, SUB_ORG_TENANT, null},
                // An issuer naming an unrelated organization is not accepted.
                {"https://localhost:9443/o/11111111-2222-3333-4444-555555555555/oauth2/token", SUB_ORG_TENANT, null},
                // A foreign origin must not select a key even when the organization segment is correct.
                {"https://evil.example.com/o/" + SUB_ORG_ID + "/oauth2/token", SUB_ORG_TENANT, null},
                // A scheme downgrade must not select a key.
                {"http://localhost:9443/o/" + SUB_ORG_ID + "/oauth2/token", SUB_ORG_TENANT, null},
                // A different port must not select a key.
                {"https://localhost:9999/o/" + SUB_ORG_ID + "/oauth2/token", SUB_ORG_TENANT, null},
                // The organization qualified issuer resolves to the owning organization's tenant.
                {ORG_QUALIFIED_ISSUER, SUB_ORG_TENANT, SUB_ORG_TENANT},
                // An unrecognised issuer is rejected.
                {"https://localhost:9443/some/other/path", SUB_ORG_TENANT, null},
                // A token with no issuer claim is rejected.
                {null, SUB_ORG_TENANT, null},
                /*
                 The tenant qualified issuer form, /t/<tenant-domain>/oauth2/token, which is produced when
                 the relying party obtains the token through the tenant's own endpoints. The organization
                 qualified form of the same tenant is a different string, so both must be recognised.
                */
                {TENANT_QUALIFIED_ISSUER, SUB_ORG_TENANT, SUB_ORG_TENANT},
                // The application owner tenant is accepted regardless of the configured token issuer.
                {TENANT_QUALIFIED_ISSUER, SUPER_TENANT_DOMAIN_NAME, SUB_ORG_TENANT},
                // The configured token issuer tenant is accepted in the tenant qualified form.
                {ROOT_TENANT_QUALIFIED_ISSUER, SUPER_TENANT_DOMAIN_NAME, SUPER_TENANT_DOMAIN_NAME},
                // The root tenant must not be selected when the application issues from the sub organization.
                {ROOT_TENANT_QUALIFIED_ISSUER, SUB_ORG_TENANT, null},
                // A tenant qualified issuer naming an unrelated tenant is not accepted.
                {"https://localhost:9443/t/unrelated-tenant/oauth2/token", SUB_ORG_TENANT, null},
                // A foreign origin must not select a key even when the tenant segment is correct.
                {"https://evil.example.com/t/sub-org-tenant/oauth2/token", SUB_ORG_TENANT, null},
                // A scheme downgrade must not select a key.
                {"http://localhost:9443/t/sub-org-tenant/oauth2/token", SUB_ORG_TENANT, null},
                // A different port must not select a key.
                {"https://localhost:9999/t/sub-org-tenant/oauth2/token", SUB_ORG_TENANT, null},
                /*
                 An application with no token issuer configured, the state of one migrated from before the
                 setting existed. Issuance falls back to the tenant serving the request, so the root
                 organization of the application's own organization is a legitimate issuer for it.
                */
                {ROOT_ISSUER, null, SUPER_TENANT_DOMAIN_NAME},
                // The application's own tenant still selects its own key when it has no issuer configured.
                {SUB_ORG_ISSUER, null, SUB_ORG_TENANT},
                // An unrelated issuer is still refused when the application has no issuer configured.
                {"https://localhost:9443/t/another-tenant/oauth2/token", null, null},
                // A foreign origin is still refused when the application has no issuer configured.
                {"https://evil.example.com/o/" + SUB_ORG_ID + "/oauth2/token", null, null},
        };
    }

    @Test(dataProvider = "signingTenantResolutionDataProvider")
    public void testResolveSigningTenantDomain(String issuerClaim, String appIssuerTenant, String expectedTenant)
            throws Exception {

        try (MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils =
                     mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class)) {
            mockApplicationWithIssuer(issuerUtils, appIssuerTenant);
            mockAccessingOrganization();
            try {
                Object resolved = invokePrivateMethod(logoutServlet, "resolveSigningTenantDomain",
                        idTokenWithIssuer(issuerClaim));
                assertEquals(resolved, expectedTenant);
            } finally {
                clearAccessingOrganization();
            }
        }
    }

    @DataProvider(name = "ownTenantRequestDataProvider")
    public Object[][] ownTenantRequestDataProvider() {

        /*
         Issuer claims and the tenant each must resolve to when there is no accessing organization. The
         request is then served in the tenant that owns the application, so any issuer resolves to that
         tenant. A token carrying no issuer claim at all is still rejected, by the check that runs before
         the application is looked up.
        */
        return new Object[][]{
                {SUB_ORG_ISSUER, SUB_ORG_TENANT},
                {ORG_QUALIFIED_ISSUER, SUB_ORG_TENANT},
                {TENANT_QUALIFIED_ISSUER, SUB_ORG_TENANT},
                {ROOT_ISSUER, SUB_ORG_TENANT},
                {"https://evil.example.com/t/sub-org-tenant/oauth2/token", SUB_ORG_TENANT},
                {null, null},
        };
    }

    @Test(dataProvider = "ownTenantRequestDataProvider")
    public void testResolveSigningTenantDomainWithoutAccessingOrganization(String issuerClaim,
                                                                            String expectedTenant)
            throws Exception {

        /*
         Without an accessing organization the request is already served in the tenant that owns the
         application, so the token was issued in that same tenant and its key is the application owner
         tenant key. The issuer claim is not consulted on this path.
        */
        try (MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils =
                     mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class)) {
            mockApplicationWithIssuer(issuerUtils, SUB_ORG_TENANT);
            Object resolved = invokePrivateMethod(logoutServlet, "resolveSigningTenantDomain",
                    idTokenWithIssuer(issuerClaim));
            assertEquals(resolved, expectedTenant);
        }
    }

    @Test
    public void testResolveSigningTenantDomainWithOrganizationQualifiedIssuer() throws Exception {

        // The organization qualified issuer resolves to the tenant of the organization that owns the
        // application, which is how a token obtained through /o/<org-id>/oauth2/token is validated.
        try (MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils =
                     mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class)) {
            mockApplicationWithIssuer(issuerUtils, SUB_ORG_TENANT);
            mockAccessingOrganization();
            try {
                Object resolved = invokePrivateMethod(logoutServlet, "resolveSigningTenantDomain",
                        idTokenWithIssuer(ORG_QUALIFIED_ISSUER));
                assertEquals(resolved, SUB_ORG_TENANT);
            } finally {
                clearAccessingOrganization();
            }
        }
    }

    @Test
    public void testResolveSigningTenantDomainWithTenantQualifiedIssuer() throws Exception {

        // A token obtained through /t/<tenant-domain>/oauth2/token carries an issuer that names the tenant
        // directly. It is signed by the same key as the organization qualified form of that tenant, so it
        // must resolve to the same tenant.
        try (MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils =
                     mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class)) {
            mockApplicationWithIssuer(issuerUtils, SUPER_TENANT_DOMAIN_NAME);
            mockAccessingOrganization();
            try {
                Object resolved = invokePrivateMethod(logoutServlet, "resolveSigningTenantDomain",
                        idTokenWithIssuer(TENANT_QUALIFIED_ISSUER));
                assertEquals(resolved, SUB_ORG_TENANT);
            } finally {
                clearAccessingOrganization();
            }
        }
    }

    @Test
    public void testResolveSigningTenantDomainRejectsUnrelatedTenantInIssuer() throws Exception {

        // The tenant named in a tenant qualified issuer must be one of the two tenants that may issue for
        // the application. An issuer naming any other tenant must not select a key.
        try (MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils =
                     mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class)) {
            mockApplicationWithIssuer(issuerUtils, SUB_ORG_TENANT);
            mockAccessingOrganization();
            try {
                Object resolved = invokePrivateMethod(logoutServlet, "resolveSigningTenantDomain",
                        idTokenWithIssuer("https://localhost:9443/t/another-tenant/oauth2/token"));
                assertEquals(resolved, null);
            } finally {
                clearAccessingOrganization();
            }
        }
    }

    @Test
    public void testResolveSigningTenantDomainDeniesWhenIssuerResolutionFails() throws Exception {

        // Issuer resolution reaches services that may be unavailable and fail with unchecked exceptions.
        // The request must be denied rather than failing with a server error.
        try (MockedStatic<OAuth2OIDCConfigOrgUsageScopeUtils> issuerUtils =
                     mockStatic(OAuth2OIDCConfigOrgUsageScopeUtils.class)) {
            mockApplicationWithIssuer(issuerUtils, SUB_ORG_TENANT);
            mockAccessingOrganization();
            try {
                issuerUtils.when(() -> OAuth2OIDCConfigOrgUsageScopeUtils.getIssuerLocation(SUB_ORG_TENANT))
                        .thenThrow(new NullPointerException("organization manager is not available"));
                Object resolved = invokePrivateMethod(logoutServlet, "resolveSigningTenantDomain",
                        idTokenWithIssuer(SUB_ORG_ISSUER));
                assertEquals(resolved, null);
            } finally {
                clearAccessingOrganization();
            }
        }
    }

    private void mockServiceURLBuilder(String context, MockedStatic<ServiceURLBuilder> serviceURLBuilder)
            throws URLBuilderException {

        ServiceURLBuilder mockServiceURLBuilder = mock(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
        lenient().when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);

        ServiceURL serviceURL = mock(ServiceURL.class);
        lenient().when(serviceURL.getRelativeInternalURL()).thenReturn(context);
        lenient().when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
    }

    private Object invokePrivateMethod(Object object, String methodName, Object... params) throws Exception {

        Class<?>[] paramTypes = new Class[params.length];
        for (int i = 0; i < params.length; i++) {
            paramTypes[i] = params[i].getClass();
        }
        Method method = object.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(object, params);
    }

    private void mockKeystores() throws IdentityKeyStoreResolverException, KeyStoreException {

        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                TestUtil.loadKeyStoreFromFileSystem(TestUtil.getFilePath("wso2carbon.jks"), "wso2carbon", "JKS")
                        .getCertificate("wso2carbon"));
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                TestUtil.loadKeyStoreFromFileSystem(TestUtil.getFilePath("wso2carbon.jks"), "wso2carbon", "JKS"));

        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }
}
