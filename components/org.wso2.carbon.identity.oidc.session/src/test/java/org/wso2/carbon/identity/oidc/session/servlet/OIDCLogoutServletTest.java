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
package org.wso2.carbon.identity.oidc.session.servlet;

import edu.emory.mathcs.backport.java.util.Arrays;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.core.internal.CarbonCoreDataHolder;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Collections;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import static org.testng.Assert.assertTrue;

@PrepareForTest({OIDCSessionManagementUtil.class, OIDCSessionManager.class, FrameworkUtils.class,
        IdentityConfigParser.class, OAuthServerConfiguration.class, IdentityTenantUtil.class, KeyStoreManager.class,
        CarbonCoreDataHolder.class, IdentityDatabaseUtil.class})
/**
 * Unit test coverage for OIDCLogoutServlet class
 */
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
    IdentityConfigParser identityConfigParser;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    KeyStoreManager keyStoreManager;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    private static final String CLIENT_ID_VALUE = "3T9l2uUf8AzNOfmGS9lPEIsdrR8a";
    private static final String APP_NAME = "myApp";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String USERNAME = "user1";
    private static final String OPBROWSER_STATE = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final int TENANT_ID = -1234;

    private OIDCLogoutServlet logoutServlet;

    @BeforeTest
    public void setUp() throws Exception {
        logoutServlet = new OIDCLogoutServlet();

        initiateInMemoryH2();
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");

    }

    @DataProvider(name = "provideDataForTestDoGet")
    public Object[][] provideDataForTestDoGet() {
        Cookie opbsCookie = new Cookie("opbs", OPBROWSER_STATE);

        String idTokenHint =
                "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJr" +
                        "aWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1" +
                        "NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6WyIzVDlsMnVVZjhBek5PZm1HUzlsUEVJc2RyUjhhIl0sImF6cCI6IjNUOWwydVVmO" +
                        "EF6Tk9mbUdTOWxQRUlzZHJSOGEiLCJhdXRoX3RpbWUiOjE1MDcwMDk0MDQsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M" +
                        "1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUwNzAxMzAwNSwibm9uY2UiOiJDcXNVOXdabFFJWUdVQjg2IiwiaWF0IjoxNTA3MDA5ND" +
                        "A1fQ.ivgnkuW-EFT7m55Mr1pyit1yALwVxrHjVqmgSley1lUhZNAlJMxefs6kjSbGStQg-mqEv0VQ7NJkZu0w1kYYD_76-KkjI1sk" +
                        "P1zEqSXMhTyE8UtQ-CpR1w8bnTU7D50v-537z8vTf7PnTTA-wxpTuoYmv4ya2z0Rv-gFTM4KPdxsc7j6yFuQcfWg5SyP9lYpJdt-s-O" +
                        "w9FY1rlUVvNbtF1u2Fruc1kj9jkjSbvFgSONRhizRH6P_25v0LpgNZrOpiLZF92CtkCBbAGQChWACN6RWDpy5Fj2JuQMNcCvkxlv" +
                        "OVcx-7biH16qVnY9UFs4DxZo2cGzyWbXuH8sDTkzQBg";

        String[] redirectUrl = {
                "?oauthErrorCode=access_denied&oauthErrorMsg=opbs+cookie+not+received.+Missing+session+state.",
                "?oauthErrorCode=access_denied&oauthErrorMsg=No+valid+session+found+for+the+received+session+state.",
                "?oauthErrorCode=server_error&oauthErrorMsg=User+logout+failed",
                "?oauthErrorCode=access_denied&oauthErrorMsg=End+User+denied+the+logout+request",
                "https://localhost:8080/playground/oauth2client",
                "https://localhost:9443/authenticationendpoint/oauth2_logout_consent.do"
        };

        return new Object[][]{
                // opbs cookie is null.
                {null, true, redirectUrl[0], "cookie", "", null, false, "", false},
                // opbs cookie is existing and there is no any existing sessions.
                {opbsCookie, false, redirectUrl[1], "valid", "", null, false, "", false},
                // opbs cookie and a previous session are existing and userConsent="Approve".
                {opbsCookie, true, redirectUrl[2], "failed", "approve", null, false, "", false},
                // opbs cookie and previous session are existing, but the userConsent!="Approve".
                {opbsCookie, true, redirectUrl[3], "denied", "no", null, false, "", false},
                // opbs cookie and previous session are existing, but user consent is empty and sessionDataKey is
                // empty.
                {opbsCookie, true, redirectUrl[4], "oauth2client", " ", null, true, "", false},
                // opbs cookie and previous session are existing, user consent is empty and there is a value for
                // sessionDataKey and skipUserConsent=false.
                {opbsCookie, true, redirectUrl[2], "failed", " ", "090907ce-eab0-40d2-a46d", false, "", false},
                // opbs cookie and previous session are existing, user consent is empty, there is a value for
                // sessionDataKey, skipUserConsent=true and an invalid idTokenHint.
                {opbsCookie, true, redirectUrl[2], "failed", " ", "090907ce-eab0-40d2-a46d", true,
                        "7893-090907ce-eab0-40d2", false},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=true and an invalid idTokenHint.
                {opbsCookie, true, redirectUrl[2], "failed", " ", null, true,
                        "7893-090907ce-eab0-40d2", false},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=false and a valid idTokenHint.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, false,
                        idTokenHint, false},
                // opbs cookie and previous session are existing, user consent is empty,sessionDataKey = null,
                // skipUserConsent=true and a valid idTokenHint.
                {opbsCookie, true, redirectUrl[5], "oauth2_logout_consent.do", " ", null, true,
                        idTokenHint, false},
        };
    }

    @Test(dataProvider = "provideDataForTestDoGet")
    public void testDoGet(Object cookie, boolean sessionExists, String redirectUrl, String expected, String consent,
                          String sessionDataKey, boolean skipUserConsent, String idTokenHint,
                          boolean isJWTSignedWithSPKey) throws Exception {
        TestUtil.startTenantFlow("carbon.super");

        mockStatic(OIDCSessionManagementUtil.class);
        when(OIDCSessionManagementUtil.getOPBrowserStateCookie(request)).thenReturn((Cookie) cookie);
        when(OIDCSessionManagementUtil.getErrorPageURL(anyString(), anyString())).thenReturn(redirectUrl);

        mockStatic(OIDCSessionManager.class);
        when(OIDCSessionManagementUtil.getSessionManager()).thenReturn(oidcSessionManager);
        when(oidcSessionManager.sessionExists(OPBROWSER_STATE)).thenReturn(sessionExists);

        when(request.getParameter("consent")).thenReturn(consent);
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Arrays.asList(new String[]{"cookie" })));
        when(request.getHeader("COOKIE")).thenReturn("opbs");

        doThrow(new ServletException()).when(commonAuthenticationHandler).doPost(request, response);

        when(request.getSession()).thenReturn(httpSession);
        when(httpSession.getMaxInactiveInterval()).thenReturn(2);

        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);

        when(request.getParameter("sessionDataKey")).thenReturn(sessionDataKey);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(skipUserConsent);

        when(request.getParameter("id_token_hint")).thenReturn(idTokenHint);

        when(OIDCSessionManagementUtil
                .removeOPBrowserStateCookie(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn((Cookie) cookie);

        when(OIDCSessionManagementUtil.getOIDCLogoutConsentURL()).thenReturn(redirectUrl);
        when(OIDCSessionManagementUtil.getOIDCLogoutURL()).thenReturn(redirectUrl);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.isJWTSignedWithSPKey()).thenReturn(isJWTSignedWithSPKey);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(TENANT_ID)).thenReturn(keyStoreManager);
        when(keyStoreManager.getDefaultPublicKey())
                .thenReturn(TestUtil.getPublicKey(TestUtil.loadKeyStoreFromFileSystem(TestUtil
                        .getFilePath("wso2carbon.jks"), "wso2carbon", "JKS"), "wso2carbon"));

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArguments()[0];
            }
        });

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        logoutServlet.doGet(request, response);
        verify(response).sendRedirect(captor.capture());
        assertTrue(captor.getValue().contains(expected));
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @AfterTest
    public void cleanData() throws Exception {
        super.cleanData();
    }

}
