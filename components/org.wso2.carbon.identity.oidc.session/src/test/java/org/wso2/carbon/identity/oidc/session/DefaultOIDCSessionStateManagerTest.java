/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for the opbs cookie path resolution in {@link DefaultOIDCSessionStateManager}.
 */
@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class DefaultOIDCSessionStateManagerTest {

    private static final String OPBS_VALUE = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String TENANT_DOMAIN = "foo.com";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";

    @DataProvider(name = "opbsCookiePathDataProvider")
    public Object[][] provideOpbsCookiePathData() {

        return new Object[][]{
                // loginTenantDomain, proxyContextPath, superTenantAppendInCookiePath, expectedCookiePath

                // A tenanted cookie path carries the proxy context path.
                {TENANT_DOMAIN, "auth", false, "/auth/t/" + TENANT_DOMAIN + "/"},

                // The configured value is normalized before it is applied.
                {TENANT_DOMAIN, "/auth/", false, "/auth/t/" + TENANT_DOMAIN + "/"},

                // Without a proxy context path the tenanted path is unchanged.
                {TENANT_DOMAIN, "", false, "/t/" + TENANT_DOMAIN + "/"},

                // The super tenant keeps the root cookie path, which already covers any prefix.
                {SUPER_TENANT_DOMAIN, "auth", false, "/"},

                // When the super tenant is appended, its path is prefixed like any other tenant.
                {SUPER_TENANT_DOMAIN, "auth", true, "/auth/t/" + SUPER_TENANT_DOMAIN + "/"},
        };
    }

    @Test(dataProvider = "opbsCookiePathDataProvider")
    public void testAddOPBrowserStateCookieAppliesProxyContextPath(String loginTenantDomain, String proxyContextPath,
                                                                  boolean superTenantAppendInCookiePath,
                                                                  String expectedCookiePath) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        lenient().when(request.getCookies()).thenReturn(null);

        ServerConfiguration serverConfiguration = mock(ServerConfiguration.class);
        lenient().when(serverConfiguration.getFirstProperty(IdentityCoreConstants.PROXY_CONTEXT_PATH))
                .thenReturn(proxyContextPath);

        PrivilegedCarbonContext.startTenantFlow();
        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ServerConfiguration> serverConfigurationStatic = mockStatic(ServerConfiguration.class)) {

            identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(true);
            identityTenantUtil.when(IdentityTenantUtil::isSuperTenantAppendInCookiePath)
                    .thenReturn(superTenantAppendInCookiePath);
            serverConfigurationStatic.when(ServerConfiguration::getInstance).thenReturn(serverConfiguration);

            new DefaultOIDCSessionStateManager()
                    .addOPBrowserStateCookie(response, request, loginTenantDomain, OPBS_VALUE);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(cookieCaptor.capture());
        assertEquals(cookieCaptor.getValue().getPath(), expectedCookiePath,
                "Unexpected opbs cookie path for login tenant domain: " + loginTenantDomain);
    }

    @Test
    public void testAddOPBrowserStateCookieWithoutTenantedSessions() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(false);

            new DefaultOIDCSessionStateManager()
                    .addOPBrowserStateCookie(response, request, TENANT_DOMAIN, OPBS_VALUE);
        }

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(cookieCaptor.capture());
        assertEquals(cookieCaptor.getValue().getPath(), "/",
                "The cookie path should stay at the root path when tenanted sessions are disabled");
    }
}
