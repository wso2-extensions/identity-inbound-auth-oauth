/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class CookieBasedTokenBinderTest {

    private static final String COOKIE_NAME = "atbv";
    private static final String BINDING_VALUE = "0f8fad5b-d9cb-469f-a165-70867728950e";
    private static final String SUPER_TENANT = "carbon.super";

    @Mock
    private HttpServletResponse response;

    @Mock
    private PrivilegedCarbonContext carbonContext;

    private CookieBasedTokenBinder cookieBasedTokenBinder;

    @BeforeMethod
    public void setUp() {

        cookieBasedTokenBinder = new CookieBasedTokenBinder();
    }

    @DataProvider(name = "cookiePathData")
    public Object[][] cookiePathData() {

        return new Object[][]{
                // tenantedSessions, appendSuperTenant, orgId, appResidentOrgId, contextTenant, loginTenant, path
                // Tenant login: scoped to the tenant path.
                {true, true, null, null, null, "tenant1.com", "/t/tenant1.com/"},
                // Super tenant, with the super tenant appended to cookie paths: still the root path.
                {true, true, null, null, null, SUPER_TENANT, "/"},
                // Super tenant, without the super tenant appended to cookie paths.
                {true, false, null, null, null, SUPER_TENANT, "/"},
                // Organization qualified request (/o/<org-id>).
                {true, true, "org-id-1", null, null, "tenant1.com", "/o/org-id-1/"},
                // Application resident in an organization: scoped to the root tenant path.
                {true, true, null, "app-org-1", "root.com", "tenant1.com", "/t/root.com/"},
                // Tenanted sessions disabled: root path.
                {false, true, null, null, null, "tenant1.com", "/"},
                // No login tenant domain: root path.
                {true, true, null, null, null, null, "/"}
        };
    }

    @Test(dataProvider = "cookiePathData")
    public void testSetTokenBindingValueForResponseScopesCookiePath(boolean tenantedSessions,
                                                                   boolean appendSuperTenant, String orgId,
                                                                   String appResidentOrgId, String contextTenant,
                                                                   String loginTenant, String expectedPath) {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext =
                     mockStatic(PrivilegedCarbonContext.class)) {
            identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(tenantedSessions);
            frameworkUtils.when(FrameworkUtils::isOrganizationQualifiedRequest).thenReturn(orgId != null);
            frameworkUtils.when(() -> FrameworkUtils.prependProxyContextPath(anyString()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            privilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            lenient().when(carbonContext.getOrganizationId()).thenReturn(orgId);
            lenient().when(carbonContext.getApplicationResidentOrganizationId()).thenReturn(appResidentOrgId);
            lenient().when(carbonContext.getTenantDomain()).thenReturn(contextTenant);

            cookieBasedTokenBinder.setTokenBindingValueForResponse(response, BINDING_VALUE, loginTenant);

            Cookie cookie = captureCookie();
            assertEquals(cookie.getPath(), expectedPath);
            assertEquals(cookie.getValue(), BINDING_VALUE);
        }
    }

    @Test
    public void testSetTokenBindingValueForResponseWithoutTenantKeepsRootPath() {

        cookieBasedTokenBinder.setTokenBindingValueForResponse(response, BINDING_VALUE);

        assertEquals(captureCookie().getPath(), "/");
    }

    private Cookie captureCookie() {

        ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(captor.capture());
        Cookie cookie = captor.getValue();
        assertEquals(cookie.getName(), COOKIE_NAME);
        assertTrue(cookie.getSecure());
        assertTrue(cookie.isHttpOnly());
        return cookie;
    }
}
