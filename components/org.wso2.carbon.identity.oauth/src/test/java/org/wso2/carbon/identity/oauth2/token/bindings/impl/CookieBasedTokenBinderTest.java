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

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenBindingMgtDAO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;

@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class CookieBasedTokenBinderTest {

    private static final String COOKIE_NAME = "atbv";

    @Mock
    private HttpServletRequest request;

    @Mock
    private OAuthTokenPersistenceFactory persistenceFactory;

    @Mock
    private TokenBindingMgtDAO tokenBindingMgtDAO;

    private CookieBasedTokenBinder cookieBasedTokenBinder;

    @BeforeMethod
    public void setUp() {

        cookieBasedTokenBinder = new CookieBasedTokenBinder();
    }

    @DataProvider(name = "reusableCookieValues")
    public Object[][] reusableCookieValues() {

        String uuid = UUID.randomUUID().toString();
        return new Object[][]{
                // A binding exists for the value in this deployment's store.
                {uuid, true},
                // No binding in this deployment's store: the value was minted by another deployment that
                // shares the cookie host (e.g. a central and a regional deployment on one API domain).
                // It must be reused, otherwise the other deployment's tokens lose their binding.
                {uuid, false}
        };
    }

    @Test(dataProvider = "reusableCookieValues")
    public void testGetOrGenerateReusesWellFormedCookieValue(String cookieValue, boolean bindingExists)
            throws Exception {

        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(COOKIE_NAME, cookieValue)});
        try (MockedStatic<OAuthTokenPersistenceFactory> factory = mockStatic(OAuthTokenPersistenceFactory.class)) {
            mockBindingExists(factory, OAuth2Util.getTokenBindingReference(cookieValue), bindingExists);

            assertEquals(cookieBasedTokenBinder.getOrGenerateTokenBindingValue(request), cookieValue);
        }
    }

    @DataProvider(name = "nonReusableCookies")
    public Object[][] nonReusableCookies() {

        return new Object[][]{
                // No cookies at all.
                {null},
                // No atbv cookie.
                {new Cookie[]{new Cookie("other", UUID.randomUUID().toString())}},
                // Blank atbv cookie.
                {new Cookie[]{new Cookie(COOKIE_NAME, " ")}},
                // Unknown value that is not a UUID this binder could have minted.
                {new Cookie[]{new Cookie(COOKIE_NAME, "attacker-chosen-value")}},
                // Unknown value that is a UUID only in a non-canonical form.
                {new Cookie[]{new Cookie(COOKIE_NAME, UUID.randomUUID().toString().toUpperCase())}}
        };
    }

    @Test(dataProvider = "nonReusableCookies")
    public void testGetOrGenerateMintsNewValue(Cookie[] cookies) throws Exception {

        when(request.getCookies()).thenReturn(cookies);
        try (MockedStatic<OAuthTokenPersistenceFactory> factory = mockStatic(OAuthTokenPersistenceFactory.class)) {
            mockBindingExists(factory, null, false);

            String value = cookieBasedTokenBinder.getOrGenerateTokenBindingValue(request);

            assertNotNull(value);
            assertEquals(UUID.fromString(value).toString(), value);
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    assertNotEquals(value, cookie.getValue());
                }
            }
        }
    }

    @Test(expectedExceptions = OAuthSystemException.class)
    public void testGetTokenBindingValueStillRequiresKnownBinding() throws Exception {

        String cookieValue = UUID.randomUUID().toString();
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(COOKIE_NAME, cookieValue)});
        try (MockedStatic<OAuthTokenPersistenceFactory> factory = mockStatic(OAuthTokenPersistenceFactory.class)) {
            mockBindingExists(factory, OAuth2Util.getTokenBindingReference(cookieValue), false);

            cookieBasedTokenBinder.getTokenBindingValue(request);
        }
    }

    private void mockBindingExists(MockedStatic<OAuthTokenPersistenceFactory> factory, String bindingReference,
                                   boolean exists) throws IdentityOAuth2Exception {

        // Lenient: requests without a usable cookie never reach the DAO.
        factory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(persistenceFactory);
        lenient().when(persistenceFactory.getTokenBindingMgtDAO()).thenReturn(tokenBindingMgtDAO);
        if (bindingReference != null) {
            lenient().when(tokenBindingMgtDAO.isTokenBindingExistsForBindingReference(bindingReference))
                    .thenReturn(exists);
        } else {
            lenient().when(tokenBindingMgtDAO.isTokenBindingExistsForBindingReference(anyString()))
                    .thenReturn(exists);
        }
    }
}
