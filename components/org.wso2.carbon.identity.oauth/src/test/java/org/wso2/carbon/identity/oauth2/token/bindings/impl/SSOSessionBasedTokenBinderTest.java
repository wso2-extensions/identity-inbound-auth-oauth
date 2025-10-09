/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import org.apache.commons.codec.digest.DigestUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class SSOSessionBasedTokenBinderTest {

    @Mock
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;

    @Mock
    private HttpServletRequest httpServletRequest;

    private SSOSessionBasedTokenBinder ssoSessionBasedTokenBinder;

    private static final String COMMONAUTH_COOKIE = "commonAuthId";
    private static final String COMMONAUTH_COOKIE_VALUE = "common-auth-cookie-value";
    private static final String SESSION_IDENTIFIER = DigestUtils.sha256Hex(COMMONAUTH_COOKIE_VALUE);
    private static final String BINDING_REFERENCE = "sso-binding-reference";

    @BeforeMethod
    public void setUp() {

        ssoSessionBasedTokenBinder = new SSOSessionBasedTokenBinder();
    }

    @DataProvider(name = "tokenBindingDataProviderForDTO")
    public Object[][] tokenBindingDataProviderForDTO() {

        SessionContext sessionContext = mock(SessionContext.class);
        return new Object[][]{
                // A valid session context exists for the session identifier, so the binding is valid.
                {SESSION_IDENTIFIER, sessionContext, true},
                // No session context for the session identifier (e.g., expired session), so binding is invalid.
                {SESSION_IDENTIFIER, null, false},
                // No session identifier cookie in the request, so binding is invalid.
                {null, null, false}
        };
    }

    @Test(dataProvider = "tokenBindingDataProviderForDTO")
    public void testIsValidTokenBindingWithDTO(String sessionIdentifier, SessionContext sessionContext,
                                               boolean expectedResult) {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {

            oAuth2Util.when(() -> OAuth2Util.getTokenBindingValue(oAuth2AccessTokenReqDTO, COMMONAUTH_COOKIE))
                    .thenReturn(Optional.ofNullable(sessionIdentifier));

            if (sessionIdentifier != null) {
                frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(sessionIdentifier))
                        .thenReturn(sessionContext);
                // We only need to mock the reference generation for the happy path (when a session exists).
                if (sessionContext != null) {
                    oAuth2Util.when(() -> OAuth2Util.getTokenBindingReference(sessionIdentifier))
                            .thenReturn(BINDING_REFERENCE);
                    when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn(OAuthConstants.GrantTypes.REFRESH_TOKEN);
                }
            }

            assertEquals(ssoSessionBasedTokenBinder.isValidTokenBinding(oAuth2AccessTokenReqDTO, BINDING_REFERENCE),
                    expectedResult);
        }
    }

    @DataProvider(name = "tokenBindingDataProviderForRequest")
    public Object[][] tokenBindingDataProviderForRequest() {

        SessionContext sessionContext = mock(SessionContext.class);
        Cookie validCookie = new Cookie(COMMONAUTH_COOKIE, COMMONAUTH_COOKIE_VALUE);
        return new Object[][]{
                // A valid session context exists for the session identifier in the cookie, so the binding is valid.
                {new Cookie[]{validCookie}, sessionContext, true},
                // No session context for the session identifier (e.g., expired session), so binding is invalid.
                {new Cookie[]{validCookie}, null, false},
                // No commonAuth cookie in the request, so binding is invalid.
                {new Cookie[]{}, null, false},
                // No cookies in the request at all, so binding is invalid.
                {null, null, false}
        };
    }

    @Test(dataProvider = "tokenBindingDataProviderForRequest")
    public void testIsValidTokenBindingWithRequest(Cookie[] cookies, SessionContext sessionContext,
                                                   boolean expectedResult) {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {

            when(httpServletRequest.getCookies()).thenReturn(cookies);

            if (cookies != null && cookies.length > 0) {
                frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(SESSION_IDENTIFIER))
                        .thenReturn(sessionContext);
                if (sessionContext != null) {
                    oAuth2Util.when(() -> OAuth2Util.getTokenBindingReference(SESSION_IDENTIFIER))
                            .thenReturn(BINDING_REFERENCE);
                }
            }

            assertEquals(ssoSessionBasedTokenBinder.isValidTokenBinding(httpServletRequest, BINDING_REFERENCE),
                    expectedResult);
        }
    }
}
