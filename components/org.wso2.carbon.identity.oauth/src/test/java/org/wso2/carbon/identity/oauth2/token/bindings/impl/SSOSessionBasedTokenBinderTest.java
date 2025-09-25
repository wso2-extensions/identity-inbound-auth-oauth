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

import org.apache.commons.lang.StringUtils;
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for SSOSessionBasedTokenBinder class.
 */
public class SSOSessionBasedTokenBinderTest {

    private static final String SESSION_IDENTIFIER = "session_identifier";
    private static final String TENANT_DOMAIN = "tenant_domain";
    private SSOSessionBasedTokenBinder ssoSessionBasedTokenBinder;

    @BeforeClass
    public void setUp() {

        ssoSessionBasedTokenBinder = new SSOSessionBasedTokenBinder();
    }

    @DataProvider(name = "tokenBindingDataProvider")
    public Object[][] tokenBindingDataProvider() {

        TokenBinding tokenBindingWithValidValue = new TokenBinding();
        tokenBindingWithValidValue.setBindingValue(SESSION_IDENTIFIER);

        TokenBinding tokenBindingWithEmptyValue = new TokenBinding();
        tokenBindingWithEmptyValue.setBindingValue(StringUtils.EMPTY);

        AccessTokenDO accessTokenDOWithEmptyTokenBinding = new AccessTokenDO();
        accessTokenDOWithEmptyTokenBinding.setTokenBinding(tokenBindingWithEmptyValue);

        AccessTokenDO accessTokenDOWithNullTokenBindingValue = new AccessTokenDO();
        accessTokenDOWithNullTokenBindingValue.setTokenBinding(new TokenBinding());

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        AccessTokenDO accessTokenDOWithUser = new AccessTokenDO();
        accessTokenDOWithUser.setAuthzUser(authenticatedUser);
        accessTokenDOWithUser.setTokenBinding(tokenBindingWithValidValue);

        AccessTokenDO accessTokenDOWithoutUser = new AccessTokenDO();
        accessTokenDOWithoutUser.setTokenBinding(tokenBindingWithValidValue);

        return new Object[][]{
                {null, null, false},
                {new AccessTokenDO(), null, false},
                {accessTokenDOWithNullTokenBindingValue, null, false},
                {accessTokenDOWithEmptyTokenBinding, null, false},
                {accessTokenDOWithUser, new SessionContext(), true},
                {accessTokenDOWithoutUser, new SessionContext(), true},
                {accessTokenDOWithUser, null, false}
        };
    }

    @Test(dataProvider = "tokenBindingDataProvider")
    public void testIsValidTokenBinding(AccessTokenDO accessTokenDO, SessionContext sessionContext,
                                        boolean expectedResult) {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(SESSION_IDENTIFIER, TENANT_DOMAIN))
                    .thenReturn(sessionContext);
            frameworkUtils.when(FrameworkUtils::getLoginTenantDomainFromContext).thenReturn(TENANT_DOMAIN);

            assertEquals(ssoSessionBasedTokenBinder.isValidTokenBinding(accessTokenDO), expectedResult,
                    "Failed to validate token binding.");
        }
    }
}
