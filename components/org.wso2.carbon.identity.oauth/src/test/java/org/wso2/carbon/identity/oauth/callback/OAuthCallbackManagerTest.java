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

package org.wso2.carbon.identity.oauth.callback;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for OAuthCallbackManager.
 */
@PrepareForTest({OAuthCallbackHandlerRegistry.class})
public class OAuthCallbackManagerTest extends PowerMockTestCase {

    @Mock
    private OAuthCallbackHandlerRegistry oAuthCallbackHandlerRegistry;

    @Test
    public void testHandleCallbackNoCallBackHandlerCanbeFound() throws Exception {

        mockStatic(OAuthCallbackHandlerRegistry.class);
        when(OAuthCallbackHandlerRegistry.getInstance()).thenReturn(oAuthCallbackHandlerRegistry);

        OAuthCallbackManager oAuthCallbackManager = new OAuthCallbackManager();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        OAuthCallback oAuthCallback = new OAuthCallback(authenticatedUser, "client", OAuthCallback.OAuthCallbackType
                .ACCESS_DELEGATION_AUTHZ);
        oAuthCallback.setAuthorized(false);

        oAuthCallbackManager.handleCallback(oAuthCallback);
        assertFalse(oAuthCallback.isAuthorized(), "oAuthCallback should not be a authorized callback if it has not " +
                "been handled.");
    }

    @Test
    public void testHandleCallbackCallBackHandlerCanbeFound() throws Exception {

        DefaultCallbackHandler defaultCallbackHandler = new DefaultCallbackHandler();
        when(oAuthCallbackHandlerRegistry.getOAuthAuthzHandler(any(OAuthCallback.class)))
                .thenReturn(defaultCallbackHandler);
        mockStatic(OAuthCallbackHandlerRegistry.class);
        when(OAuthCallbackHandlerRegistry.getInstance()).thenReturn(oAuthCallbackHandlerRegistry);

        OAuthCallbackManager oAuthCallbackManager = new OAuthCallbackManager();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        OAuthCallback oAuthCallback = new OAuthCallback(authenticatedUser, "client", OAuthCallback.OAuthCallbackType
                .ACCESS_DELEGATION_AUTHZ);
        oAuthCallback.setAuthorized(false);

        oAuthCallbackManager.handleCallback(oAuthCallback);
        assertTrue(oAuthCallback.isAuthorized(), "oAuthCallback should be a authorized callback once it has been " +
                "handled.");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testHandleCallbackErrorWhileObtainingCallbackHandler() throws Exception {

        when(oAuthCallbackHandlerRegistry.getOAuthAuthzHandler(any(OAuthCallback.class)))
                .thenThrow(new IdentityOAuth2Exception(""));
        mockStatic(OAuthCallbackHandlerRegistry.class);
        when(OAuthCallbackHandlerRegistry.getInstance()).thenReturn(oAuthCallbackHandlerRegistry);

        OAuthCallbackManager oAuthCallbackManager = new OAuthCallbackManager();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        OAuthCallback oAuthCallback = new OAuthCallback(authenticatedUser, "client", OAuthCallback.OAuthCallbackType
                .ACCESS_DELEGATION_AUTHZ);
        oAuthCallback.setAuthorized(false);

        oAuthCallbackManager.handleCallback(oAuthCallback);
    }
}
