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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import javax.security.auth.callback.Callback;


import static org.testng.Assert.*;

/**
 * Unit tests for DefaultCallbackHandlerTest.
 */
public class DefaultCallbackHandlerTest {

    @DataProvider(name = "testHandle")
    public Object[][] callBackType() {
        return new Object[][] {
                {OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_AUTHZ},
                {OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_TOKEN},
                {OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_AUTHZ},
                {OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_TOKEN},
                {null}
        };
    }

    @Test
    public void testCanHandle() throws Exception {

        Callback[] callbacks = new Callback[5];
        DefaultCallbackHandler defaultCallbackHandler = new DefaultCallbackHandler();
        assertTrue(defaultCallbackHandler.canHandle(callbacks), "Should return true for any array of Callback.");
    }

    @Test(dataProvider = "testHandle")
    public void testHandle(OAuthCallback.OAuthCallbackType callbackType) throws Exception {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        OAuthCallback oAuthCallback = new OAuthCallback(authenticatedUser, "client", callbackType);
        oAuthCallback.setAuthorized(false);
        oAuthCallback.setValidScope(false);

        DefaultCallbackHandler defaultCallbackHandler = new DefaultCallbackHandler();
        defaultCallbackHandler.handle(new Callback[]{oAuthCallback});
        if (callbackType == OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_AUTHZ
                || callbackType == OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_TOKEN) {
            assertTrue(oAuthCallback.isAuthorized(), "Should be an authorized callback once ACCESS_DELEGATION_* " +
                    "callback has been handled.");
        } else if (callbackType == OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_AUTHZ
                || callbackType == OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_TOKEN) {
            assertTrue(oAuthCallback.isValidScope(), "Should be a valid scope once SCOPE_VALIDATION_* callback has " +
                    "been handled.");
        } else {
            assertFalse(oAuthCallback.isAuthorized(), "Should be an unauthorized callback if the callbackType is not " +
                    "an enum of OAuthCallback.OAuthCallbackType.");
            assertFalse(oAuthCallback.isValidScope(), "Should be an invalid scope if the callbackType is not " +
                    "an enum of OAuthCallback.OAuthCallbackType.");
        }
    }
}
