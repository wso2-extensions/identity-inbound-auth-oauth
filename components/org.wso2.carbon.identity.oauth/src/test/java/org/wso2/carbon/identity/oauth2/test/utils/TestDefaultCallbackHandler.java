/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.oauth2.test.utils;

import org.wso2.carbon.identity.oauth.callback.DefaultCallbackHandler;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;

import java.io.IOException;
import java.util.Arrays;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class TestDefaultCallbackHandler extends DefaultCallbackHandler {

    @Override
    public boolean canHandle(Callback[] callbacks) throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        OAuthCallback oauthCallback = (OAuthCallback) callbacks[0];
        String[] requestedScopes = oauthCallback.getRequestedScope();
        if (oauthCallback.getCallbackType().equals(OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_AUTHZ) &&
            Arrays.asList(requestedScopes).contains(TestConstants.SCOPE_UNAUTHORIZED_ACCESS)) {
            oauthCallback.setAuthorized(false);
        } else if (oauthCallback.getCallbackType().equals(OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_AUTHZ) &&
                   Arrays.asList(requestedScopes).contains(TestConstants.SCOPE_UNAUTHORIZED_SCOPE)) {
            oauthCallback.setAuthorized(false);
        } else {
            super.handle(callbacks);
        }

    }
}
