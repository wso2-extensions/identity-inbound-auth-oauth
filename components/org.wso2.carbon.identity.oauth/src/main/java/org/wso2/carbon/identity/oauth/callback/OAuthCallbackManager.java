/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import javax.security.auth.callback.Callback;

public class OAuthCallbackManager {

    private static final Log log = LogFactory.getLog(OAuthCallbackManager.class);
    private OAuthCallbackHandlerRegistry callbackHandlerRegistry;

    public OAuthCallbackManager() throws IdentityOAuth2Exception {
        callbackHandlerRegistry = OAuthCallbackHandlerRegistry.getInstance();
    }

    public void handleCallback(OAuthCallback authzCallback)
            throws IdentityOAuth2Exception {
        try {
            OAuthCallbackHandler authzCbHandler =
                    callbackHandlerRegistry.getOAuthAuthzHandler(authzCallback);
            if (authzCbHandler != null) {
                authzCbHandler.handle(new Callback[]{authzCallback});
            }
        } catch (Exception e) {
            log.error("Error while calling OAuthAuthorization Handler. ", e);
            throw new IdentityOAuth2Exception("Error while calling OAuthAuthorization Handler. ", e);
        }
    }
}
