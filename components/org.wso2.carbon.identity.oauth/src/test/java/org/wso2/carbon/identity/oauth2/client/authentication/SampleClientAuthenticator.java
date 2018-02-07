/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

/**
 * Sample authenticator which is used for unit tests.
 */
public class SampleClientAuthenticator extends AbstractOAuthClientAuthenticator {

    public static final String SAMPLE_HEADER = "SampleHeader";
    public static final String EXPECTED_SAMPLE_HEADER = "expectedSampleHeader";
    public boolean enabled = true;

    @Override
    public boolean authenticateClient(HttpServletRequest request, Map<String, List> content,
                                      OAuthClientAuthnContext oAuthClientAuthnContext) throws OAuthClientAuthnException {

        if (EXPECTED_SAMPLE_HEADER.equalsIgnoreCase(request.getHeader(SAMPLE_HEADER))) {
            return true;
        } else if (request.getHeader("ErrorAuthenticate") != null) {
            throw new OAuthClientAuthnException("invalid_client", "Error while authenticating client");
        }
        return false;
    }

    @Override
    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> content, OAuthClientAuthnContext oAuthClientAuthnContext) {

        if (request.getHeader(SAMPLE_HEADER) != null) {
            return true;
        }
        return false;
    }

    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> content,
                              OAuthClientAuthnContext oAuthClientAuthnContext) throws OAuthClientAuthnException {

        if (request.getHeader("ErrorCanAuthenticate") != null) {
            throw new OAuthClientAuthnException("invalid_request", "Error while evaluating can authenticate");
        }
        return request.getHeader(SAMPLE_HEADER);
    }

    @Override
    public int getPriority() {

        return 150;
    }

    @Override
    public String getName() {

        return "SampleClientAuthenticator";
    }

    @Override
    public boolean isEnabled() {

        return this.enabled;
    }
}
