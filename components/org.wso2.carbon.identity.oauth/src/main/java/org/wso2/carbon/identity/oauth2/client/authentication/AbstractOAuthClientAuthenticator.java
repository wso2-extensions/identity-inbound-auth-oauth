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

import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Abstract OAuth2 client authenticator.
 */
public abstract class AbstractOAuthClientAuthenticator extends AbstractIdentityHandler implements
        OAuthClientAuthenticator {

    /**
     * Get the set of body parameters.
     *
     * @param content Map of parameters
     * @return Body parameters as a string map
     */
    protected Map<String, String> getBodyParameters(Map<String, List> content) {
        Map<String, String> stringParams = new HashMap<>();
        content.forEach((key, value) -> {
            if (value != null && value.size() > 0) {
                stringParams.put(key, (String) value.get(0));
            }
        });
        return stringParams;
    }

    /**
     * Get HTTP headers as string map
     *
     * @param request HttpServeletRequest
     * @return HTTP headers as a string parameter map
     */
    protected Map<String, String> getHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String attributeName = headerNames.nextElement();
            headers.put(attributeName, request.getHeader(attributeName));
        }
        return headers;
    }

}
