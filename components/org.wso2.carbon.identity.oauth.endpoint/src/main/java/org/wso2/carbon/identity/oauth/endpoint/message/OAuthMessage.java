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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.message;

import org.wso2.carbon.identity.oauth.endpoint.authz.OAuthAuthorizeState;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuthRequestStateValidator;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuthMessage {

    private HttpServletRequest request;
    private HttpServletResponse response;
    private Map<String, Object> properties = new HashMap();
    private OAuthAuthorizeState requestType;

    private OAuthMessage(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    public Object getProperty(String key) {
        if (properties != null) {
            return properties.get(key);
        } else {
            return null;
        }
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public void setProperty(String key, Object value) {
        properties.put(key, value);
    }

    public void removeProperty(String key) {
        properties.remove(key);
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public OAuthAuthorizeState getRequestType() {
        return requestType;
    }

    private void setRequestType(OAuthAuthorizeState requestType) {
        this.requestType = requestType;
    }


    public static class OAuthMessageBuilder {

        private HttpServletRequest request;
        private HttpServletResponse response;

        public HttpServletRequest getRequest() {
            return request;
        }

        public HttpServletResponse getResponse() {
            return response;
        }

        public OAuthMessageBuilder setRequest(HttpServletRequest request) {
            this.request = request;
            return this;
        }

        public OAuthMessageBuilder setResponse(HttpServletResponse response) {
            this.response = response;
            return this;
        }

        public OAuthMessage build() throws InvalidRequestException {

            OAuthMessage oAuthMessage = new OAuthMessage(request, response);
            OAuthRequestStateValidator oAuthRequestStateValidator = new OAuthRequestStateValidator();
            oAuthMessage.setRequestType(oAuthRequestStateValidator.getAndValidateCurrentState(request));
            return oAuthMessage;
        }
    }
}
