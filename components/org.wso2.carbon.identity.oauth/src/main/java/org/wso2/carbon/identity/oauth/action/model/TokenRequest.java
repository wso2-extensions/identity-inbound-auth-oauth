/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.action.model;

import org.wso2.carbon.identity.action.execution.model.Request;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TokenRequest extends Request {

    private static final List<String> headersToAvoid = new ArrayList<>();
    private static final List<String> paramsToAvoid = new ArrayList<>();

    static {
        headersToAvoid.add("authorization");
        headersToAvoid.add("cookie");
        headersToAvoid.add("set-cookie");
        headersToAvoid.add("accept-encoding");
        headersToAvoid.add("accept-language");
        headersToAvoid.add("content-length");
        headersToAvoid.add("content-type");
        // parameters from authorization code grant
        paramsToAvoid.add("code");
        paramsToAvoid.add("client_id");
        paramsToAvoid.add("client_secret");
        paramsToAvoid.add("redirect_uri");
        paramsToAvoid.add("grant_type");
        paramsToAvoid.add("scope");
        // parameters from password grant
        paramsToAvoid.add("username");
        paramsToAvoid.add("password");
        // parameters from refresh token grant
        paramsToAvoid.add("refresh_token");
    }

    private final String clientId;
    private final String grantType;
    private final String redirectUri;
    private final List<String> scopes;

    private TokenRequest(Builder builder) {

        this.clientId = builder.clientId;
        this.grantType = builder.grantType;
        this.redirectUri = builder.redirectUri;
        this.scopes = builder.scopes;
        this.additionalHeaders = builder.additionalHeaders;
        this.additionalParams = builder.additionalParams;
    }

    public String getClientId() {

        return clientId;
    }

    public String getGrantType() {

        return grantType;
    }

    public String getRedirectUri() {

        return redirectUri;
    }

    public List<String> getScopes() {

        return scopes;
    }

    public static class Builder {

        private final Map<String, String[]> additionalHeaders = new HashMap<>();
        private final Map<String, String[]> additionalParams = new HashMap<>();
        private String clientId;
        private String grantType;
        private String redirectUri;
        private List<String> scopes = new ArrayList<>();

        public Builder clientId(String clientId) {

            this.clientId = clientId;
            return this;
        }

        public Builder grantType(String grantType) {

            this.grantType = grantType;
            return this;
        }

        public Builder redirectUri(String redirectUri) {

            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scopes(List<String> scopes) {

            this.scopes = scopes;
            return this;
        }

        public Builder addAdditionalHeader(String key, String[] value) {

            if (!headersToAvoid.contains(key.toLowerCase())) {
                this.additionalHeaders.put(key, value);
            }
            return this;
        }

        public Builder addAdditionalParam(String key, String[] value) {

            if (!paramsToAvoid.contains(key)) {
                this.additionalParams.put(key, value);
            }
            return this;
        }

        public TokenRequest build() {

            return new TokenRequest(this);
        }
    }
}