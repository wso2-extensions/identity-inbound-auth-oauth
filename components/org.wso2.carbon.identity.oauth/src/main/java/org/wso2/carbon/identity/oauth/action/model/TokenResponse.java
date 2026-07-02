/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the token endpoint response sent in the event payload
 * of the pre issue access token action.
 * It models the custom, top level parameters that can be added to the token endpoint response,
 * in addition to the access token and refresh token content.
 */
public class TokenResponse {

    private final Map<String, Object> params;

    private TokenResponse(Builder builder) {

        this.params = builder.params;
    }

    @JsonInclude(JsonInclude.Include.ALWAYS)
    public Map<String, Object> getParams() {

        return params;
    }

    public Builder copy() {

        return new Builder().params(new HashMap<>(this.params));
    }

    /**
     * Builder for TokenResponse.
     */
    public static class Builder {

        private Map<String, Object> params = new HashMap<>();

        public Builder params(Map<String, Object> params) {

            this.params = params;
            return this;
        }

        public Builder addParam(String name, Object value) {

            this.params.put(name, value);
            return this;
        }

        public Map<String, Object> getParams() {

            return params;
        }

        public TokenResponse build() {

            return new TokenResponse(this);
        }
    }
}
