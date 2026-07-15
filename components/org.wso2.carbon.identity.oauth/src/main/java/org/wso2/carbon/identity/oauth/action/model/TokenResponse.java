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

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the token endpoint response sent in the event payload
 * of the pre issue access token action.
 * It models the manifest of top level field names that will be present on the token endpoint's response,
 * so that an external service can add custom fields to the response, and remove optional standard fields
 * from it.
 */
public class TokenResponse {

    private final List<String> fields;

    private TokenResponse(Builder builder) {

        this.fields = builder.fields;
    }

    public List<String> getFields() {

        return fields;
    }

    /**
     * Builder for TokenResponse.
     */
    public static class Builder {

        private List<String> fields = new ArrayList<>();

        public Builder fields(List<String> fields) {

            this.fields = fields;
            return this;
        }

        public TokenResponse build() {

            return new TokenResponse(this);
        }
    }
}
