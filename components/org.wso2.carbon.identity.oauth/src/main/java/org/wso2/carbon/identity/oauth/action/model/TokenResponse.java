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
 * It models the manifest of top level field names present on the token endpoint's success and
 * failure responses, so that an external service can add custom fields to either response, and
 * remove optional standard fields from the success response.
 */
public class TokenResponse {

    private final Fields fields;

    private TokenResponse(Builder builder) {

        this.fields = builder.fields;
    }

    public Fields getFields() {

        return fields;
    }

    /**
     * Builder for TokenResponse.
     */
    public static class Builder {

        private Fields fields;

        public Builder fields(Fields fields) {

            this.fields = fields;
            return this;
        }

        public TokenResponse build() {

            return new TokenResponse(this);
        }
    }

    /**
     * Represents the field name manifests for the success and failure token responses.
     */
    public static class Fields {

        private final List<String> success;
        private final List<String> failure;

        private Fields(Builder builder) {

            this.success = builder.success;
            this.failure = builder.failure;
        }

        public List<String> getSuccess() {

            return success;
        }

        public List<String> getFailure() {

            return failure;
        }

        /**
         * Builder for Fields.
         */
        public static class Builder {

            private List<String> success = new ArrayList<>();
            private List<String> failure = new ArrayList<>();

            public Builder success(List<String> success) {

                this.success = success;
                return this;
            }

            public Builder failure(List<String> failure) {

                this.failure = failure;
                return this;
            }

            public Fields build() {

                return new Fields(this);
            }
        }
    }
}
