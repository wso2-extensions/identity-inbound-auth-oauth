/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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
import java.util.stream.Collectors;

/**
 * This class represents the model of the access token sent in the json request
 * to the API endpoint of the pre issue access token action.
 */
public class AccessToken extends AbstractToken {

    List<String> scopes;

    private AccessToken(Builder builder) {

        super(builder);
        this.scopes = builder.scopes;
    }

    public List<String> getScopes() {

        return scopes;
    }

    public AccessToken.Builder copy() {

        return new Builder()
                .tokenType(this.tokenType)
                .scopes(new ArrayList<>(this.scopes))
                .claims(this.claims.stream().map(Claim::copy).collect(Collectors.toList()));
    }

    /**
     * Builder for AccessToken.
     */
    public static class Builder extends AbstractBuilder<Builder> {

        private List<String> scopes = new ArrayList<>();

        @Override
        protected Builder self() {

            return this;
        }

        public Builder scopes(List<String> scopes) {

            this.scopes = scopes;
            return self();
        }

        public Builder addScope(String scope) {

            this.scopes.add(scope);
            return self();
        }

        public List<String> getScopes() {

            return scopes;
        }

        public AccessToken build() {

            return new AccessToken(this);
        }
    }
}
