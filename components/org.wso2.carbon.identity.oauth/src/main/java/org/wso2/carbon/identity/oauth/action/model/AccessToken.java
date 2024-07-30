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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This class represents the model of the access token sent in the json request
 * to the API endpoint of the pre issue access token action.
 */
public class AccessToken {

    private final String tokenType;
    List<String> scopes;
    List<Claim> claims;

    private AccessToken(Builder builder) {

        this.tokenType = builder.tokenType;
        this.scopes = builder.scopes;
        this.claims = builder.claims;
    }

    public String getTokenType() {

        return tokenType;
    }

    public List<String> getScopes() {

        return scopes;
    }

    public List<Claim> getClaims() {

        return claims;
    }

    public Claim getClaim(String name) {

        if (claims != null) {
            for (Claim claim : claims) {
                if (claim.getName().equals(name)) {
                    return claim;
                }
            }
        }

        return null;
    }

    public AccessToken.Builder copy() {

        return new Builder()
                .tokenType(this.tokenType)
                .scopes(new ArrayList<>(this.scopes))
                .claims(this.claims.stream().map(Claim::copy).collect(Collectors.toList()));
    }

    /**
     * Enum for standard claim names.
     */
    public enum ClaimNames {

        SUB("sub"),
        ISS("iss"),
        AUD("aud"),
        CLIENT_ID("client_id"),
        AUTHORIZED_USER_TYPE("aut"),
        EXPIRES_IN("expires_in"),

        TOKEN_BINDING_REF("binding_ref"),
        TOKEN_BINDING_TYPE("binding_type"),
        SUBJECT_TYPE("subject_type");

        private final String name;

        ClaimNames(String name) {

            this.name = name;
        }

        public static boolean contains(String name) {

            return Arrays.stream(ClaimNames.values())
                    .anyMatch(claimName -> claimName.name.equals(name));
        }

        public String getName() {

            return name;
        }
    }

    /**
     * Model class for claims.
     */
    public static class Claim {

        private String name;
        private Object value;

        public Claim() {

        }

        public Claim(String name, Object value) {

            this.name = name;
            this.value = value;
        }

        public String getName() {

            return name;
        }

        public void setName(String name) {

            this.name = name;
        }

        public Object getValue() {

            return value;
        }

        public void setValue(Object value) {

            this.value = value;
        }

        public Claim copy() {

            return new Claim(this.name, deepCopyValue(this.value));
        }

        private Object deepCopyValue(Object value) {

            if (value instanceof List) {
                List<?> originalList = (List<?>) value;
                List<Object> copiedList = new ArrayList<>();
                for (Object item : originalList) {
                    copiedList.add(deepCopyValue(item)); // Recursive for nested lists
                }
                return copiedList;
            } else if (value instanceof Map) {
                Map<?, ?> originalMap = (Map<?, ?>) value;
                Map<Object, Object> copiedMap = new HashMap<>();
                for (Map.Entry<?, ?> entry : originalMap.entrySet()) {
                    copiedMap.put(entry.getKey(), deepCopyValue(entry.getValue())); // Recursive for nested maps
                }
                return copiedMap;
            } else if (value.getClass().isArray()) {
                return Arrays.copyOf((Object[]) value, ((Object[]) value).length);
            } else {
                // For immutable types or types not requiring deep copy
                return value;
            }
        }
    }

    /**
     * Builder for AccessToken.
     */
    public static class Builder {

        private String tokenType;
        private List<String> scopes = new ArrayList<>();
        private List<Claim> claims = new ArrayList<>();

        public Builder tokenType(String tokenType) {

            this.tokenType = tokenType;
            return this;
        }

        public Builder scopes(List<String> scopes) {

            this.scopes = scopes;
            return this;
        }

        public Builder claims(List<Claim> claims) {

            this.claims = claims;
            return this;
        }

        public Builder addClaim(String name, Object value) {

            this.claims.add(new Claim(name, value));
            return this;
        }

        public Builder addScope(String scope) {

            this.scopes.add(scope);
            return this;
        }

        public String getTokenType() {

            return tokenType;
        }

        public List<String> getScopes() {

            return scopes;
        }

        public List<Claim> getClaims() {

            return claims;
        }

        public Claim getClaim(String name) {

            if (claims != null) {
                for (Claim claim : claims) {
                    if (claim.getName().equals(name)) {
                        return claim;
                    }
                }
            }

            return null;
        }

        public AccessToken build() {

            return new AccessToken(this);
        }
    }
}
