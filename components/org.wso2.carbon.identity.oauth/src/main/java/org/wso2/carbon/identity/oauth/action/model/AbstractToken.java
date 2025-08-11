/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.action.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a generic token model used in pre-issue access toke flow,
 * such as access tokens and refresh tokens.
 */
public abstract class AbstractToken {

    protected final String tokenType;
    protected List<Claim> claims;

    protected AbstractToken(AbstractBuilder<?> builder) {

        this.tokenType = builder.tokenType;
        this.claims = builder.claims;
    }

    public String getTokenType() {

        return tokenType;
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

    /**
     * Abstract builder class for constructing token instances which are used in pre-issue access token flow.
     *
     * @param <T> The type of the concrete builder extending this abstract builder.
     */
    public abstract static class AbstractBuilder<T extends AbstractBuilder<T>> {

        protected String tokenType;
        protected List<Claim> claims = new ArrayList<>();

        public T tokenType(String tokenType) {

            this.tokenType = tokenType;
            return self();
        }

        public T claims(List<Claim> claims) {

            this.claims = claims;
            return self();
        }

        public T addClaim(String name, Object value) {

            this.claims.add(new Claim(name, value));
            return self();
        }

        public String getTokenType() {

            return tokenType;
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

        protected abstract T self();

        public abstract AbstractToken build();
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
            } else if (value != null && value.getClass().isArray()) {
                return Arrays.copyOf((Object[]) value, ((Object[]) value).length);
            } else {
                // For immutable types or types not requiring deep copy
                return value;
            }
        }
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
        SUBJECT_TYPE("subject_type"),

        IAT("iat");

        private final String name;

        ClaimNames(String name) {

            this.name = name;
        }

        public static boolean contains(String name) {

            return Arrays.stream(AccessToken.ClaimNames.values())
                    .anyMatch(claimName -> claimName.getName().equals(name));
        }

        public String getName() {

            return name;
        }
    }
}
