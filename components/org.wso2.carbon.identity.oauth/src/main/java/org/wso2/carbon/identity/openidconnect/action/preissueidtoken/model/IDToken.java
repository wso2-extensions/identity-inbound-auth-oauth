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

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model;

import org.wso2.carbon.identity.oauth.action.model.AbstractToken;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * This class represents the model of the id token sent in the json request
 * to the API endpoint of the pre issue id token action.
 */
public class IDToken extends AbstractToken {

    private IDToken(AbstractBuilder<?> builder) {
        super(builder);
    }

    public Builder copy() {

        return new Builder()
                .tokenType(this.tokenType)
                .claims(this.claims.stream().map(Claim::copy).collect(Collectors.toList()));
    }

    /**
     * Builder for IdToken.
     */
    public static class Builder extends AbstractBuilder<Builder> {

        @Override
        protected Builder self() {

            return this;
        }

        public IDToken build() {

            return new IDToken(this);
        }
    }

    /**
     * Enum containing standard claim names defined in the ID Token.
     */
    public enum ClaimNames {

        ISS("iss"),
        AT_HASH("at_hash"),
        C_HASH("c_hash"),
        S_HASH("s_hash"),
        SESSION_ID_CLAIM("sid"),
        EXPIRES_IN("expires_in"),
        REALM("realm"),
        TENANT("tenant"),
        USERSTORE("userstore"),
        IDP_SESSION_KEY("isk"),
        SUB("sub"),
        AUD("aud"),
        EXP("exp"),
        IAT("iat"),
        AUTH_TIME("auth_time"),
        NONCE("nonce"),
        ACR("acr"),
        AMR("amr"),
        AZP("azp");


        private final String claimName;

        ClaimNames(String claimName) {
            this.claimName = claimName;
        }

        public String getName() {
            return claimName;
        }

        public static boolean contains(String name) {

            return Arrays.stream(AccessToken.ClaimNames.values())
                    .anyMatch(claimName -> claimName.getName().equals(name));
        }
    }
}
