/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.handlers.response;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;

/**
 * Holds response for the OAuth flow api calls.
 */
public class OAuth2TokenResponse extends org.apache.oltu.oauth2.as.response.OAuthASResponse {

    protected OAuth2TokenResponse(String uri, int responseStatus) {

        super(uri, responseStatus);
    }

    public static OAuth2TokenResponse.OAuthTokenResponseBuilder tokenResponse(int code) {

        return new OAuth2TokenResponse.OAuthTokenResponseBuilder(code);
    }

    /**
     * Builds the token response fields and returns {@link OAuth2TokenResponse} instance.
     */
    public static class OAuthTokenResponseBuilder extends OAuthASResponse.OAuthTokenResponseBuilder {

        public OAuthTokenResponseBuilder(int responseCode) {

            super(responseCode);
        }

        public OAuthTokenResponseBuilder setParam(String key, Object value) {

            this.parameters.put(key, value);
            return this;
        }

        public OAuthTokenResponseBuilder setAccessToken(String token) {

            return (OAuthTokenResponseBuilder) super.setAccessToken(token);
        }

        public OAuthTokenResponseBuilder setExpiresIn(String expiresIn) {

            return (OAuthTokenResponseBuilder) super.setExpiresIn(expiresIn);
        }

        public OAuthTokenResponseBuilder setRefreshToken(String refreshToken) {

            return (OAuthTokenResponseBuilder) super.setRefreshToken(refreshToken);
        }

        public OAuthTokenResponseBuilder setTokenType(String tokenType) {

            return (OAuthTokenResponseBuilder) super.setTokenType(tokenType);
        }

        public OAuthTokenResponseBuilder location(String location) {

            return (OAuthTokenResponseBuilder) super.location(location);
        }
    }
}
