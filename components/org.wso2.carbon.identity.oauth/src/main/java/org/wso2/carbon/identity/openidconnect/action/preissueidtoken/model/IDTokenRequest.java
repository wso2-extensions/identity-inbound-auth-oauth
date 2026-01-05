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

import org.wso2.carbon.identity.oauth.action.model.TokenRequest;

/**
 * This class represents the model of the ID token request sent in the json request
 * to the API endpoint of the pre issue ID token action.
 */
public class IDTokenRequest extends TokenRequest {

    /**
     * response_type parameter value in the OIDC authorization request.
     */
    private final String responseType;

    private IDTokenRequest(Builder builder) {

        super(builder);
        this.responseType = builder.responseType;
    }

    public  String getResponseType() {

        return responseType;
    }

    /**
     * Builder for IDTokenRequest.
     */
    public static class Builder extends TokenRequest.Builder {

        private String responseType;

        public Builder responseType(String responseType) {

            this.responseType = responseType;
            return this;
        }

        public IDTokenRequest build() {

            return new IDTokenRequest(this);
        }
    }
}
