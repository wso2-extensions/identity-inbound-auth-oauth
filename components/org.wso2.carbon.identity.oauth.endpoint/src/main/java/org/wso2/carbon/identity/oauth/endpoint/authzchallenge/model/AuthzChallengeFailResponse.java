/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthzChallengeFailResponse extends  AuthzChallengeGenericResponse {

    private String code;

    @JsonProperty("trace_id")
    private String traceId;

    @JsonProperty("error_uri")
    private String errorUri;

    @JsonProperty("request_uri")
    private String requestUri;

    @JsonProperty("expires_in")
    private String expiresIn;

    public AuthzChallengeFailResponse() {

    }

    public AuthzChallengeFailResponse(String authSession, String error, String errorDescription, String code, String traceId, String errorUri,
                                      String requestUri, String expiresIn) {

        super(authSession, error, errorDescription);
        this.code = code;
        this.traceId = traceId;
        this.errorUri = errorUri;
        this.requestUri = requestUri;
        this.expiresIn = expiresIn;
    }

    public String getCode() {

        return code;
    }

    public void setCode(String code) {

        this.code = code;
    }

    @JsonIgnore
    public String getTraceId() {

        return traceId;
    }

    public void setTraceId(String traceId) {

        this.traceId = traceId;
    }

    @JsonIgnore
    public String getErrorUri() {

        return errorUri;
    }

    public void setErrorUri(String errorUri) {

        this.errorUri = errorUri;
    }

    @JsonIgnore
    public String getRequestUri() {

        return requestUri;
    }

    public void setRequestUri(String request_uri) {

        this.requestUri = request_uri;
    }

    @JsonIgnore
    public String getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {

        this.expiresIn = expiresIn;
    }
}
