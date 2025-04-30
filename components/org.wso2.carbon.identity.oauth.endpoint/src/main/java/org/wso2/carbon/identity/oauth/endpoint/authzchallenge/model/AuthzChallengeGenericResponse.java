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

/**
 * Generic response for authorization challenge endpoint.
 */
public class AuthzChallengeGenericResponse {

    @JsonProperty("auth_session")
    private String authSession;

    @JsonProperty("error")
    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    public AuthzChallengeGenericResponse() {

    }

    public AuthzChallengeGenericResponse(String authSession, String error, String errorDescription) {

        this.authSession = authSession;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    @JsonIgnore
    public String getAuthSession() {

        return authSession;
    }

    public void setAuthSession(String authSession) {

        this.authSession = authSession;
    }

    public String getError() {

        return error;
    }

    public void setError(String error) {

        this.error = error;
    }

    @JsonIgnore
    public String getErrorDescription() {

        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {

        this.errorDescription = errorDescription;
    }
}
