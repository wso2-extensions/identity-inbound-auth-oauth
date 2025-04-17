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
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;

public class AuthzChallengeIncompleteResponse  extends AuthzChallengeGenericResponse {

    @JsonProperty("next_step")
    private NextStep nextStep;

    public AuthzChallengeIncompleteResponse() {

    }

    public AuthzChallengeIncompleteResponse(String authSession, String error, String errorDescription,
                                            NextStep nextStep) {

        super(authSession, error, errorDescription);
        this.nextStep = nextStep;
    }

    @JsonIgnore
    public NextStep getNextStep() {

        return nextStep;
    }

    public void setNextStep(NextStep nextStep) {

        this.nextStep = nextStep;
    }

}
