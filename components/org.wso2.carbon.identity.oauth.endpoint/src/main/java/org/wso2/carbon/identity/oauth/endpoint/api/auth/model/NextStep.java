/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.api.auth.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Class containing the details of the next authentication step.
 */
public class NextStep {

    private StepTypeEnum stepType;
    private List<Authenticator> authenticators = new ArrayList<>();
    private List<Message> messages = new ArrayList<>();

    public NextStep() {

    }

    public NextStep(StepTypeEnum stepType, List<Authenticator> authenticators, List<Message> messages) {

        this.stepType = stepType;
        this.authenticators = authenticators;
        this.messages = messages;
    }

    public StepTypeEnum getStepType() {

        return stepType;
    }

    public void setStepType(StepTypeEnum stepType) {

        this.stepType = stepType;
    }

    public List<Authenticator> getAuthenticators() {

        return authenticators;
    }

    public void setAuthenticators(List<Authenticator> authenticators) {

        this.authenticators = authenticators;
    }

    public List<Message> getMessages() {

        return messages;
    }

    public void setMessages(List<Message> messages) {

        this.messages = messages;
    }
}

