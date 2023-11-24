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

import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;

import java.util.ArrayList;
import java.util.List;

/**
 * Class containing the authentication response.
 */
public class AuthResponse {

    private String flowId;
    private AuthServiceConstants.FlowStatus flowStatus;
    private FlowTypeEnum flowType = FlowTypeEnum.AUTHENTICATION;
    private NextStep nextStep;
    private List<Link> links = new ArrayList<>();

    public AuthResponse() {

    }

    public AuthResponse(String flowId, AuthServiceConstants.FlowStatus flowStatus, FlowTypeEnum flowType,
                        NextStep nextStep, List<Link> links) {

        this.flowId = flowId;
        this.flowStatus = flowStatus;
        this.flowType = flowType;
        this.nextStep = nextStep;
        this.links = links;
    }

    public String getFlowId() {

        return flowId;
    }

    public void setFlowId(String flowId) {

        this.flowId = flowId;
    }

    public AuthServiceConstants.FlowStatus getFlowStatus() {

        return flowStatus;
    }

    public void setFlowStatus(AuthServiceConstants.FlowStatus flowStatus) {

        this.flowStatus = flowStatus;
    }

    public FlowTypeEnum getFlowType() {

        return flowType;
    }

    public void setFlowType(FlowTypeEnum flowType) {

        this.flowType = flowType;
    }

    public NextStep getNextStep() {

        return nextStep;
    }

    public void setNextStep(NextStep nextStep) {

        this.nextStep = nextStep;
    }

    public List<Link> getLinks() {

        return links;
    }

    public void setLinks(List<Link> links) {

        this.links = links;
    }
}

