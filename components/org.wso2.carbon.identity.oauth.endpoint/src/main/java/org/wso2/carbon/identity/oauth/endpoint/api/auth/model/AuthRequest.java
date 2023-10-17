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

/**
 * Class containing authentication request details.
 */
public class AuthRequest  {
  
    private String flowId;
    private SelectedAuthenticator selectedAuthenticator;

    public AuthRequest() {

    }

    public AuthRequest(String flowId, SelectedAuthenticator selectedAuthenticator) {

        this.flowId = flowId;
        this.selectedAuthenticator = selectedAuthenticator;
    }

    public String getFlowId() {

        return flowId;
    }

    public void setFlowId(String flowId) {

        this.flowId = flowId;
    }

    public SelectedAuthenticator getSelectedAuthenticator() {

        return selectedAuthenticator;
    }

    public void setSelectedAuthenticator(SelectedAuthenticator selectedAuthenticator) {

        this.selectedAuthenticator = selectedAuthenticator;
    }
}

