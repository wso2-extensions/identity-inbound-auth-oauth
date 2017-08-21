/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.discovery;

/**
 * MessageContext contains the OIDProviderRequest and OIDProviderConfigResponse
 * which can be used in further processing.
 */
class MessageContext {

    private OIDProviderConfigResponse configurations;

    private OIDProviderRequest request;

    public MessageContext() {
        this.request = new OIDProviderRequest();
        this.configurations = new OIDProviderConfigResponse();
    }

    public MessageContext(OIDProviderRequest request) {
        this.request = request;
        this.configurations = new OIDProviderConfigResponse();
    }

    public void setConfigurations(OIDProviderConfigResponse configurations) {
        this.configurations = configurations;
    }

    public OIDProviderConfigResponse getConfigurations() {
        return configurations;
    }

    public OIDProviderRequest getRequest() {
        return request;
    }

    public void setRequest(OIDProviderRequest request) {
        this.request = request;
    }

}
