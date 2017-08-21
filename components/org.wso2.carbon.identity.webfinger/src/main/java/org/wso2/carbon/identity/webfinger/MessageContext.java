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

package org.wso2.carbon.identity.webfinger;

/**
 * MessageContext contains the WebFingerRequest and WebFingerResponse
 * which can be used in further processing.
 */
class MessageContext {
    private WebFingerRequest request;
    private WebFingerResponse response;

    public MessageContext() {
        this.request = new WebFingerRequest();
        this.response = new WebFingerResponse();
    }

    public MessageContext(WebFingerRequest request) {
        this.request = request;
        this.response = new WebFingerResponse();
    }

    public WebFingerRequest getRequest() {
        return request;
    }

    public void setRequest(WebFingerRequest request) {
        this.request = request;
    }

    public WebFingerResponse getResponse() {
        return response;
    }

    public void setResponse(WebFingerResponse response) {
        this.response = response;
    }


}
