/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.ciba.dto;

/**
 * Captures the the values for authorization request.
 */
public class AuthzRequestDTO {

    private String user;
    private String authReqIDasState;
    private String client_id;
    private String callBackUrl;
    private String bindingMessage;
    private String transactionContext;
    private String scope;

    public String getBindingMessage() {

        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {

        this.bindingMessage = bindingMessage;
    }

    public String getTransactionContext() {

        return transactionContext;
    }

    public void setTransactionDetails(String transactionContext) {

        this.transactionContext = transactionContext;
    }

    public String getCallBackUrl() {

        return callBackUrl;
    }

    public void setCallBackUrl(String callBackUrl) {

        this.callBackUrl = callBackUrl;
    }

    public String getUser() {

        return user;
    }

    public void setUser(String user) {

        this.user = user;
    }

    public String getAuthReqIDasState() {

        return authReqIDasState;
    }

    public void setAuthReqIDasState(String authReqIDasState) {

        this.authReqIDasState = authReqIDasState;
    }

    public String getClient_id() {

        return client_id;
    }

    public void setClient_id(String client_id) {

        this.client_id = client_id;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public String getScope() {

        return scope;
    }
}
