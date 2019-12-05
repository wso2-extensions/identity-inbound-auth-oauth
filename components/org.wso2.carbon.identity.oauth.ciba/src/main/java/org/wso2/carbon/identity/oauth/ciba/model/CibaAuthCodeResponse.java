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

package org.wso2.carbon.identity.oauth.ciba.model;

import java.util.Arrays;

/**
 * Captures the values for authorization request.
 */
public class CibaAuthCodeResponse {

    private String userHint;
    private String authReqId; // Authentication request identifier.
    private String clientId;
    private String callBackUrl;
    private String bindingMessage;
    private String transactionContext;
    private String[] scopes;
    private long expiresIn;

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

    public String getUserHint() {

        return userHint;
    }

    public void setUserHint(String userHint) {

        this.userHint = userHint;
    }

    public String getAuthReqId() {

        return authReqId;
    }

    public void setAuthReqId(String authReqId) {

        this.authReqId = authReqId;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public void setScopes(String[] scopes) {

        if (scopes != null) {
            this.scopes = Arrays.copyOf(scopes, scopes.length);
        }
    }

    public String[] getScopes() {

        return scopes != null ? Arrays.copyOf(scopes, scopes.length) : new String[0];
    }

    public long getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {

        this.expiresIn = expiresIn;
    }
}
