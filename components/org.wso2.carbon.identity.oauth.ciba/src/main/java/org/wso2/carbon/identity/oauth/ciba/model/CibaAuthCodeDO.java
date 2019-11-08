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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.wso2.carbon.identity.oauth.ciba.model;

/**
 * This DO captures parameters to be stored in database tables.
 */
public class CibaAuthCodeDO {

    public CibaAuthCodeDO() {

    }

    private static String cibaAuthCodeDOKey;
    private static String hashedCibaAuthReqId;
    private static String authenticationStatus;
    private static String authenticatedUser;
    private static long lastPolledTime;
    private static long interval;
    private static long expiryTime;
    private static String bindingMessage;
    private static String transactionContext;
    private static String scope;

    public String getCibaAuthCodeDOKey() {

        return cibaAuthCodeDOKey;
    }

    public void setCibaAuthCodeDOKey(String cibaAuthCodeDOKey) {

        this.cibaAuthCodeDOKey = cibaAuthCodeDOKey;
    }

    public String getHashedCibaAuthReqId() {

        return hashedCibaAuthReqId;
    }

    public void setHashedCibaAuthReqId(String hashedCibaAuthReqId) {

        this.hashedCibaAuthReqId = hashedCibaAuthReqId;
    }

    public String getAuthenticationStatus() {

        return authenticationStatus;
    }

    public void setAuthenticationStatus(String authenticationStatus) {

        this.authenticationStatus = authenticationStatus;
    }

    public String getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(String authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    public void setExpiryTime(long expiryTime) {

        this.expiryTime = expiryTime;
    }

    public long getExpiryTime() {

        return expiryTime;
    }

    public String getBindingMessage() {

        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {

        this.bindingMessage = bindingMessage;
    }

    public String getTransactionContext() {

        return transactionContext;
    }

    public void setTransactionContext(String transactionContext) {

        this.transactionContext = transactionContext;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public long getLastPolledTime() {

        return lastPolledTime;
    }

    public void setLastPolledTime(long lastPolledTime) {

        this.lastPolledTime = lastPolledTime;
    }

    public long getInterval() {

        return interval;
    }

    public void setInterval(long interval) {

        this.interval = interval;
    }

}
