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
 * Captures the authentication request validated parameters.
 */
public class CibaAuthRequestDTO {

    private String issuer;
    private String audience;
    private long issuedTime;
    private long expiredTime;
    private long notBeforeTime;
    private String JWTID;
    private long requestedExpiry;
    private String userHint;
    private String bindingMessage;
    private String userCode;
    private String[] scope;
    private String clientNotificationToken;
    private String acrValues;
    private String transactionContext;

    public String getTransactionContext() {

        return transactionContext;
    }

    public void setTransactionContext(String transactionContext) {

        this.transactionContext = transactionContext;
    }

    public String getIssuer() {

        return issuer;
    }

    public void setIssuer(String issuer) {

        this.issuer = issuer;
    }

    public String getAudience() {

        return audience;
    }

    public void setAudience(String audience) {

        this.audience = audience;
    }

    public long getIssuedTime() {

        return issuedTime;
    }

    public void setIssuedTime(long issuedTime) {

        this.issuedTime = issuedTime;
    }

    public long getExpiredTime() {

        return expiredTime;
    }

    public void setExpiredTime(long expiredTime) {

        this.expiredTime = expiredTime;
    }

    public long getNotBeforeTime() {

        return notBeforeTime;
    }

    public void setNotBeforeTime(long notBeforeTime) {

        this.notBeforeTime = notBeforeTime;
    }

    public String getJWTID() {

        return JWTID;
    }

    public void setJWTID(String JWTID) {

        this.JWTID = JWTID;
    }

    public long getRequestedExpiry() {

        return requestedExpiry;
    }

    public void setRequestedExpiry(long requestedExpiry) {

        this.requestedExpiry = requestedExpiry;
    }

    public String getUserHint() {

        return userHint;
    }

    public void setUserHint(String userHint) {

        this.userHint = userHint;
    }

    public String getBindingMessage() {

        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {

        this.bindingMessage = bindingMessage;
    }

    public String getUserCode() {

        return userCode;
    }

    public void setUserCode(String userCode) {

        this.userCode = userCode;
    }

    public String[] getScope() {

        return scope;
    }

    public void setScope(String scope[]) {

        this.scope = scope;
    }

    public String getClientNotificationToken() {

        return clientNotificationToken;
    }

    public void setClientNotificationToken(String clientNotificationToken) {

        this.clientNotificationToken = clientNotificationToken;
    }

    public String getAcrValues() {

        return acrValues;
    }

    public void setAcrValues(String acrValues) {

        this.acrValues = acrValues;
    }

}
