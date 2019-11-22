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

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.sql.Timestamp;

/**
 * Contains parameters to be stored in database tables.
 */
public class CibaAuthCodeDO {

    public CibaAuthCodeDO() {

    }

    private String cibaAuthCodeKey;
    private String authReqID;
    private String consumerAppKey;
    private Timestamp issuedTime;
    private Timestamp lastPolledTime;
    private long interval;
    private long expiresIn;
    private Enum authenticationStatus;
    private String[] scope;
    private AuthenticatedUser authenticatedUser;

    public String getCibaAuthCodeKey() {

        return cibaAuthCodeKey;
    }

    public void setCibaAuthCodeKey(String cibaAuthCodeKey) {

        this.cibaAuthCodeKey = cibaAuthCodeKey;
    }

    public String getAuthReqID() {

        return authReqID;
    }

    public void setAuthReqID(String authReqID) {

        this.authReqID = authReqID;
    }

    public Enum getAuthenticationStatus() {

        return authenticationStatus;
    }

    public void setAuthenticationStatus(Enum authenticationStatus) {

        this.authenticationStatus = authenticationStatus;
    }

    public void setExpiresIn(long expiresIn) {

        this.expiresIn = expiresIn;
    }

    public long getExpiresIn() {

        return expiresIn;
    }

    public String[] getScope() {

        return scope;
    }

    public void setScope(String[] scope) {

        this.scope = scope;
    }

    public Timestamp getLastPolledTime() {

        return lastPolledTime;
    }

    public void setLastPolledTime(Timestamp lastPolledTime) {

        this.lastPolledTime = lastPolledTime;
    }

    public long getInterval() {

        return interval;
    }

    public void setInterval(long interval) {

        this.interval = interval;
    }

    public String getConsumerAppKey() {

        return consumerAppKey;
    }

    public void setConsumerAppKey(String consumerAppKey) {

        this.consumerAppKey = consumerAppKey;
    }

    public Timestamp getIssuedTime() {

        return issuedTime;
    }

    public void setIssuedTime(Timestamp issuedTime) {

        this.issuedTime = issuedTime;
    }

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(
            AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }
}
