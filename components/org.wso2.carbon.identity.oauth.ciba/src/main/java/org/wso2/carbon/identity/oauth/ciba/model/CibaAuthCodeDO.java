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
import java.util.Arrays;

/**
 * Contains parameters to be stored in database tables.
 */
public class CibaAuthCodeDO {

    private String cibaAuthCodeKey; // Internal primary key for storage management.
    private String authReqId; // Authentication request identifier mapped to authCodeKey.
    private String consumerKey;
    private Timestamp issuedTime;
    private Timestamp lastPolledTime;
    private long interval;
    private long expiresIn;
    private Enum authReqStatus;
    private String[] scopes;
    private AuthenticatedUser authenticatedUser;

    public String getCibaAuthCodeKey() {

        return cibaAuthCodeKey;
    }

    public void setCibaAuthCodeKey(String cibaAuthCodeKey) {

        this.cibaAuthCodeKey = cibaAuthCodeKey;
    }

    public String getAuthReqId() {

        return authReqId;
    }

    public void setAuthReqId(String authReqID) {

        this.authReqId = authReqID;
    }

    public Enum getAuthReqStatus() {

        return authReqStatus;
    }

    public void setAuthReqStatus(Enum authReqStatus) {

        this.authReqStatus = authReqStatus;
    }

    public void setExpiresIn(long expiresIn) {

        this.expiresIn = expiresIn;
    }

    public long getExpiresIn() {

        return expiresIn;
    }

    public String[] getScopes() {

        return scopes != null ? Arrays.copyOf(scopes, scopes.length) : new String[0];
    }

    public void setScopes(String[] scopes) {

        if (scopes != null) {
            this.scopes = Arrays.copyOf(scopes, scopes.length);
        }
    }

    public Timestamp getLastPolledTime() {

        return lastPolledTime != null ? (Timestamp) lastPolledTime.clone() : null;
    }

    public void setLastPolledTime(Timestamp lastPolledTime) {

        this.lastPolledTime = (Timestamp) lastPolledTime.clone();
    }

    public long getInterval() {

        return interval;
    }

    public void setInterval(long interval) {

        this.interval = interval;
    }

    public String getConsumerKey() {

        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {

        this.consumerKey = consumerKey;
    }

    public Timestamp getIssuedTime() {

        return issuedTime != null ? (Timestamp) issuedTime.clone() : null;
    }

    public void setIssuedTime(Timestamp issuedTime) {

        this.issuedTime = (Timestamp) issuedTime.clone();
    }

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }
}
