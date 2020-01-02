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

package org.wso2.carbon.identity.oauth2.device.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.sql.Timestamp;

/**
 * Device flow data object.
 */
public class DeviceFlowDO {

    private String deviceCode;

    private String userCode;

    private String consumerKeyID;

    private String scope;

    private String status;

    private Timestamp lastPollTime;

    private Timestamp expiryTime;

    private long pollTime;

    private String authzUser;

    private String callbackUri;

    private AuthenticatedUser authorizedUser;

    public String getDeviceCode() {

        return deviceCode;
    }

    public void setDeviceCode(String deviceCode) {

        this.deviceCode = deviceCode;
    }

    public String getUserCode() {

        return userCode;
    }

    public void setUserCode(String userCode) {

        this.userCode = userCode;
    }

    public String getConsumerKeyID() {

        return consumerKeyID;
    }

    public void setConsumerKeyID(String consumerKeyID) {

        this.consumerKeyID = consumerKeyID;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public String getStatus() {

        return status;
    }

    public void setStatus(String status) {

        this.status = status;
    }

    public void setLastPollTime(Timestamp lastPollTime) {

        this.lastPollTime = lastPollTime;
    }

    public Timestamp getLastPollTime() {

        return lastPollTime;
    }

    public Timestamp getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(Timestamp expiryTime) {

        this.expiryTime = expiryTime;
    }

    public long getPollTime() {

        return pollTime;
    }

    public void setPollTime(long pollTime) {

        this.pollTime = pollTime;
    }

    public String getAuthzUser() {

        return authzUser;
    }

    public void setAuthzUser(String authzUser) {

        this.authzUser = authzUser;
    }

    public String getCallbackUri() {

        return callbackUri;
    }

    public void setCallbackUri(String callbackUri) {

        this.callbackUri = callbackUri;
    }

    public AuthenticatedUser getAuthorizedUser() {

        return authorizedUser;
    }

    public void setAuthorizedUser(AuthenticatedUser authorizedUser) {

        this.authorizedUser = authorizedUser;
    }
}
