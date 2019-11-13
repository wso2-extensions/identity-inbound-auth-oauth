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

import java.sql.Timestamp;

public class DeviceFlowDO {

    private String deviceCode;

    private String userCode;

    private String consumerKeyID;

    private String scope;

    private Timestamp issuedTime;

    private Timestamp expiredTime;

    private String Status;

    private Timestamp lastPollTime;

    private long expiryTime;

    private long pollTime;

    private String authzUser;


    public DeviceFlowDO() {

    }

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

    public Timestamp getIssuedTime() {

        return issuedTime;
    }

    public void setIssuedTime(Timestamp issuedTime) {

        this.issuedTime = issuedTime;
    }

    public Timestamp getExpiredTime() {

        return expiredTime;
    }

    public void setExpiredTime(Timestamp expiredTime) {

        this.expiredTime = expiredTime;
    }

    public String getStatus() {

        return Status;
    }

    public void setStatus(String status) {

        Status = status;
    }

    public void setLastPollTime(Timestamp lastPollTime) {

        this.lastPollTime = lastPollTime;
    }

    public Timestamp getLastPollTime() {

        return lastPollTime;
    }


    public long getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {

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

}
